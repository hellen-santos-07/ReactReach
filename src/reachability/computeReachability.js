const t = require("@babel/types");

// React hooks that propagate data and need taint tracking
const REACT_HOOKS = new Set(["useState", "useMemo", "useCallback", "useReducer"]);

/**
 * Collects all Identifier names referenced inside the AST node subtree.
 */
function collectNodeIdentifiers(node) {
  const ids = new Set();

  function walk(n) {
    if (!n || typeof n !== "object") return;
    if (t.isIdentifier(n)) {
      ids.add(n.name);
    }
    for (const key of (t.VISITOR_KEYS[n.type] || [])) {
      const child = n[key];
      if (Array.isArray(child)) {
        child.forEach(walk);
      } else if (t.isNode(child)) {
        walk(child);
      }
    }
  }

  walk(node);
  return ids;
}

/**
 * Detects if a CallExpression is a React hook call and returns the hook name.
 * Handles: useState(...) and React.useState(...)
 */
function getHookName(callNode) {
  const callee = callNode.callee;
  if (t.isIdentifier(callee) && REACT_HOOKS.has(callee.name)) {
    return callee.name;
  }
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.object) &&
    callee.object.name === "React" &&
    t.isIdentifier(callee.property) &&
    REACT_HOOKS.has(callee.property.name)
  ) {
    return callee.property.name;
  }
  return null;
}

/**
 * Phase 1 of taint: Collection of useState setter->state mappings and identify initially-tainted state from hook calls.
 * examples:
 * const [data, setData] = useState(taintedExpr)    -> data is tainted
 * const result = useMemo(() => taintedBody, [deps]) -> result is tainted
 * const fn = useCallback(() => taintedBody, [deps]) -> fn is tainted
 */
function collectHookTaint(bodyNode, tainted) {
  // Maps setter name -> state variable name (e.g. "setData" -> "data")
  const setterToState = new Map();

  function walkHooks(node) {
    if (!node || typeof node !== "object") return;

    if (t.isVariableDeclarator(node) && node.init && t.isCallExpression(node.init)) {
      const hookName = getHookName(node.init);

      if (hookName === "useState") {
        // const [stateVar, setterVar] = useState(initialValue)
        if (t.isArrayPattern(node.id) && node.id.elements.length >= 2) {
          const stateVar = node.id.elements[0];
          const setterVar = node.id.elements[1];

          if (t.isIdentifier(stateVar) && t.isIdentifier(setterVar)) {
            setterToState.set(setterVar.name, stateVar.name);

            // If initial value is tainted, state is tainted
            const args = node.init.arguments;
            if (args.length > 0) {
              const initIds = collectNodeIdentifiers(args[0]);
              if ([...initIds].some((id) => tainted.has(id))) {
                tainted.add(stateVar.name);
              }
            }
          }
        }
      }

      if (hookName === "useMemo" || hookName === "useCallback") {
        // const result = useMemo(() => bodyWithTainted, [deps])
        if (t.isIdentifier(node.id)) {
          const args = node.init.arguments;
          if (args.length > 0 && (t.isArrowFunctionExpression(args[0]) || t.isFunctionExpression(args[0]))) {
            const callbackIds = collectNodeIdentifiers(args[0].body);
            if ([...callbackIds].some((id) => tainted.has(id))) {
              tainted.add(node.id.name);
            }
          }
        }
      }

      if (hookName === "useReducer") {
        // const [state, dispatch] = useReducer(reducer, initialState)
        if (t.isArrayPattern(node.id) && node.id.elements.length >= 1) {
          const stateVar = node.id.elements[0];
          const args = node.init.arguments;
          // If initialState is tainted, state is tainted
          if (t.isIdentifier(stateVar) && args.length >= 2) {
            const initIds = collectNodeIdentifiers(args[1]);
            if ([...initIds].some((id) => tainted.has(id))) {
              tainted.add(stateVar.name);
            }
          }
        }
      }
    }

    for (const key of (t.VISITOR_KEYS[node.type] || [])) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(walkHooks);
      } else if (t.isNode(child)) {
        walkHooks(child);
      }
    }
  }

  walkHooks(bodyNode);
  return setterToState;
}

/**
 * Phase 2 of taint: Propagation on setter calls and local variables.
 * example:
 * setData(taintedExpr) -> "data" is tainted (via setter)
 * const x = taintedExpr -> x is tainted
 * const {a, b} = taintedExpr -> a, b are tainted
 * let y = transform(tainted); y = fn(t2) -> y is tainted
 */
function propagateTaint(bodyNode, tainted, setterToState) {
  function propagate(node) {
    if (!node || typeof node !== "object") return;

    // --- setter calls: setData(taintedExpr) -> data is tainted ---
    if (t.isCallExpression(node) && t.isIdentifier(node.callee)) {
      const stateVar = setterToState.get(node.callee.name);
      if (stateVar && node.arguments.length > 0) {
        const argIds = collectNodeIdentifiers(node.arguments[0]);
        if ([...argIds].some((id) => tainted.has(id))) {
          tainted.add(stateVar);
        }
      }
    }

    // variable declarations: const x = taintedExpr
    if (t.isVariableDeclarator(node) && node.init) {
      const initIds = collectNodeIdentifiers(node.init);
      if ([...initIds].some((id) => tainted.has(id))) {
        if (t.isIdentifier(node.id)) {
          tainted.add(node.id.name);
        } else if (t.isObjectPattern(node.id)) {
          for (const prop of node.id.properties) {
            if (prop.value && t.isIdentifier(prop.value)) {
              tainted.add(prop.value.name);
            }
          }
        } else if (t.isArrayPattern(node.id)) {
          for (const elem of (node.id.elements || [])) {
            if (t.isIdentifier(elem)) {
              tainted.add(elem.name);
            }
          }
        }
      }
    }

    // reassignment: x = taintedExpr
    if (t.isAssignmentExpression(node) && t.isIdentifier(node.left)) {
      const rightIds = collectNodeIdentifiers(node.right);
      if ([...rightIds].some((id) => tainted.has(id))) {
        tainted.add(node.left.name);
      }
    }

    for (const key of (t.VISITOR_KEYS[node.type] || [])) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(propagate);
      } else if (t.isNode(child)) {
        propagate(child);
      }
    }
  }

  propagate(bodyNode);
}

/**
 * Computes the full set of tainted identifiers within a component.
 * 1. seeds with the vulnerable dependency's imported identifiers
 * 2. propagates through hooks (useState, useMemo, useCallback, useReducer)
 * 3. propagates through local variable assignments and setter calls
 * 4. runs two passes to handle short taint chains
 */
function computeTaintedIdentifiers(bodyNode, sourceIdentifiers) {
  const tainted = new Set(sourceIdentifiers);

  // Phase 1: Hooks analysis: detect state/setter mappings, initial taint
  const setterToState = collectHookTaint(bodyNode, tainted);

  // Phase 2: Local propagation: variables, assignments, setter calls
  // Two passes to handle chains: const a = vuln(); const b = fn(a);
  propagateTaint(bodyNode, tainted, setterToState);
  propagateTaint(bodyNode, tainted, setterToState);

  return tainted;
}

/**
 * Checks if a sink's source location falls within a component's source range.
 */
function isInsideComponent(sink, component) {
  if (!sink.loc || !component.loc) return false;
  return (
    sink.loc.start.line >= component.loc.start.line &&
    sink.loc.end.line <= component.loc.end.line
  );
}

/**
 * Intra-component structural reachability analysis.
 *
 * For each vulnerable dependency usage, determines whether its data can structurally reach a security-sensitive sink within a component, following React's data flow model: hooks -> local variables -> JSX render.
 * levels:
 * CRITICAL: imported identifier flows directly into a sink expression
 * HIGH: a variable derived from the import (via hooks or local propagation) reaches a sink
 * MEDIUM: dep used in a component with sinks, but no data path proven
 * LOW: dep imported but no component or sink context
 * NONE: dep imported but identifiers never referenced (dead import)
 */
function computeReachability(dependencyUsages, components, sinks) {
  const findings = [];

  for (const usage of dependencyUsages) {
    const vulnIds = new Set(usage.importedAs);
    const fileComponents = components.filter((c) => c.filePath === usage.filePath);
    const fileSinks = sinks.filter((s) => s.filePath === usage.filePath);

    // No binding names captured — can't trace data flow
    if (vulnIds.size === 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "LOW",
        reason: "Vulnerable dependency imported but no binding name captured (dynamic import or bare require)",
        component: null,
        sinkType: null,
        sinkLoc: null,
        taintedPath: []
      });
      continue;
    }

    // Find components that actually reference the vulnerable identifiers
    const relevantComponents = fileComponents.filter((c) =>
      usage.importedAs.some((id) => id in c.usedImports)
    );

    if (relevantComponents.length === 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "NONE",
        reason: "Vulnerable dependency imported but identifiers are never referenced in any component",
        component: null,
        sinkType: null,
        sinkLoc: null,
        taintedPath: []
      });
      continue;
    }

    for (const component of relevantComponents) {
      const componentSinks = fileSinks.filter((s) => isInsideComponent(s, component));

      // Component uses the dep but contains no sinks
      if (componentSinks.length === 0) {
        findings.push({
          packageName: usage.packageName,
          filePath: usage.filePath,
          reachability: "MEDIUM",
          reason: "Vulnerable dependency used inside React component but no security sink found in this component",
          component: component.name,
          sinkType: null,
          sinkLoc: null,
          taintedPath: [...usage.importedAs]
        });
        continue;
      }

      // Compute tainted identifiers through React hooks + local propagation
      const tainted = computeTaintedIdentifiers(component.bodyNode, vulnIds);

      let componentHasSinkPath = false;

      for (const sink of componentSinks) {
        const sinkIds = new Set(sink.identifiers);
        const overlap = [...tainted].filter((id) => sinkIds.has(id));

        if (overlap.length > 0) {
          componentHasSinkPath = true;

          // Distinguish direct use vs propagated use
          const directIds = overlap.filter((id) => vulnIds.has(id));
          const isDirect = directIds.length > 0;

          findings.push({
            packageName: usage.packageName,
            filePath: usage.filePath,
            reachability: isDirect ? "CRITICAL" : "HIGH",
            reason: isDirect
              ? "Vulnerable dependency identifier flows directly into a security sink"
              : "Variable derived from vulnerable dependency reaches a security sink via React hooks or local propagation",
            component: component.name,
            sinkType: sink.sinkType,
            sinkLoc: sink.loc,
            taintedPath: overlap
          });
        }
      }

      // Component has sinks but no proven data path
      if (!componentHasSinkPath) {
        findings.push({
          packageName: usage.packageName,
          filePath: usage.filePath,
          reachability: "MEDIUM",
          reason: "Vulnerable dependency used in a component with sinks, but no structural data path found",
          component: component.name,
          sinkType: null,
          sinkLoc: null,
          taintedPath: [...usage.importedAs]
        });
      }
    }
  }

  return findings;
}

module.exports = computeReachability;