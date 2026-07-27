const t = require("@babel/types");

// React hooks that propagate data and need taint tracking
const REACT_HOOKS = new Set([
  "useState",
  "useMemo",
  "useCallback",
  "useReducer",
]);

//Collects all Identifier names referenced inside the AST node subtree.
function collectNodeIdentifiers(node) {
  const ids = new Set();

  function walk(n) {
    if (!n || typeof n !== "object") return;
    if (t.isIdentifier(n)) {
      ids.add(n.name);
    }
    for (const key of t.VISITOR_KEYS[n.type] || []) {
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
 * const [data, setData] = useState(taintedExpr) -> data is tainted
 * const result = useMemo(() => taintedBody, [deps]) -> result is tainted
 * const fn = useCallback(() => taintedBody, [deps]) -> fn is tainted
 */
function collectHookTaint(bodyNode, tainted) {
  // Maps setter name -> state variable name (e.g. "setData" -> "data")
  const setterToState = new Map();

  function walkHooks(node) {
    if (!node || typeof node !== "object") return;

    if (
      t.isVariableDeclarator(node) &&
      node.init &&
      t.isCallExpression(node.init)
    ) {
      // node is the AST node from the component's body: it can be anything - variable declaration, expression, etc. We only care about variable declarations that are initialized with a call expression (potential hook call).
      const hookName = getHookName(node.init);

      if (hookName === "useState") {
        // const [stateVar, setterVar] = useState(initialValue)
        if (t.isArrayPattern(node.id) && node.id.elements.length >= 2) {
          //node.id is the left-hand side of the variable declaration. We check if it's an array pattern with at least 2 elements, which matches the typical useState destructuring.
          const stateVar = node.id.elements[0]; // The first element is the state variable
          const setterVar = node.id.elements[1]; // The second element is the setter function

          if (t.isIdentifier(stateVar) && t.isIdentifier(setterVar)) {
            // should be simple identifiers, not patterns
            setterToState.set(setterVar.name, stateVar.name); // Map the setter name to the state variable name for later propagation checks

            // If initial value is tainted, state is tainted
            const args = node.init.arguments;
            if (args.length > 0) {
              const initIds = collectNodeIdentifiers(args[0]); // collect identifiers from the initial value expression
              if ([...initIds].some((id) => tainted.has(id))) {
                // if any of those identifiers are tainted, we consider the state variable tainted
                tainted.add(stateVar.name); // so... add the state variable name to the tainted set :D
              }
            }
          }
        }
      }

      if (hookName === "useMemo" || hookName === "useCallback") {
        // const result = useMemo(() => bodyWithTainted, [deps])
        if (t.isIdentifier(node.id)) {
          const args = node.init.arguments;
          if (
            args.length > 0 &&
            (t.isArrowFunctionExpression(args[0]) ||
              t.isFunctionExpression(args[0]))
          ) {
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

    for (const key of t.VISITOR_KEYS[node.type] || []) {
      // recursively walk the AST to find all hook calls, even if nested inside other expressions
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

    //setter calls: setData(taintedExpr) -> data is tainted
    if (t.isCallExpression(node) && t.isIdentifier(node.callee)) {
      // check if it's a call expression with an identifier callee (setData(...))
      const stateVar = setterToState.get(node.callee.name);
      if (stateVar && node.arguments.length > 0) {
        const argIds = collectNodeIdentifiers(node.arguments[0]);
        if ([...argIds].some((id) => tainted.has(id))) {
          // if any argument identifier is tainted, the state variable is tainted
          tainted.add(stateVar);
        }
      }
    }

    // variable declarations: const x = taintedExpr
    if (t.isVariableDeclarator(node) && node.init) {
      const initIds = collectNodeIdentifiers(node.init);
      if ([...initIds].some((id) => tainted.has(id))) {
        // if any identifier in the initializer is tainted, the variable is tainted
        if (t.isIdentifier(node.id)) {
          tainted.add(node.id.name);
        } else if (t.isObjectPattern(node.id)) {
          for (const prop of node.id.properties) {
            if (prop.value && t.isIdentifier(prop.value)) {
              tainted.add(prop.value.name);
            }
          }
        } else if (t.isArrayPattern(node.id)) {
          for (const elem of node.id.elements || []) {
            if (t.isIdentifier(elem)) {
              tainted.add(elem.name);
            }
          }
        }
      }
    }

    // reassignment: x = taintedExpr -> x is tainted
    if (t.isAssignmentExpression(node) && t.isIdentifier(node.left)) {
      const rightIds = collectNodeIdentifiers(node.right);
      if ([...rightIds].some((id) => tainted.has(id))) {
        // if any identifier in the right-hand side is tainted, the left-hand side is tainted
        tainted.add(node.left.name);
      }
    }

    for (const key of t.VISITOR_KEYS[node.type] || []) {
      // recursively propagate through the AST to find all variable declarations and assignments, even if nested inside other expressions
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
  // just 2 passes for simplicity - in practice most taint chains are short and this avoids the complexity of a worklist algorithm
  propagateTaint(bodyNode, tainted, setterToState);
  propagateTaint(bodyNode, tainted, setterToState);

  return tainted;
}

/**
 * Checks if a sink's source location falls within a component's source range.
 * We kind of need to do this because the extraction is structural and doesn't enforce that sinks are only extracted from within component bodies, so we need to check if a sink is actually inside a component when matching them up in the reachability analysis.
 */
function isInsideComponent(sink, component) {
  if (!sink.loc || !component.loc) return false;
  return (
    sink.loc.start.line >= component.loc.start.line &&
    sink.loc.end.line <= component.loc.end.line
  );
}

function sinkMetadata(sink) {
  return {
    sinkRuleId: sink.ruleId ?? null,
    sinkCategory: sink.category ?? null,
    sinkPriority: sink.priority ?? null,
    confidence: sink.confidence ?? null,
  };
}

/**
 * Finds JSX attributes in a component body that pass tainted data as props to child components (PascalCase JSX elements).
 *
 * Returns a Map: childComponentName -> Set<propName>
 * Only non-spread JSXAttributes whose value expression references at least
 * one tainted identifier are included.
 */
function collectTaintedJSXProps(bodyNode, tainted) {
  const taintedProps = new Map();

  function walk(node) {
    if (!node || typeof node !== "object") return;

    if (t.isJSXOpeningElement(node)) {
      const nameNode = node.name;
      // Only PascalCase names (React components, not HTML elements)
      if (t.isJSXIdentifier(nameNode) && /^[A-Z]/.test(nameNode.name)) {
        // check if it's a JSX element with a PascalCase name, which indicates it's a React component
        const childName = nameNode.name;
        for (const attr of node.attributes) {
          // iterate over the attributes of the JSX element to find props that might be tainted
          if (!t.isJSXAttribute(attr) || !attr.name) continue; // care only about normal JSX attributes
          const attrName =
            typeof attr.name.name === "string" ? attr.name.name : null;
          if (!attrName) continue;
          const val = attr.value;
          if (t.isJSXExpressionContainer(val)) {
            // we only care about attributes whose value is a JSX expression, since static string values can't be tainted
            const attrIds = collectNodeIdentifiers(val.expression);
            if ([...attrIds].some((id) => tainted.has(id))) {
              // if any identifier in the attribute value is tainted, the prop is tainted
              if (!taintedProps.has(childName))
                taintedProps.set(childName, new Set());
              taintedProps.get(childName).add(attrName);
            }
          }
        }
      }
    }

    for (const key of t.VISITOR_KEYS[node.type] || []) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(walk);
      else if (t.isNode(child)) walk(child);
    }
  }

  walk(bodyNode);
  return taintedProps;
}

/**
 * Resolves which local identifiers in a child component correspond to a set of incoming tainted prop names, so they can seed taint propagation.
 *
 * Handles:
 * - Destructured first param: function Comp({ propA, propB: localB, propC = val })
 * - Identifier first param: function Comp(props) -> seeds "props" (conservative)
 * - Rest element: function Comp({ ...rest }) -> seeds "rest" (conservative)
 * - Class components (null params): returns empty set
 */
function extractPropSeedIdentifiers(params, taintedPropNames) {
  const seeds = new Set();
  if (!params || params.length === 0) return seeds;

  const firstParam = params[0]; // firstParam is the props parameter in a function component, or null in a class component

  if (t.isObjectPattern(firstParam)) { // isObjectPattern means destructured props: function Comp({ propA, propB: localB, propC = val })
    for (const prop of firstParam.properties) { // for each property in the destructuring pattern
      if (t.isRestElement(prop)) { // isRestElement means a rest element: function Comp({ ...rest })
        if (t.isIdentifier(prop.argument)) seeds.add(prop.argument.name); // conservatively seed the rest identifier if any tainted prop is included in the rest
        continue;
      }
      if (!t.isObjectProperty(prop)) continue; // we only care about normal properties, not rest elements

      // The incoming prop name (key side)
      const keyName = t.isIdentifier(prop.key) // if the key is an identifier (propA), use its name
        ? prop.key.name
        : t.isStringLiteral(prop.key)
          ? prop.key.value
          : null;
      if (!keyName || !taintedPropNames.has(keyName)) continue;

      // The local binding name (value side)
      const localName = t.isIdentifier(prop.value) // if the value is an identifier (propB: localB or propC = val), use its name
        ? prop.value.name
        : t.isAssignmentPattern(prop.value) && t.isIdentifier(prop.value.left)
          ? prop.value.left.name
          : null;
      if (localName) seeds.add(localName);
    }
  } else if (t.isIdentifier(firstParam)) {
    // props object - conservatively seed the whole props reference
    seeds.add(firstParam.name);
  }

  return seeds;
}

/**
 * Intra-component structural reachability analysis.
 *
 * For each vulnerable dependency usage, determines whether its data can structurally reach a security-sensitive sink within a component, following React's data flow model: hooks -> local variables -> JSX render.
 * levels:
 * - CRITICAL: imported identifier flows directly into a sink expression
 * - HIGH: a variable derived from the import (via hooks or local propagation) reaches a sink
 * - MEDIUM: dep used in a component with sinks, but no data path proven
 * - LOW: dep imported but no component or sink context
 * - NONE: dep imported but identifiers never referenced (dead import)
 *
 * When a Component Graph (graph) is provided, also performs inter-component reachability: if tainted data is passed as a prop to a child component that contains a security sink, a HIGH inter-component finding is emitted.
 */
function computeReachability(
  dependencyUsages,
  components,
  sinks,
  graph = null,
) {
  const findings = [];

  for (const usage of dependencyUsages) {
    const vulnIds = new Set(usage.importedAs);
    const fileComponents = components.filter(
      (c) => c.filePath === usage.filePath,
    );
    const fileSinks = sinks.filter((s) => s.filePath === usage.filePath);

    // No binding names captured - can't trace data flow
    if (vulnIds.size === 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "LOW",
        auditSeverity: usage.auditSeverity ?? "unknown",
        reason:
          "Vulnerable dependency imported but no binding name captured (dynamic import or bare require)",
        component: null,
        sinkType: null,
        sinkLoc: null,
        taintedPath: [],
      });
      continue;
    }

    // Find components that actually reference the vulnerable identifiers
    const relevantComponents = fileComponents.filter((c) =>
      usage.importedAs.some((id) => id in c.usedImports),
    );

    if (relevantComponents.length === 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "NONE",
        auditSeverity: usage.auditSeverity ?? "unknown",
        reason:
          "Vulnerable dependency imported but identifiers are never referenced in any component",
        component: null,
        sinkType: null,
        sinkLoc: null,
        taintedPath: [],
      });
      continue;
    }

    for (const component of relevantComponents) {
      const componentSinks = fileSinks.filter((s) =>
        isInsideComponent(s, component),
      );

      // Always compute tainted identifiers - needed for both intra- and inter-component analysis
      const tainted = computeTaintedIdentifiers(component.bodyNode, vulnIds);

      if (componentSinks.length === 0) {
        // Component uses the dep but contains no sinks
        findings.push({
          packageName: usage.packageName,
          filePath: usage.filePath,
          reachability: "MEDIUM",
          auditSeverity: usage.auditSeverity ?? "unknown",
          reason:
            "Vulnerable dependency used inside React component but no security sink found in this component",
          component: component.name,
          sinkType: null,
          sinkLoc: null,
          taintedPath: [...usage.importedAs],
        });
      } else {
        // Intra-component sink matching
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
              auditSeverity: usage.auditSeverity ?? "unknown",
              reason: isDirect
                ? "Vulnerable dependency identifier flows directly into a security sink"
                : "Variable derived from vulnerable dependency reaches a security sink via React hooks or local propagation",
              component: component.name,
              sinkType: sink.sinkType,
              sinkLoc: sink.loc,
              ...sinkMetadata(sink),
              taintedPath: overlap,
            });
          }
        }

        // Component has sinks but no proven data path
        if (!componentHasSinkPath) {
          findings.push({
            packageName: usage.packageName,
            filePath: usage.filePath,
            reachability: "MEDIUM",
            auditSeverity: usage.auditSeverity ?? "unknown",
            reason:
              "Vulnerable dependency used in a component with sinks, but no structural data path found",
            component: component.name,
            sinkType: null,
            sinkLoc: null,
            taintedPath: [...usage.importedAs],
          });
        }
      }

      // Inter-component analysis
      if (graph) {
        const taintedJSXProps = collectTaintedJSXProps(
          component.bodyNode,
          tainted,
        );

        for (const [childName, propNames] of taintedJSXProps) {
          const childNodes = graph.getNodeByName(childName);

          for (const childGraphNode of childNodes) {
            const childComp = childGraphNode.component;
            const childCompSinks = sinks.filter(
              (s) =>
                s.filePath === childComp.filePath &&
                isInsideComponent(s, childComp),
            );

            if (childCompSinks.length === 0) continue;

            const propSeedIds = extractPropSeedIdentifiers(
              childComp.params,
              propNames,
            );
            if (propSeedIds.size === 0) continue;

            const childTainted = computeTaintedIdentifiers(
              childComp.bodyNode,
              propSeedIds,
            );

            for (const childSink of childCompSinks) {
              const sinkIds = new Set(childSink.identifiers);
              const overlap = [...childTainted].filter((id) => sinkIds.has(id));

              if (overlap.length > 0) {
                findings.push({
                  packageName: usage.packageName,
                  filePath: usage.filePath,
                  reachability: "HIGH",
                  auditSeverity: usage.auditSeverity ?? "unknown",
                  reason:
                    "Tainted data from vulnerable dependency flows through component props boundary into a security sink in a child component",
                  component: component.name,
                  childComponent: childComp.name,
                  sinkType: childSink.sinkType,
                  sinkLoc: childSink.loc,
                  ...sinkMetadata(childSink),
                  sinkFilePath: childComp.filePath,
                  taintedPath: [...propNames, ...overlap],
                  propagationType: "inter-component",
                });
              }
            }
          }
        }
      }
    }
  }

  return findings;
}

module.exports = computeReachability;
