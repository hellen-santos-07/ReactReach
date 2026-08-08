const t = require("@babel/types");

// React hooks that propagate data and need taint tracking
const REACT_HOOKS = new Set([
  "useState",
  "useMemo",
  "useCallback",
  "useReducer",
]);

function collectPathBindings(nodePath) {
  const bindings = new Set();
  function collect(path) {
    if (!path.isIdentifier() || !path.isReferencedIdentifier()) return;
    const binding = path.scope.getBinding(path.node.name);
    if (binding) bindings.add(binding);
  }
  collect(nodePath);
  if (nodePath.traverse) nodePath.traverse({ Identifier: collect });
  return bindings;
}

function referencesTaint(nodePath, taintedBindings) {
  return [...collectPathBindings(nodePath)].some((binding) => taintedBindings.has(binding));
}

function addPatternBindings(patternPath, taintedBindings) {
  let changed = false;
  for (const name of Object.keys(t.getBindingIdentifiers(patternPath.node))) {
    const binding = patternPath.scope.getBinding(name);
    if (binding && !taintedBindings.has(binding)) {
      taintedBindings.add(binding);
      changed = true;
    }
  }
  return changed;
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
function collectSetterBindings(bodyPath) {
  const setterToState = new Map();
  bodyPath.traverse({
    VariableDeclarator(path) {
      if (!t.isArrayPattern(path.node.id) || !t.isCallExpression(path.node.init) || getHookName(path.node.init) !== "useState") return;
      const [stateNode, setterNode] = path.node.id.elements;
      if (!t.isIdentifier(stateNode) || !t.isIdentifier(setterNode)) return;
      const stateBinding = path.scope.getBinding(stateNode.name);
      const setterBinding = path.scope.getBinding(setterNode.name);
      if (stateBinding && setterBinding) setterToState.set(setterBinding, stateBinding);
    },
  });
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
function propagateBindingPass(bodyPath, taintedBindings, setterToState) {
  let changed = false;
  function add(binding) {
    if (!binding || taintedBindings.has(binding)) return;
    taintedBindings.add(binding);
    changed = true;
  }
  bodyPath.traverse({
    CallExpression(path) {
      if (!t.isIdentifier(path.node.callee) || path.node.arguments.length === 0) return;
      const setterBinding = path.scope.getBinding(path.node.callee.name);
      const stateBinding = setterToState.get(setterBinding);
      const firstArgument = path.get("arguments")[0];
      if (stateBinding && firstArgument && referencesTaint(firstArgument, taintedBindings)) add(stateBinding);
    },
    VariableDeclarator(path) {
      if (!path.node.init) return;
      const initPath = path.get("init");
      const idPath = path.get("id");
      const hookName = t.isCallExpression(path.node.init) ? getHookName(path.node.init) : null;
      if (hookName === "useState") {
        const initial = initPath.get("arguments")[0];
        const stateNode = t.isArrayPattern(path.node.id) ? path.node.id.elements[0] : null;
        if (initial && t.isIdentifier(stateNode) && referencesTaint(initial, taintedBindings)) add(path.scope.getBinding(stateNode.name));
        return;
      }
      if (hookName === "useReducer") {
        const initial = initPath.get("arguments")[1];
        const stateNode = t.isArrayPattern(path.node.id) ? path.node.id.elements[0] : null;
        if (initial && t.isIdentifier(stateNode) && referencesTaint(initial, taintedBindings)) add(path.scope.getBinding(stateNode.name));
        return;
      }
      if (referencesTaint(initPath, taintedBindings) && addPatternBindings(idPath, taintedBindings)) changed = true;
    },
    AssignmentExpression(path) {
      if (!t.isIdentifier(path.node.left) || !referencesTaint(path.get("right"), taintedBindings)) return;
      add(path.scope.getBinding(path.node.left.name));
    },
  });
  return changed;
}

/**
 * Computes the full set of tainted identifiers within a component.
 * 1. seeds with the vulnerable dependency's imported identifiers
 * 2. propagates through hooks (useState, useMemo, useCallback, useReducer)
 * 3. propagates through local variable assignments and setter calls
 * 4. runs two passes to handle short taint chains
 */
function computeTaintedBindings(component, sourceIdentifiers, options = {}) {
  const taintedBindings = new Set();
  const sourceBindings = new Set();
  const bodyPath = component.bodyPath;
  if (!bodyPath) return { bindings: taintedBindings, sourceBindings, names: new Set(sourceIdentifiers) };
  for (const identifier of sourceIdentifiers) {
    const binding = component.componentPath.scope.getBinding(identifier);
    if (binding) {
      taintedBindings.add(binding);
      sourceBindings.add(binding);
    }
  }
  const setterToState = collectSetterBindings(bodyPath);
  const maxIterations = options.maxIterations ?? 100;
  let changed = true;
  let iterations = 0;
  while (changed && iterations < maxIterations) {
    changed = propagateBindingPass(bodyPath, taintedBindings, setterToState);
    iterations++;
  }
  if (changed) {
    options.diagnostics?.push({
      code: "TAINT_ITERATION_LIMIT",
      filePath: component.filePath,
      component: component.name,
      maxIterations,
      message: `Taint propagation reached the ${maxIterations}-iteration limit`,
    });
  }
  return {
    bindings: taintedBindings,
    sourceBindings,
    names: new Set([...taintedBindings].map((binding) => binding.identifier.name)),
  };
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

function sinkOverlap(sink, taint) {
  if (Array.isArray(sink.referencedBindings)) {
    const bindings = sink.referencedBindings.filter((binding) => taint.bindings.has(binding));
    return {
      bindings,
      names: [...new Set(bindings.map((binding) => binding.identifier.name))],
    };
  }
  const names = sink.identifiers.filter((identifier) => taint.names.has(identifier));
  return { bindings: [], names };
}

/**
 * Finds JSX attributes in a component body that pass tainted data as props to child components (PascalCase JSX elements).
 *
 * Returns a Map: childComponentName -> Set<propName>
 * Only non-spread JSXAttributes whose value expression references at least
 * one tainted identifier are included.
 */
function collectTaintedJSXProps(component, taint) {
  const taintedProps = new Map();
  if (!component.bodyPath) return taintedProps;
  component.bodyPath.traverse({
    JSXOpeningElement(path) {
      const nameNode = path.node.name;
      if (!t.isJSXIdentifier(nameNode) || !/^[A-Z]/.test(nameNode.name)) return;
      const childName = nameNode.name;
      for (const attributePath of path.get("attributes")) {
        if (!attributePath.isJSXAttribute() || !attributePath.node.name) continue;
        const attributeName = typeof attributePath.node.name.name === "string" ? attributePath.node.name.name : null;
        const valuePath = attributePath.get("value");
        if (!attributeName || !valuePath.isJSXExpressionContainer()) continue;
        if (!referencesTaint(valuePath.get("expression"), taint.bindings)) continue;
        if (!taintedProps.has(childName)) taintedProps.set(childName, new Set());
        taintedProps.get(childName).add(attributeName);
      }
    },
  });
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
const REASON_CODES = Object.freeze({
  NO_BINDING: "NO_BINDING",
  UNUSED_IMPORT: "UNUSED_IMPORT",
  COMPONENT_WITHOUT_SINK: "COMPONENT_WITHOUT_SINK",
  DIRECT_SINK_FLOW: "DIRECT_SINK_FLOW",
  PROPAGATED_SINK_FLOW: "PROPAGATED_SINK_FLOW",
  NO_PROVEN_SINK_PATH: "NO_PROVEN_SINK_PATH",
  INTER_COMPONENT_SINK_FLOW: "INTER_COMPONENT_SINK_FLOW",
});

const REASONS = Object.freeze({
  [REASON_CODES.NO_BINDING]: "Vulnerable dependency imported but no binding name captured (dynamic import or bare require)",
  [REASON_CODES.UNUSED_IMPORT]: "Vulnerable dependency imported but identifiers are never referenced in any component",
  [REASON_CODES.COMPONENT_WITHOUT_SINK]: "Vulnerable dependency used inside React component but no security sink found in this component",
  [REASON_CODES.DIRECT_SINK_FLOW]: "Vulnerable dependency identifier flows directly into a security sink",
  [REASON_CODES.PROPAGATED_SINK_FLOW]: "Variable derived from vulnerable dependency reaches a security sink via React hooks or local propagation",
  [REASON_CODES.NO_PROVEN_SINK_PATH]: "Vulnerable dependency used in a component with sinks, but no structural data path found",
  [REASON_CODES.INTER_COMPONENT_SINK_FLOW]: "Tainted data from vulnerable dependency flows through component props boundary into a security sink in a child component",
});

function groupByFile(items) {
  const index = new Map();
  for (const item of items) {
    if (!index.has(item.filePath)) index.set(item.filePath, []);
    index.get(item.filePath).push(item);
  }
  return index;
}

function createAnalysisIndexes(components, sinks) {
  const componentsByFile = groupByFile(components);
  const sinksByFile = groupByFile(sinks);
  const sinksByComponent = new Map();
  for (const component of components) {
    const componentSinks = (sinksByFile.get(component.filePath) || []).filter((sink) => isInsideComponent(sink, component));
    sinksByComponent.set(component, componentSinks);
  }
  return { componentsByFile, sinksByFile, sinksByComponent };
}

function createFinding(usage, reasonCode, values) {
  return {
    packageName: usage.packageName,
    filePath: usage.filePath,
    auditSeverity: usage.auditSeverity ?? "unknown",
    reasonCode,
    reason: REASONS[reasonCode],
    ...values,
  };
}

function findRelevantComponents(usage, componentsByFile) {
  return (componentsByFile.get(usage.filePath) || []).filter((component) =>
    usage.importedAs.some((identifier) => identifier in component.usedImports),
  );
}

function analyzeIntraComponent(usage, component, vulnIds, componentSinks, options) {
  const findings = [];
  const taint = computeTaintedBindings(component, vulnIds, options);
  if (componentSinks.length === 0) {
    findings.push(createFinding(usage, REASON_CODES.COMPONENT_WITHOUT_SINK, {
      reachability: "MEDIUM",
      component: component.name,
      sinkType: null,
      sinkLoc: null,
      taintedPath: [...usage.importedAs],
    }));
    return { findings, taint };
  }

  let hasSinkPath = false;
  for (const sink of componentSinks) {
    const overlap = sinkOverlap(sink, taint);
    if (overlap.names.length === 0) continue;
    hasSinkPath = true;
    const direct = overlap.bindings.some((binding) => taint.sourceBindings.has(binding)) ||
      (overlap.bindings.length === 0 && overlap.names.some((identifier) => vulnIds.has(identifier)));
    const reasonCode = direct ? REASON_CODES.DIRECT_SINK_FLOW : REASON_CODES.PROPAGATED_SINK_FLOW;
    findings.push(createFinding(usage, reasonCode, {
      reachability: direct ? "CRITICAL" : "HIGH",
      component: component.name,
      sinkType: sink.sinkType,
      sinkLoc: sink.loc,
      ...sinkMetadata(sink),
      taintedPath: overlap.names,
    }));
  }
  if (!hasSinkPath) {
    findings.push(createFinding(usage, REASON_CODES.NO_PROVEN_SINK_PATH, {
      reachability: "MEDIUM",
      component: component.name,
      sinkType: null,
      sinkLoc: null,
      taintedPath: [...usage.importedAs],
    }));
  }
  return { findings, taint };
}

function analyzeInterComponent(usage, component, initialTaint, graph, sinksByComponent, options) {
  if (!graph) return [];
  const findings = [];
  const queue = [{
    current: component,
    taint: initialTaint,
    componentPath: [component.name],
    propagationPath: [],
    taintedProps: [],
    resolutionConfidence: 100,
  }];
  const visited = new Set();
  while (queue.length) {
    const state = queue.shift();
    const outgoingProps = collectTaintedJSXProps(state.current, state.taint);
    for (const [renderedName, propNames] of outgoingProps) {
      const edges = graph.resolveRenderedChild
        ? graph.resolveRenderedChild(state.current, renderedName)
        : graph.getNodeByName(renderedName).map((node) => ({ node, resolution: "global-fallback", confidence: 60 }));
      for (const edge of edges) {
        const childComponent = edge.node.component;
        if (childComponent === component) continue;
        const propSeedIds = extractPropSeedIdentifiers(childComponent.params, propNames);
        if (propSeedIds.size === 0) continue;
        const visitKey = `${edge.node.key}|${[...propSeedIds].sort().join(",")}`;
        if (visited.has(visitKey)) continue;
        visited.add(visitKey);
        const childTaint = computeTaintedBindings(childComponent, propSeedIds, options);
        const componentPath = [...state.componentPath, childComponent.name];
        const propagationStep = {
          from: state.current.name,
          to: childComponent.name,
          props: [...propNames],
          resolution: edge.resolution,
        };
        const propagationPath = [...state.propagationPath, propagationStep];
        const taintedProps = [...state.taintedProps, ...propNames];
        const resolutionConfidence = Math.min(state.resolutionConfidence, edge.confidence ?? 60);
        for (const sink of sinksByComponent.get(childComponent) || []) {
          const overlap = sinkOverlap(sink, childTaint);
          if (overlap.names.length === 0) continue;
          findings.push(createFinding(usage, REASON_CODES.INTER_COMPONENT_SINK_FLOW, {
            reachability: "HIGH",
            component: component.name,
            childComponent: childComponent.name,
            componentPath,
            propagationPath,
            sinkType: sink.sinkType,
            sinkLoc: sink.loc,
            ...sinkMetadata(sink),
            componentResolutionConfidence: resolutionConfidence,
            sinkFilePath: childComponent.filePath,
            taintedPath: [...taintedProps, ...overlap.names],
            propagationType: "inter-component",
          }));
        }
        queue.push({ current: childComponent, taint: childTaint, componentPath, propagationPath, taintedProps, resolutionConfidence });
      }
    }
  }
  return findings;
}

function analyzeUsage(usage, indexes, graph, options) {
  const vulnIds = new Set(usage.importedAs);
  if (vulnIds.size === 0) {
    return [createFinding(usage, REASON_CODES.NO_BINDING, {
      reachability: "LOW", component: null, sinkType: null, sinkLoc: null, taintedPath: [],
    })];
  }
  const relevantComponents = findRelevantComponents(usage, indexes.componentsByFile);
  if (relevantComponents.length === 0) {
    return [createFinding(usage, REASON_CODES.UNUSED_IMPORT, {
      reachability: "NONE", component: null, sinkType: null, sinkLoc: null, taintedPath: [],
    })];
  }
  const findings = [];
  for (const component of relevantComponents) {
    const intra = analyzeIntraComponent(usage, component, vulnIds, indexes.sinksByComponent.get(component) || [], options);
    findings.push(...intra.findings);
    findings.push(...analyzeInterComponent(usage, component, intra.taint, graph, indexes.sinksByComponent, options));
  }
  return findings;
}

function computeReachability(dependencyUsages, components, sinks, graph = null, config = {}) {
  const indexes = createAnalysisIndexes(components, sinks);
  const diagnostics = [];
  const options = { maxIterations: config.maxTaintIterations ?? 100, diagnostics };
  const findings = dependencyUsages.flatMap((usage) => analyzeUsage(usage, indexes, graph, options));
  Object.defineProperty(findings, "diagnostics", { value: diagnostics, enumerable: false });
  return findings;
}

module.exports = computeReachability;
module.exports.REASON_CODES = REASON_CODES;
module.exports.createAnalysisIndexes = createAnalysisIndexes;
