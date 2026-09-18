const t = require("@babel/types");
const { REASON_CODES, REASONS } = require("./classification");
const createReachabilityChain = require("./handlers/createReachabilityChain");
const { computeTaintedBindings, referencesTaint } = require("./taintPropagation");

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
function propertyKeyName(property) {
  if (t.isIdentifier(property.key)) return property.key.name;
  return t.isStringLiteral(property.key) ? property.key.value : null;
}

function localPatternName(value) {
  if (t.isIdentifier(value)) return value.name;
  return t.isAssignmentPattern(value) && t.isIdentifier(value.left) ? value.left.name : null;
}

function collectObjectPatternSeeds(pattern, taintedPropNames) {
  const seeds = new Set();
  for (const property of pattern.properties) {
    if (t.isRestElement(property)) {
      if (t.isIdentifier(property.argument)) seeds.add(property.argument.name);
      continue;
    }
    if (!t.isObjectProperty(property)) continue;
    const keyName = propertyKeyName(property);
    if (!keyName || !taintedPropNames.has(keyName)) continue;
    const localName = localPatternName(property.value);
    if (localName) seeds.add(localName);
  }
  return seeds;
}

function extractPropSeedIdentifiers(params, taintedPropNames) {
  if (!params || params.length === 0) return new Set();
  const firstParam = params[0];
  if (t.isObjectPattern(firstParam)) return collectObjectPatternSeeds(firstParam, taintedPropNames);
  const seeds = new Set();
  if (t.isIdentifier(firstParam)) seeds.add(firstParam.name);
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

function createFinding(usage, classification, values) {
  return {
    packageName: usage.packageName,
    filePath: usage.filePath,
    auditSeverity: usage.auditSeverity ?? "unknown",
    reasonCode: classification.reasonCode,
    reason: REASONS[classification.reasonCode],
    reachability: classification.reachability,
    ...values,
  };
}

function classifyFinding(chain, usage, context, values) {
  const classification = chain.handle(context);
  return classification ? createFinding(usage, classification, values) : null;
}

function findRelevantComponents(usage, componentsByFile) {
  return (componentsByFile.get(usage.filePath) || []).filter((component) =>
    usage.importedAs.some((identifier) => identifier in component.usedImports),
  );
}

function analyzeIntraComponent(usage, component, vulnIds, componentSinks, options, chain) {
  const findings = [];
  const taint = computeTaintedBindings(component, vulnIds, options);
  const componentFinding = classifyFinding(chain, usage, {
    stage: "component",
    componentSinks,
  }, {
    component: component.name,
    sinkType: null,
    sinkLoc: null,
    taintedPath: [...usage.importedAs],
  });
  if (componentFinding) {
    findings.push(componentFinding);
    return { findings, taint };
  }

  let hasSinkPath = false;
  for (const sink of componentSinks) {
    const overlap = sinkOverlap(sink, taint);
    const direct = overlap.bindings.some((binding) => taint.sourceBindings.has(binding)) ||
      (overlap.bindings.length === 0 && overlap.names.some((identifier) => vulnIds.has(identifier)));
    const finding = classifyFinding(chain, usage, {
      stage: "sink",
      hasTaintOverlap: overlap.names.length > 0,
      direct,
    }, {
      component: component.name,
      sinkType: sink.sinkType,
      sinkLoc: sink.loc,
      ...sinkMetadata(sink),
      taintedPath: overlap.names,
    });
    if (!finding) continue;
    hasSinkPath = true;
    findings.push(finding);
  }
  const fallbackFinding = classifyFinding(chain, usage, {
    stage: "component-fallback",
    hasSinkPath,
  }, {
    component: component.name,
    sinkType: null,
    sinkLoc: null,
    taintedPath: [...usage.importedAs],
  });
  if (fallbackFinding) findings.push(fallbackFinding);
  return { findings, taint };
}

function resolveRenderedEdges(graph, component, renderedName) {
  if (graph.resolveRenderedChild) return graph.resolveRenderedChild(component, renderedName);
  return graph.getNodeByName(renderedName).map((node) => ({
    node,
    resolution: "global-fallback",
    confidence: 60,
  }));
}

function createChildTraversalState(rootComponent, state, edge, propNames, visited, options) {
  const childComponent = edge.node.component;
  if (childComponent === rootComponent) return null;
  const propSeedIds = extractPropSeedIdentifiers(childComponent.params, propNames);
  if (propSeedIds.size === 0) return null;
  const visitKey = `${edge.node.key}|${[...propSeedIds].sort().join(",")}`;
  if (visited.has(visitKey)) return null;
  visited.add(visitKey);
  const propagationStep = {
    from: state.current.name,
    to: childComponent.name,
    props: [...propNames],
    resolution: edge.resolution,
  };
  return {
    current: childComponent,
    taint: computeTaintedBindings(childComponent, propSeedIds, options),
    componentPath: [...state.componentPath, childComponent.name],
    propagationPath: [...state.propagationPath, propagationStep],
    taintedProps: [...state.taintedProps, ...propNames],
    resolutionConfidence: Math.min(state.resolutionConfidence, edge.confidence ?? 60),
  };
}

function classifyChildComponentSinks(usage, rootComponent, state, sinksByComponent, chain) {
  const findings = [];
  for (const sink of sinksByComponent.get(state.current) || []) {
    const overlap = sinkOverlap(sink, state.taint);
    const finding = classifyFinding(chain, usage, {
      stage: "inter-component",
      hasTaintOverlap: overlap.names.length > 0,
    }, {
      component: rootComponent.name,
      childComponent: state.current.name,
      componentPath: state.componentPath,
      propagationPath: state.propagationPath,
      sinkType: sink.sinkType,
      sinkLoc: sink.loc,
      ...sinkMetadata(sink),
      componentResolutionConfidence: state.resolutionConfidence,
      sinkFilePath: state.current.filePath,
      taintedPath: [...state.taintedProps, ...overlap.names],
      propagationType: "inter-component",
    });
    if (finding) findings.push(finding);
  }
  return findings;
}

function analyzeInterComponent(usage, component, initialTaint, graph, sinksByComponent, options, chain) {
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
      const edges = resolveRenderedEdges(graph, state.current, renderedName);
      for (const edge of edges) {
        const childState = createChildTraversalState(component, state, edge, propNames, visited, options);
        if (!childState) continue;
        findings.push(...classifyChildComponentSinks(usage, component, childState, sinksByComponent, chain));
        queue.push(childState);
      }
    }
  }
  return findings;
}

function analyzeUsage(usage, indexes, graph, options, chain) {
  const vulnIds = new Set(usage.importedAs);
  const relevantComponents = findRelevantComponents(usage, indexes.componentsByFile);
  const usageFinding = classifyFinding(chain, usage, {
    stage: "usage",
    vulnerableIdentifiers: vulnIds,
    relevantComponents,
  }, { component: null, sinkType: null, sinkLoc: null, taintedPath: [] });
  if (usageFinding) return [usageFinding];
  const findings = [];
  for (const component of relevantComponents) {
    const intra = analyzeIntraComponent(usage, component, vulnIds, indexes.sinksByComponent.get(component) || [], options, chain);
    findings.push(...intra.findings);
    findings.push(...analyzeInterComponent(usage, component, intra.taint, graph, indexes.sinksByComponent, options, chain));
  }
  return findings;
}

function computeReachability(dependencyUsages, components, sinks, graph = null, config = {}) {
  const indexes = createAnalysisIndexes(components, sinks);
  const diagnostics = [];
  const options = { maxIterations: config.maxTaintIterations ?? 100, diagnostics };
  const chain = createReachabilityChain();
  const findings = dependencyUsages.flatMap((usage) => analyzeUsage(usage, indexes, graph, options, chain));
  Object.defineProperty(findings, "diagnostics", { value: diagnostics, enumerable: false });
  return findings;
}

module.exports = computeReachability;
module.exports.REASON_CODES = REASON_CODES;
module.exports.createAnalysisIndexes = createAnalysisIndexes;
