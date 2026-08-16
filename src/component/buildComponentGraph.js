/**
 * Builds a Component Graph (CoG) from the extracted React components.
 *
 * The CoG is a directed graph where an edge A -> B means component A renders
 * component B within its JSX output, modelling the primary inter-component
 * data-flow channel in React: props passed from parent to child.
 *
 * Nodes:
 * - One node per extracted component, uniquely keyed by "filePath#ComponentName".
 *
 * Edges:
 * - Derived from each component's "renderedComponents" list, which records every PascalCase JSX element name rendered in its body.
 *
 * Resolution strategy for rendered names -> graph nodes
 * - Same-file preference: if a component named B exists in the same file as A, it is matched first. This handles locally-defined sub-components.
 * - Import resolution: relative imports are resolved to the matching source module before any global name lookup.
 * - Global fallback: if neither same-file nor import resolution succeeds, the name is looked up across all files. When multiple components share a name, all candidates are linked conservatively.
 * - Unresolved: names that cannot be matched to any extracted component (third-party UI library components such as <Button> or <Modal>) are stored in "node.unresolvedChildren" just for traceability.
 *
 * Cycles:
 * - React does not allow true rendering cycles at runtime, but the extraction is structural. All BFS traversals are cycle-safe via a visited set.
 * - Self-references (a component rendering itself) are ignored as they do not contribute to inter-component reachability.
 */
const path = require("path");

/**
 * Produces the unique node key for a given (filePath, componentName) pair.
 * @param {string} filePath
 * @param {string} name
 * @returns {string}
 */
function makeKey(filePath, name) {
  return `${filePath}#${name}`;
}

function moduleKeys(filePath) {
  const normalized = path.normalize(filePath);
  const withoutExtension = normalized.replace(/\.(?:js|jsx|ts|tsx)$/, "");
  const keys = [withoutExtension];
  if (path.basename(withoutExtension) === "index") keys.push(path.dirname(withoutExtension));
  return keys;
}

function addToIndex(index, key, node) {
  if (!index.has(key)) index.set(key, []);
  index.get(key).push(node);
}

function createGraphNode(component) {
  return {
    key: makeKey(component.filePath, component.name),
    component,
    children: [],
    parents: [],
    unresolvedChildren: [],
    childEdges: [],
  };
}

function allocateGraphNodes(components) {
  const nodes = new Map();
  const byName = new Map();
  const byModulePath = new Map();
  for (const component of components) {
    const node = createGraphNode(component);
    if (nodes.has(node.key)) continue;
    nodes.set(node.key, node);
    addToIndex(byName, component.name, node);
    for (const moduleKey of moduleKeys(component.filePath)) addToIndex(byModulePath, moduleKey, node);
  }
  return { nodes, byName, byModulePath };
}

function importedComponentName(importInfo, renderedName) {
  return importInfo.importedName !== "default" && importInfo.importedName !== "*"
    ? importInfo.importedName
    : renderedName;
}

function resolveImportedCandidates(component, renderedName, byModulePath) {
  const importInfo = component.componentImports?.[renderedName];
  if (!importInfo?.source?.startsWith(".")) return [];
  const importKey = path.normalize(path.resolve(path.dirname(component.filePath), importInfo.source));
  const candidates = byModulePath.get(importKey) || [];
  const expectedName = importedComponentName(importInfo, renderedName);
  const named = candidates.filter((candidate) => candidate.component.name === expectedName);
  if (named.length) return named;
  return candidates.length === 1 ? candidates : [];
}

function resolveRenderedCandidates(parentNode, renderedName, indexes) {
  const { component } = parentNode;
  const sameFile = indexes.nodes.get(makeKey(component.filePath, renderedName));
  if (sameFile) return { nodes: [sameFile], resolution: "same-file", confidence: 100 };
  const imported = resolveImportedCandidates(component, renderedName, indexes.byModulePath);
  if (imported.length) return { nodes: imported, resolution: "import", confidence: 100 };
  const global = indexes.byName.get(renderedName) || [];
  if (global.length) return { nodes: global, resolution: "global-fallback", confidence: 60 };
  return null;
}

function connectNodes(parentNode, childNode, renderedName, resolution, confidence, graphState) {
  if (childNode === parentNode) return;
  if (!parentNode.children.includes(childNode)) {
    parentNode.children.push(childNode);
    childNode.parents.push(parentNode);
    graphState.edgeCount++;
  }
  const edgeExists = parentNode.childEdges.some((edge) => edge.node === childNode && edge.renderedName === renderedName);
  if (!edgeExists) parentNode.childEdges.push({ node: childNode, renderedName, resolution, confidence });
}

function recordUnresolvedChild(node, renderedName) {
  if (!node.unresolvedChildren.includes(renderedName)) node.unresolvedChildren.push(renderedName);
}

function connectGraphEdges(indexes) {
  const graphState = { edgeCount: 0 };
  for (const node of indexes.nodes.values()) {
    for (const renderedName of node.component.renderedComponents || []) {
      if (renderedName === node.component.name) continue;
      const resolved = resolveRenderedCandidates(node, renderedName, indexes);
      if (!resolved) {
        recordUnresolvedChild(node, renderedName);
        continue;
      }
      for (const childNode of resolved.nodes) {
        connectNodes(node, childNode, renderedName, resolved.resolution, resolved.confidence, graphState);
      }
    }
  }
  return graphState.edgeCount;
}

function traverseRelations(initialNodes, relation) {
  const visited = new Set();
  const queue = [...initialNodes];
  while (queue.length > 0) {
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);
    queue.push(...current[relation]);
  }
  return visited;
}

function createGraphApi(indexes, edgeCount) {
  const { nodes, byName } = indexes;
  return {
    nodes,
    get size() { return nodes.size; },
    edgeCount,
    getNode(filePath, name) { return nodes.get(makeKey(filePath, name)); },
    getNodeByName(name) { return byName.get(name) || []; },
    resolveRenderedChild(component, renderedName) {
      const parent = nodes.get(makeKey(component.filePath, component.name));
      return parent ? parent.childEdges.filter((edge) => edge.renderedName === renderedName) : [];
    },
    roots() { return [...nodes.values()].filter((node) => node.parents.length === 0); },
    ancestors(node) { return traverseRelations(node.parents, "parents"); },
    descendants(node) { return traverseRelations(node.children, "children"); },
  };
}

/**
 * Builds the Component Graph from the extracted components array.
 *
 * @param {Array<{
 *   name: string,
 *   type: string,
 *   filePath: string,
 *   loc: object,
 *   bodyNode: object,
 *   usedImports: object,
 *   renderedComponents: string[]
 * }>} components - Output of extractComponents()
 *
 * @returns {{
 *   nodes: Map<string, GraphNode>,
 *   size: number,
 *   edgeCount: number,
 *   getNode(filePath: string, name: string): GraphNode|undefined,
 *   getNodeByName(name: string): GraphNode[],
 *   roots(): GraphNode[],
 *   ancestors(node: GraphNode): Set<GraphNode>,
 *   descendants(node: GraphNode): Set<GraphNode>
 * }}
 *
 * @typedef {{
 *   key: string,
 *   component: object,
 *   children: GraphNode[],
 *   parents: GraphNode[],
 *   unresolvedChildren: string[]
 * }} GraphNode
 */
function buildComponentGraph(components) {
  const indexes = allocateGraphNodes(components);
  const edgeCount = connectGraphEdges(indexes);
  return createGraphApi(indexes, edgeCount);
}

module.exports = buildComponentGraph;
