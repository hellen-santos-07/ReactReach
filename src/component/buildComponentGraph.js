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
 * - Global fallback: if no same-file match exists, the name is looked up across all files. When multiple components share a name (rare), all candidates are linked conservatively.
 * - Unresolved: names that cannot be matched to any extracted component (third-party UI library components such as <Button> or <Modal>) are stored in "node.unresolvedChildren" just for traceability.
 *
 * Cycles:
 * - React does not allow true rendering cycles at runtime, but the extraction is structural. All BFS traversals are cycle-safe via a visited set.
 * - Self-references (a component rendering itself) are ignored as they do not contribute to inter-component reachability.
 */

/**
 * Produces the unique node key for a given (filePath, componentName) pair.
 * @param {string} filePath
 * @param {string} name
 * @returns {string}
 */
function makeKey(filePath, name) {
  return `${filePath}#${name}`;
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
  // step 1: allocate one node per component

  /** @type {Map<string, GraphNode>} */
  const nodes = new Map();

  /** @type {Map<string, GraphNode[]>} name -> [nodes] for resolution */
  const byName = new Map();

  for (const component of components) {
    const key = makeKey(component.filePath, component.name);

    // Guard against duplicate (filePath, name) pairs - keep the first
    if (nodes.has(key)) continue;

    /** @type {GraphNode} */
    const node = {
      key,
      component,
      children: [], // GraphNode[] rendered by this component
      parents: [], // GraphNode[] that render this component
      unresolvedChildren: [], // string[]  names that could not be resolved
    };

    nodes.set(key, node);

    if (!byName.has(component.name)) {
      byName.set(component.name, []);
    }
    byName.get(component.name).push(node);
  }

  // step 2: resolve edges from renderedComponents
  let edgeCount = 0;

  for (const node of nodes.values()) {
    const { component } = node;
    const rendered = component.renderedComponents || [];

    for (const childName of rendered) {
      // Skip self-references (should not occur, but guard anyway)
      if (childName === component.name) continue;

      // Stage 1 - same-file match
      const sameFileKey = makeKey(component.filePath, childName);
      if (nodes.has(sameFileKey)) {
        const childNode = nodes.get(sameFileKey);
        if (!node.children.includes(childNode)) {
          node.children.push(childNode);
          childNode.parents.push(node);
          edgeCount++;
        }
        continue;
      }

      // Stage 2 - global (cross-file) fallback
      const candidates = byName.get(childName);
      if (candidates && candidates.length > 0) {
        for (const childNode of candidates) {
          if (!node.children.includes(childNode)) {
            node.children.push(childNode);
            childNode.parents.push(node);
            edgeCount++;
          }
        }
        continue;
      }

      // Stage 3 - unresolved (third-party component or HTML element)
      if (!node.unresolvedChildren.includes(childName)) {
        node.unresolvedChildren.push(childName);
      }
    }
  }

  // step 3: public graph API
  return {
    /** All component nodes keyed by "filePath#ComponentName". */
    nodes,

    /** Number of nodes in the graph. */
    get size() {
      return nodes.size;
    },

    /** Number of directed edges (parent renders child) in the graph. */
    edgeCount,

    /**
     * Retrieve a node by its exact (filePath, name) coordinates.
     * @param {string} filePath
     * @param {string} name
     * @returns {GraphNode|undefined}
     */
    getNode(filePath, name) {
      return nodes.get(makeKey(filePath, name));
    },

    /**
     * Retrieve all nodes that share a given component name (across all files).
     * Returns an empty array when no match is found.
     * @param {string} name
     * @returns {GraphNode[]}
     */
    getNodeByName(name) {
      return byName.get(name) || [];
    },

    /**
     * Root components: those not rendered by any other component in the graph. These represent the application entry points (<App/>).
     * @returns {GraphNode[]}
     */
    roots() {
      return [...nodes.values()].filter((n) => n.parents.length === 0);
    },

    /**
     * Returns all ancestor nodes of a given component - every component that directly or transitively renders it. BFS, cycle-safe.
     * @param {GraphNode} node
     * @returns {Set<GraphNode>}
     */
    ancestors(node) {
      const visited = new Set();
      const queue = [...node.parents];
      while (queue.length > 0) {
        const current = queue.shift();
        if (visited.has(current)) continue;
        visited.add(current);
        queue.push(...current.parents);
      }
      return visited;
    },

    /**
     * Returns all descendant nodes of a given component - every componentthat it directly or transitively renders. BFS, cycle-safe.
     * @param {GraphNode} node
     * @returns {Set<GraphNode>}
     */
    descendants(node) {
      const visited = new Set();
      const queue = [...node.children];
      while (queue.length > 0) {
        const current = queue.shift();
        if (visited.has(current)) continue;
        visited.add(current);
        queue.push(...current.children);
      }
      return visited;
    },
  };
}

module.exports = buildComponentGraph;
