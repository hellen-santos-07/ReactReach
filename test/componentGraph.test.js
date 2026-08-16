const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const buildComponentGraph = require("../src/component/buildComponentGraph");

function component(name, filePath, renderedComponents = [], componentImports = {}) {
  return { name, filePath, renderedComponents, componentImports };
}

test("component graph exposes same-file edges, unresolved children and cycle-safe traversals", () => {
  const filePath = path.resolve("project/src/Tree.jsx");
  const parent = component("Parent", filePath, ["Child", "Unknown"]);
  const child = component("Child", filePath, ["GrandChild"]);
  const grandChild = component("GrandChild", filePath);
  const duplicateParent = component("Parent", filePath, ["GrandChild"]);
  const graph = buildComponentGraph([parent, child, grandChild, duplicateParent]);

  const parentNode = graph.getNode(filePath, "Parent");
  const childNode = graph.getNode(filePath, "Child");
  const grandChildNode = graph.getNode(filePath, "GrandChild");
  assert.equal(graph.size, 3);
  assert.equal(graph.edgeCount, 2);
  assert.deepEqual(graph.roots(), [parentNode]);
  assert.deepEqual(parentNode.unresolvedChildren, ["Unknown"]);
  assert.deepEqual([...graph.descendants(parentNode)], [childNode, grandChildNode]);
  assert.deepEqual([...graph.ancestors(grandChildNode)], [childNode, parentNode]);
  assert.deepEqual(graph.resolveRenderedChild(parent, "Child").map((edge) => edge.resolution), ["same-file"]);
  assert.deepEqual(graph.getNodeByName("missing"), []);
});

test("component graph prefers relative imports and otherwise records conservative global fallbacks", () => {
  const parentFile = path.resolve("project/src/Parent.jsx");
  const importedParentFile = path.resolve("project/src/ImportedParent.jsx");
  const safeFile = path.resolve("project/src/safe/Target.jsx");
  const otherFile = path.resolve("project/src/other/Target.jsx");
  const globalParent = component("GlobalParent", parentFile, ["Target"]);
  const importedParent = component("ImportedParent", importedParentFile, ["Alias"], {
    Alias: { source: "./safe/Target", importedName: "default" },
  });
  const safeTarget = component("Target", safeFile);
  const otherTarget = component("Target", otherFile);
  const graph = buildComponentGraph([globalParent, importedParent, safeTarget, otherTarget]);

  const globalEdges = graph.resolveRenderedChild(globalParent, "Target");
  assert.equal(globalEdges.length, 2);
  assert.ok(globalEdges.every((edge) => edge.resolution === "global-fallback" && edge.confidence === 60));
  const [importEdge] = graph.resolveRenderedChild(importedParent, "Alias");
  assert.equal(importEdge.node.component, safeTarget);
  assert.equal(importEdge.resolution, "import");
  assert.equal(importEdge.confidence, 100);
});
