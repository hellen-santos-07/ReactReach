const assert = require("node:assert/strict");
const test = require("node:test");

test("the package root exposes scanProject as its public API", () => {
  const api = require("..");
  const implementation = require("../src/scanProject");

  assert.deepEqual(Object.keys(api), ["scanProject"]);
  assert.strictEqual(api.scanProject, implementation.scanProject);
});
