const test = require("node:test");
const assert = require("node:assert/strict");
const extractDependencyUsage = require("../src/dependency/extractDependencyUsage");
const extractComponents = require("../src/component/extractComponents");
const { parseSnippet } = require("./helpers/parseSnippet");

test("dependency extraction characterizes imports, require, and dynamic import", () => {
  const vulnerable = new Map([
    ["unsafe", { severity: "critical" }],
    ["@scope/risky", { severity: "high" }],
  ]);
  const file = parseSnippet(`
    import value, { helper as localHelper } from "unsafe/subpath";
    const { run: localRun } = require("@scope/risky/feature");
    import("unsafe");
  `, "dependencies.js");
  const usages = extractDependencyUsage([file], vulnerable);
  assert.deepEqual(usages.map((usage) => usage.type), ["import", "require", "dynamic-import"]);
  assert.deepEqual(usages[0].importedAs, ["value", "localHelper"]);
  assert.deepEqual(usages[1].importedAs, ["localRun"]);
  assert.equal(usages[2].auditSeverity, "critical");
});

test("component extraction characterizes function, arrow, and class components", () => {
  const file = parseSnippet(`
    import React, { Component } from "react";
    import Widget from "./Widget";
    function FunctionView({ value }) { return <Widget value={value} />; }
    const ArrowView = () => <FunctionView value="x" />;
    class ClassView extends Component { render() { return <ArrowView />; } }
  `, "components.jsx");
  const components = extractComponents([file]);
  assert.deepEqual(components.map((component) => component.name), ["FunctionView", "ArrowView", "ClassView"]);
  assert.deepEqual(components[0].renderedComponents, ["Widget"]);
  assert.equal(components[2].type, "ClassComponent");
});
