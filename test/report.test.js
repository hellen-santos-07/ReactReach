const test = require("node:test");
const assert = require("node:assert/strict");
const { buildReport, formatSarifReport, printSummaryTable } = require("../src/report/generateReport");

test("buildReport accepts an injected scan timestamp and preserves its schema", () => {
  const graph = { size: 1, edgeCount: 0 };
  const report = buildReport("/project", new Map(), [], [], graph, [], [], { scannedAt: "2026-01-02T03:04:05.000Z" });
  assert.equal(report.scannedAt, "2026-01-02T03:04:05.000Z");
  assert.deepEqual(report.configuration, {});
  assert.deepEqual(report.summary, { vulnerablePackages: 0, sourceFiles: 0, components: 0, cogNodes: 1, cogEdges: 0, sinks: 0, findings: 0 });
});

test("report records the effective scan configuration", () => {
  const config = { sinks: ["eval"], sort: "sink-priority" };
  const report = buildReport("/project", new Map(), [], [], { size: 0, edgeCount: 0 }, [], [], { config });
  assert.deepEqual(report.configuration, config);
});

test("SARIF formatting characterizes rule and source location output", () => {
  const finding = {
    packageName: "unsafe",
    auditSeverity: "critical",
    reachability: "CRITICAL",
    reason: "direct flow",
    component: "App",
    sinkType: "eval",
    filePath: "/project/src/App.jsx",
    sinkLoc: { start: { line: 4, column: 2 } },
    taintedPath: ["unsafe"],
    reasonCode: "DIRECT_SINK_FLOW",
  };
  const report = buildReport("/project", new Map(), [{ filePath: finding.filePath }], [], { size: 0, edgeCount: 0 }, [], [finding], { scannedAt: "2026-01-02T03:04:05.000Z" });
  const sarif = formatSarifReport(report);
  const result = sarif.runs[0].results[0];
  assert.equal(sarif.version, "2.1.0");
  assert.equal(result.level, "error");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 4);
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/App.jsx");
  assert.equal(result.properties.reasonCode, "DIRECT_SINK_FLOW");
});

test("summary table can sort reached sinks by configured priority", () => {
  const findings = [
    { packageName: "lower", reachability: "CRITICAL", sinkType: "eval", sinkPriority: 20, filePath: "/project/a.jsx" },
    { packageName: "higher", reachability: "HIGH", sinkType: "location-assign", sinkPriority: 90, filePath: "/project/b.jsx" },
  ];
  const output = [];
  const originalLog = console.log;
  console.log = (line = "") => output.push(line);
  try { printSummaryTable(findings, "/project/", { sort: "sink-priority" }); }
  finally { console.log = originalLog; }
  const text = output.join("\n");
  assert.ok(text.indexOf("higher") < text.indexOf("lower"));
});

test("SARIF preserves multi-component propagation evidence and diagnostics", () => {
  const finding = {
    packageName: "unsafe",
    auditSeverity: "high",
    reachability: "HIGH",
    reason: "inter-component flow",
    reasonCode: "INTER_COMPONENT_SINK_FLOW",
    component: "Parent",
    childComponent: "GrandChild",
    componentPath: ["Parent", "Middle", "GrandChild"],
    propagationPath: [
      { from: "Parent", to: "Middle", props: ["content"], resolution: "import" },
      { from: "Middle", to: "GrandChild", props: ["html"], resolution: "import" },
    ],
    componentResolutionConfidence: 100,
    propagationType: "inter-component",
    sinkType: "dangerouslySetInnerHTML",
    filePath: "/project/src/Parent.jsx",
    sinkFilePath: "/project/src/GrandChild.jsx",
    taintedPath: ["content", "html"],
  };
  const report = buildReport("/project", new Map(), [], [], { size: 0, edgeCount: 0 }, [], [finding], {
    diagnostics: [{ code: "EXAMPLE" }],
  });
  const sarif = formatSarifReport(report);
  assert.deepEqual(sarif.runs[0].results[0].properties.componentPath, finding.componentPath);
  assert.deepEqual(sarif.runs[0].results[0].properties.propagationPath, finding.propagationPath);
  assert.deepEqual(sarif.runs[0].properties.diagnostics, [{ code: "EXAMPLE" }]);
});
