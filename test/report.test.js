const test = require("node:test");
const assert = require("node:assert/strict");
const { buildReport, formatSarifReport } = require("../src/report/generateReport");

test("buildReport accepts an injected scan timestamp and preserves its schema", () => {
  const graph = { size: 1, edgeCount: 0 };
  const report = buildReport("/project", new Map(), [], [], graph, [], [], { scannedAt: "2026-01-02T03:04:05.000Z" });
  assert.equal(report.scannedAt, "2026-01-02T03:04:05.000Z");
  assert.deepEqual(report.summary, { vulnerablePackages: 0, sourceFiles: 0, components: 0, cogNodes: 1, cogEdges: 0, sinks: 0, findings: 0 });
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
  };
  const report = buildReport("/project", new Map(), [{ filePath: finding.filePath }], [], { size: 0, edgeCount: 0 }, [], [finding], { scannedAt: "2026-01-02T03:04:05.000Z" });
  const sarif = formatSarifReport(report);
  const result = sarif.runs[0].results[0];
  assert.equal(sarif.version, "2.1.0");
  assert.equal(result.level, "error");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 4);
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/App.jsx");
});
