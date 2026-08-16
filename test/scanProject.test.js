const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { scanProject } = require("../src/scanProject");

const fixture = path.join(__dirname, "fixtures", "basic-project");

test("scanProject orchestrates injected stages and produces a deterministic report", async () => {
  const calls = [];
  const vulnerablePackages = new Map([["pkg", { name: "pkg", severity: "high" }]]);
  const parsedFiles = [{ filePath: path.join(fixture, "src", "App.jsx") }];
  const components = [{ name: "App", filePath: parsedFiles[0].filePath }];
  const graph = { size: 1, edgeCount: 0, roots: () => [{}] };
  const findings = [{ packageName: "pkg", reachability: "NONE" }];
  const dependencies = {
    auditRunner: async () => vulnerablePackages,
    projectParser: async () => parsedFiles,
    dependencyExtractor: async () => [{ packageName: "pkg" }],
    componentExtractor: async () => components,
    sinkExtractor: async () => [],
    graphBuilder: async () => graph,
    reachabilityAnalyzer: async () => findings,
    logger: (event) => calls.push(event.stage),
    clock: () => new Date("2026-01-02T03:04:05.000Z"),
    now: (() => {
      let value = 0;
      return () => value++ * 5;
    })(),
  };
  const result = await scanProject(fixture, {}, dependencies);
  assert.equal(result.report.scannedAt, "2026-01-02T03:04:05.000Z");
  assert.equal(result.report.summary.findings, 1);
  assert.deepEqual(result.diagnostics, []);
  assert.deepEqual(result.report.diagnostics, []);
  assert.equal(result.timings.auditMs, 5);
  assert.equal(result.timings.staticAnalysisMs, 30);
  assert.equal(result.timings.reportMs, 5);
  assert.equal(result.timings.totalMs, 85);
  assert.strictEqual(result.report.timings, result.timings);
  assert.deepEqual(calls, ["audit", "parse", "dependencies", "components", "sinks", "graph", "reachability"]);
});

test("scanProject rejects a missing project without terminating the process", async () => {
  await assert.rejects(() => scanProject(path.join(fixture, "missing")), { code: "PROJECT_NOT_FOUND" });
});
