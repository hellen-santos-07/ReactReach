const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const { buildReport } = require("../src/report/generateReport");

const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "schemas", "reactreach-report.schema.json"), "utf8"));
const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
const validate = ajv.compile(schema);

test("ReactReach JSON output validates against the versioned report schema", () => {
  const timings = {
    auditMs: 1,
    parseMs: 2,
    dependenciesMs: 3,
    componentsMs: 4,
    sinksMs: 5,
    graphMs: 6,
    reachabilityMs: 7,
    staticAnalysisMs: 27,
    reportMs: 1,
    totalMs: 29,
  };
  const finding = {
    packageName: "marked",
    filePath: "/project/src/App.jsx",
    auditSeverity: "high",
    reasonCode: "DIRECT_SINK_FLOW",
    reason: "Direct flow",
    reachability: "CRITICAL",
    component: "App",
    sinkType: "dangerouslySetInnerHTML",
    taintedPath: ["marked"],
  };
  const report = buildReport(
    "/project",
    new Map([["marked", { name: "marked", severity: "high" }]]),
    [{ filePath: finding.filePath }],
    [],
    { size: 0, edgeCount: 0 },
    [],
    [finding],
    { scannedAt: "2026-08-13T12:00:00.000Z", timings },
  );
  assert.equal(validate(report), true, JSON.stringify(validate.errors, null, 2));
});

test("report schema rejects unknown reachability levels", () => {
  const invalid = {
    projectPath: "/project",
    scannedAt: "2026-08-13T12:00:00.000Z",
    configuration: {},
    diagnostics: [],
    timings: {},
    summary: { vulnerablePackages: 0, sourceFiles: 0, components: 0, cogNodes: 0, cogEdges: 0, sinks: 0, findings: 1 },
    packages: [],
    analyzedFiles: [],
    findings: [{ packageName: "pkg", filePath: "/file", auditSeverity: "high", reasonCode: "X", reason: "X", reachability: "UNKNOWN" }],
  };
  assert.equal(validate(invalid), false);
  assert.ok(validate.errors.some((error) => error.instancePath.endsWith("/reachability")));
});
