const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const AjvDraft04 = require("ajv-draft-04");
const { buildReport, formatSarifReport } = require("../src/report/generateReport");

const OFFICIAL_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

function createReferenceReport() {
  const finding = {
    packageName: "marked",
    filePath: path.resolve("reference-project", "src", "App.jsx"),
    auditSeverity: "high",
    reasonCode: "DIRECT_SINK_FLOW",
    reason: "The vulnerable dependency flows directly into a sink",
    reachability: "CRITICAL",
    component: "App",
    sinkType: "dangerouslySetInnerHTML",
    sinkRuleId: "inner-html",
    sinkCategory: "html-injection",
    sinkPriority: 100,
    confidence: 100,
    taintedPath: ["marked"],
    sinkLoc: { start: { line: 3, column: 2 } },
  };
  return buildReport(
    path.resolve("reference-project"),
    new Map([["marked", { name: "marked", severity: "high", isDirect: true }]]),
    [{ filePath: finding.filePath }],
    [{ name: "App" }],
    { size: 1, edgeCount: 0 },
    [{ ruleId: "inner-html" }],
    [finding],
    { scannedAt: "2026-08-13T12:00:00.000Z", timings: {} },
  );
}

function assertValid(validate, value, label) {
  if (validate(value)) return;
  throw new Error(`${label} schema validation failed:\n${JSON.stringify(validate.errors, null, 2)}`);
}

async function main() {
  const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
  const reportSchema = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "schemas", "reactreach-report.schema.json"), "utf8"));
  const report = createReferenceReport();
  assertValid(ajv.compile(reportSchema), report, "ReactReach report");

  const response = await fetch(OFFICIAL_SARIF_SCHEMA);
  if (!response.ok) throw new Error(`Unable to obtain official SARIF schema: HTTP ${response.status}`);
  const sarifSchema = await response.json();
  const sarifAjv = new AjvDraft04({ allErrors: true, strict: false, validateFormats: false });
  assertValid(sarifAjv.compile(sarifSchema), formatSarifReport(report), "SARIF 2.1.0");
  console.log("ReactReach report schema: PASS");
  console.log("Official SARIF 2.1.0 schema: PASS");
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
