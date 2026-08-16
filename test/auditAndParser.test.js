const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runAudit, extractVulnerablePackages, parseAuditOutput } = require("../src/dependency/runAudit");
const { getSourceFiles, parseFile, parseProject } = require("../src/component/parseProject");

test("audit extraction preserves npm vulnerability metadata", () => {
  const vulnerable = extractVulnerablePackages({
    vulnerabilities: {
      marked: {
        severity: "high",
        isDirect: true,
        via: [{ source: 123, title: "XSS" }],
        effects: [],
        range: "<4.0.10",
        nodes: ["node_modules/marked"],
        fixAvailable: { name: "marked", version: "4.0.10" },
      },
    },
  });
  assert.deepEqual(vulnerable.get("marked"), {
    name: "marked",
    severity: "high",
    isDirect: true,
    via: [{ source: 123, title: "XSS" }],
    effects: [],
    range: "<4.0.10",
    nodes: ["node_modules/marked"],
    fixAvailable: { name: "marked", version: "4.0.10" },
  });
});

test("runAudit accepts npm's non-zero vulnerability result", () => {
  const stdout = JSON.stringify({ vulnerabilities: { marked: { severity: "high", isDirect: true } } });
  const auditExecutor = () => {
    const error = new Error("npm audit found vulnerabilities");
    error.stdout = stdout;
    throw error;
  };
  const result = runAudit("/project", {}, { auditExecutor, npmCommand: "npm" });
  assert.equal(result.get("marked").severity, "high");
});

test("audit failures and malformed output produce controlled errors", () => {
  assert.throws(
    () => parseAuditOutput(JSON.stringify({ error: { code: "ENOLOCK", summary: "A lockfile is required" } })),
    (error) => error.code === "AUDIT_FAILED" && /lockfile/.test(error.message),
  );
  assert.throws(
    () => parseAuditOutput("not-json"),
    (error) => error.code === "AUDIT_FAILED" && /invalid JSON/.test(error.message),
  );
  assert.throws(
    () => parseAuditOutput("{}"),
    (error) => error.code === "AUDIT_FAILED" && /vulnerabilities object/.test(error.message),
  );
  assert.throws(
    () => runAudit("/project", {}, { auditExecutor: () => { throw new Error("npm missing"); }, npmCommand: "npm" }),
    (error) => error.code === "AUDIT_FAILED" && /Unable to execute npm audit/.test(error.message),
  );
});

test("parser discovers JS, JSX, TS and TSX in deterministic order", (context) => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), "reactreach-parser-"));
  context.after(() => fs.rmSync(project, { recursive: true, force: true }));
  const source = path.join(project, "src");
  fs.mkdirSync(source);
  const fixtures = {
    "d.tsx": "export const D = (): JSX.Element => <div />;",
    "b.jsx": "export const B = () => <div />;",
    "c.ts": "export const value: string = 'safe';",
    "a.js": "export const value = 'safe';",
  };
  for (const [name, contents] of Object.entries(fixtures)) fs.writeFileSync(path.join(source, name), contents, "utf8");

  const files = getSourceFiles(project);
  assert.deepEqual(files.map((file) => path.basename(file)), ["a.js", "b.jsx", "c.ts", "d.tsx"]);
  const parsed = parseProject(project);
  assert.equal(parsed.length, 4);
  assert.ok(parsed.every((file) => file.ast.type === "File" && file.ast.loc));
});

test("parse errors identify the source file", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "reactreach-invalid-source-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "Broken.jsx");
  fs.writeFileSync(filePath, "export const Broken = <div>", "utf8");
  assert.throws(
    () => parseFile(filePath),
    (error) => error.code === "PARSE_FAILED" && error.filePath === filePath && error.message.includes(filePath),
  );
});
