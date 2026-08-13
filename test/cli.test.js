const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createProgram } = require("../src/cli");

const root = path.resolve(__dirname, "..");
const fixture = path.join(__dirname, "fixtures", "basic-project");

test("CLI passes sink selections to the scan pipeline", async () => {
  let receivedConfig;
  const scanner = async (_project, config) => {
    receivedConfig = config;
    return { findings: [], report: {} };
  };
  const originalLog = console.log;
  console.log = () => {};
  try {
    await createProgram({ scanProject: scanner }).parseAsync([
      "node", "reactreach", "scan", fixture,
      "--sinks", "eval,inner-html",
      "--exclude-sinks", "location",
      "--min-sink-priority", "90",
      "--sort", "sink-priority",
    ]);
  } finally {
    console.log = originalLog;
  }
  assert.deepEqual(receivedConfig.sinks, ["eval", "inner-html"]);
  assert.deepEqual(receivedConfig.excludeSinks, ["location"]);
  assert.equal(receivedConfig.minSinkPriority, 90);
  assert.equal(receivedConfig.sort, "sink-priority");
});

test("list-sinks is available without scanning a project", () => {
  const result = spawnSync(process.execPath, ["src/cli.js", "list-sinks", "--json"], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const rules = JSON.parse(result.stdout);
  assert.ok(rules.some((rule) => rule.id === "eval"));
});

test("invalid sink ids return configuration exit code 2", () => {
  const result = spawnSync(process.execPath, ["src/cli.js", "scan", fixture, "--sinks", "missing"], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown sink id: missing/);
});

test("CLI loads project-local sink plugins before invoking the scan pipeline", async () => {
  const pluginProject = path.join(__dirname, "..", "fixtures", "plugin-project");
  let receivedConfig;
  const originalLog = console.log;
  console.log = () => {};
  try {
    await createProgram({
      scanProject: async (_project, config) => {
        receivedConfig = config;
        return { findings: [], report: {} };
      },
    }).parseAsync(["node", "reactreach", "scan", pluginProject]);
  } finally {
    console.log = originalLog;
  }
  assert.deepEqual(receivedConfig.sinks, ["custom-alert"]);
  assert.ok(receivedConfig.sinkRules.some((rule) => rule.id === "custom-alert"));
  assert.equal(Object.keys(receivedConfig).includes("sinkRules"), false);
});

test("invalid local sink modules return configuration exit code 2", () => {
  const invalidProject = path.join(__dirname, "..", "fixtures", "invalid-plugin-project");
  const result = spawnSync(process.execPath, ["src/cli.js", "scan", invalidProject], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unable to resolve sink module/);
});
