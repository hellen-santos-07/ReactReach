const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { DEFAULT_CONFIG, mergeConfig, validateConfig, loadConfig } = require("../src/config");
const { listSinkRules, loadSinkRules } = require("../src/sinks/registry");

const ids = listSinkRules().map((rule) => rule.id);

test("configuration precedence is CLI, file, then defaults", () => {
  const config = mergeConfig(
    { minSinkPriority: 20, sort: "sink-priority", sinkPriorities: { eval: 60 } },
    { minSinkPriority: 80, sinkPriorities: { eval: 90 } },
  );
  assert.equal(config.minSinkPriority, 80);
  assert.equal(config.sort, "sink-priority");
  assert.equal(config.sinkPriorities.eval, 90);
  assert.deepEqual(config.excludeSinks, DEFAULT_CONFIG.excludeSinks);
});

test("loadConfig automatically reads reactreach.config.json", () => {
  const project = path.join(__dirname, "fixtures", "configured-project");
  const result = loadConfig(project, {}, ids);
  assert.equal(result.configPath, path.join(project, "reactreach.config.json"));
  assert.deepEqual(result.config.sinks, ["eval", "location"]);
  assert.equal(result.config.sinkPriorities.eval, 75);
});

test("CLI configuration overrides file configuration", () => {
  const project = path.join(__dirname, "fixtures", "configured-project");
  const { config } = loadConfig(project, { cliConfig: { sinks: ["inner-html"], minSinkPriority: 95 } }, ids);
  assert.deepEqual(config.sinks, ["inner-html"]);
  assert.equal(config.minSinkPriority, 95);
});

test("configuration validation reports all actionable errors", () => {
  assert.throws(
    () => validateConfig({ ...DEFAULT_CONFIG, sinks: ["missing"], minSinkPriority: 101, sort: "other", sinkPriorities: { eval: -1 } }, ids),
    (error) => error.code === "INVALID_CONFIG" && /Unknown sink id/.test(error.message) && /minSinkPriority/.test(error.message) && /sort/.test(error.message),
  );
});

test("configuration rejects the same sink in include and exclude lists", () => {
  assert.throws(
    () => validateConfig({ ...DEFAULT_CONFIG, sinks: ["eval"], excludeSinks: ["eval"] }, ids),
    /both included and excluded/,
  );
});

test("configuration validates the taint iteration limit", () => {
  assert.equal(validateConfig({ ...DEFAULT_CONFIG, maxTaintIterations: 250 }, ids).maxTaintIterations, 250);
  assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, maxTaintIterations: 0 }, ids), /maxTaintIterations/);
});

test("configuration exposes project-local sink modules before validating custom rule ids", () => {
  const project = path.join(__dirname, "fixtures", "plugin-project");
  const loaded = loadConfig(project);
  assert.deepEqual(loaded.config.sinkModules, ["./rules/customAlert.js"]);
  assert.equal(loaded.config.sinkModuleBase, project);
  assert.equal(Object.keys(loaded.config).includes("sinkModuleBase"), false);
  const customIds = loadSinkRules({
    modules: loaded.config.sinkModules,
    basePath: loaded.config.sinkModuleBase,
    includeDefault: loaded.config.includeDefaultSinks,
  }).map((rule) => rule.id);
  assert.ok(customIds.includes("custom-alert"));
  assert.equal(validateConfig(loaded.config, customIds).sinks[0], "custom-alert");
});

test("configuration rejects invalid sink module settings", () => {
  assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, sinkModules: 42 }, ids), /sinkModules/);
  assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, includeDefaultSinks: "yes" }, ids), /includeDefaultSinks/);
  assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, sinkModules: [path.resolve("rule.js")] }, ids), /relative local paths/);
});

test("configuration reports malformed sink selections without leaking a TypeError", () => {
  assert.throws(
    () => validateConfig({ ...DEFAULT_CONFIG, sinks: 42, excludeSinks: 42 }, ids),
    (error) => error.code === "INVALID_CONFIG" && /sinks must be an array/.test(error.message),
  );
});
