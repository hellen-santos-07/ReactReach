const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG = Object.freeze({
  sinks: null,
  excludeSinks: [],
  minSinkPriority: 0,
  sinkPriorities: {},
  sort: "reachability",
});

function mergeConfig(fileConfig = {}, cliConfig = {}) {
  const cliValues = Object.fromEntries(Object.entries(cliConfig).filter(([, value]) => value !== undefined));
  return {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    ...cliValues,
    sinkPriorities: {
      ...DEFAULT_CONFIG.sinkPriorities,
      ...(fileConfig.sinkPriorities || {}),
      ...(cliValues.sinkPriorities || {}),
    },
  };
}

function validateStringArray(value, field, errors) {
  if (value !== null && !Array.isArray(value)) errors.push(`${field} must be an array of sink ids`);
  else if (Array.isArray(value) && value.some((item) => typeof item !== "string" || !item.trim())) errors.push(`${field} must contain non-empty sink ids`);
}

function validateConfig(config, knownSinkIds) {
  const errors = [];
  validateStringArray(config.sinks, "sinks", errors);
  validateStringArray(config.excludeSinks, "excludeSinks", errors);
  const known = new Set(knownSinkIds);
  for (const id of [...(config.sinks || []), ...(config.excludeSinks || [])]) if (!known.has(id)) errors.push(`Unknown sink id: ${id}`);
  const excluded = new Set(config.excludeSinks || []);
  const overlap = (config.sinks || []).filter((id) => excluded.has(id));
  if (overlap.length) errors.push(`Sink ids cannot be both included and excluded: ${overlap.join(", ")}`);
  if (!Number.isFinite(config.minSinkPriority) || config.minSinkPriority < 0 || config.minSinkPriority > 100) errors.push("minSinkPriority must be between 0 and 100");
  if (!["reachability", "sink-priority"].includes(config.sort)) errors.push("sort must be reachability or sink-priority");
  if (!config.sinkPriorities || typeof config.sinkPriorities !== "object" || Array.isArray(config.sinkPriorities)) errors.push("sinkPriorities must be an object");
  else {
    for (const [id, priority] of Object.entries(config.sinkPriorities)) {
      if (!known.has(id)) errors.push(`Unknown sink priority id: ${id}`);
      if (!Number.isFinite(priority) || priority < 0 || priority > 100) errors.push(`Priority for ${id} must be between 0 and 100`);
    }
  }
  if (errors.length) {
    const error = new Error(`Invalid configuration:\n- ${errors.join("\n- ")}`);
    error.code = "INVALID_CONFIG";
    throw error;
  }
  return config;
}

function loadConfig(projectPath, options = {}, knownSinkIds = []) {
  const configPath = options.configPath
    ? path.resolve(options.configPath)
    : path.join(projectPath, "reactreach.config.json");
  let fileConfig = {};
  if (fs.existsSync(configPath)) {
    try {
      fileConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
    } catch (cause) {
      const error = new Error(`Unable to read configuration ${configPath}: ${cause.message}`);
      error.code = "INVALID_CONFIG";
      throw error;
    }
  } else if (options.configPath) {
    const error = new Error(`Configuration file not found: ${configPath}`);
    error.code = "INVALID_CONFIG";
    throw error;
  }
  const config = validateConfig(mergeConfig(fileConfig, options.cliConfig), knownSinkIds);
  return { config, configPath: fs.existsSync(configPath) ? configPath : null };
}

module.exports = { DEFAULT_CONFIG, mergeConfig, validateConfig, loadConfig };
