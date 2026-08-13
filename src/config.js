const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG = Object.freeze({
  sinks: null,
  excludeSinks: [],
  minSinkPriority: 0,
  sinkPriorities: {},
  sort: "reachability",
  maxTaintIterations: 100,
  includeDefaultSinks: true,
  sinkModules: [],
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

function validateStringArray(value, field, errors, itemDescription = "sink ids") {
  if (value !== null && !Array.isArray(value)) errors.push(`${field} must be an array of ${itemDescription}`);
  else if (Array.isArray(value) && value.some((item) => typeof item !== "string" || !item.trim())) errors.push(`${field} must contain non-empty ${itemDescription}`);
}

function validateConfig(config, knownSinkIds = null) {
  const errors = [];
  validateStringArray(config.sinks, "sinks", errors);
  validateStringArray(config.excludeSinks, "excludeSinks", errors);
  validateStringArray(config.sinkModules, "sinkModules", errors, "module paths");
  if (typeof config.includeDefaultSinks !== "boolean") errors.push("includeDefaultSinks must be boolean");
  if (Array.isArray(config.sinkModules)) {
    for (const moduleEntry of config.sinkModules) {
      if (typeof moduleEntry === "string" && (path.isAbsolute(moduleEntry) || /^[a-z][a-z0-9+.-]*:/i.test(moduleEntry))) {
        errors.push(`sinkModules entries must be relative local paths: ${moduleEntry}`);
      }
    }
  }
  const known = knownSinkIds === null ? null : new Set(knownSinkIds);
  if (known) {
    for (const id of [...(config.sinks || []), ...(config.excludeSinks || [])]) if (!known.has(id)) errors.push(`Unknown sink id: ${id}`);
  }
  const excluded = new Set(config.excludeSinks || []);
  const overlap = (config.sinks || []).filter((id) => excluded.has(id));
  if (overlap.length) errors.push(`Sink ids cannot be both included and excluded: ${overlap.join(", ")}`);
  if (!Number.isFinite(config.minSinkPriority) || config.minSinkPriority < 0 || config.minSinkPriority > 100) errors.push("minSinkPriority must be between 0 and 100");
  if (!["reachability", "sink-priority"].includes(config.sort)) errors.push("sort must be reachability or sink-priority");
  if (!Number.isInteger(config.maxTaintIterations) || config.maxTaintIterations < 1 || config.maxTaintIterations > 10000) errors.push("maxTaintIterations must be an integer between 1 and 10000");
  if (!config.sinkPriorities || typeof config.sinkPriorities !== "object" || Array.isArray(config.sinkPriorities)) errors.push("sinkPriorities must be an object");
  else {
    for (const [id, priority] of Object.entries(config.sinkPriorities)) {
      if (known && !known.has(id)) errors.push(`Unknown sink priority id: ${id}`);
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

function loadConfig(projectPath, options = {}, knownSinkIds = null) {
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
  const configExists = fs.existsSync(configPath);
  const config = validateConfig(mergeConfig(fileConfig, options.cliConfig), knownSinkIds);
  Object.defineProperty(config, "sinkModuleBase", {
    value: configExists ? path.dirname(configPath) : projectPath,
    enumerable: false,
  });
  return { config, configPath: configExists ? configPath : null };
}

module.exports = { DEFAULT_CONFIG, mergeConfig, validateConfig, loadConfig };
