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

function validateModuleSettings(config, errors) {
  validateStringArray(config.sinkModules, "sinkModules", errors, "module paths");
  if (typeof config.includeDefaultSinks !== "boolean") errors.push("includeDefaultSinks must be boolean");
  for (const moduleEntry of Array.isArray(config.sinkModules) ? config.sinkModules : []) {
    if (typeof moduleEntry === "string" && (path.isAbsolute(moduleEntry) || /^[a-z][a-z0-9+.-]*:/i.test(moduleEntry))) {
      errors.push(`sinkModules entries must be relative local paths: ${moduleEntry}`);
    }
  }
}

function validateKnownSinkIds(config, known, errors) {
  if (!known) return;
  const selectedIds = [
    ...(Array.isArray(config.sinks) ? config.sinks : []),
    ...(Array.isArray(config.excludeSinks) ? config.excludeSinks : []),
  ];
  for (const id of selectedIds) if (!known.has(id)) errors.push(`Unknown sink id: ${id}`);
}

function validateSinkSelection(config, known, errors) {
  validateStringArray(config.sinks, "sinks", errors);
  validateStringArray(config.excludeSinks, "excludeSinks", errors);
  validateKnownSinkIds(config, known, errors);
  const excluded = new Set(Array.isArray(config.excludeSinks) ? config.excludeSinks : []);
  const overlap = (Array.isArray(config.sinks) ? config.sinks : []).filter((id) => excluded.has(id));
  if (overlap.length) errors.push(`Sink ids cannot be both included and excluded: ${overlap.join(", ")}`);
}

function isNumberBetween(value, minimum, maximum) {
  return Number.isFinite(value) && value >= minimum && value <= maximum;
}

function validateScalarSettings(config, errors) {
  if (!isNumberBetween(config.minSinkPriority, 0, 100)) errors.push("minSinkPriority must be between 0 and 100");
  if (!new Set(["reachability", "sink-priority"]).has(config.sort)) errors.push("sort must be reachability or sink-priority");
  const validIterationLimit = Number.isInteger(config.maxTaintIterations) && isNumberBetween(config.maxTaintIterations, 1, 10000);
  if (!validIterationLimit) errors.push("maxTaintIterations must be an integer between 1 and 10000");
}

function validateSinkPriorities(config, known, errors) {
  const priorities = config.sinkPriorities;
  if (!priorities || typeof priorities !== "object" || Array.isArray(priorities)) {
    errors.push("sinkPriorities must be an object");
    return;
  }
  for (const [id, priority] of Object.entries(priorities)) {
    if (known && !known.has(id)) errors.push(`Unknown sink priority id: ${id}`);
    if (!isNumberBetween(priority, 0, 100)) errors.push(`Priority for ${id} must be between 0 and 100`);
  }
}

function throwInvalidConfiguration(errors) {
  if (errors.length === 0) return;
  const error = new Error(`Invalid configuration:\n- ${errors.join("\n- ")}`);
  error.code = "INVALID_CONFIG";
  throw error;
}

function validateConfig(config, knownSinkIds = null) {
  const errors = [];
  const known = knownSinkIds === null ? null : new Set(knownSinkIds);
  validateSinkSelection(config, known, errors);
  validateModuleSettings(config, errors);
  validateScalarSettings(config, errors);
  validateSinkPriorities(config, known, errors);
  throwInvalidConfiguration(errors);
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
