const path = require("path");
const t = require("@babel/types");

const REQUIRED_FIELDS = ["id", "name", "category", "defaultPriority", "confidence", "nodeType", "match", "getValueNode"];

/**
 * @typedef {Object} ISinkRule
 * @property {string} id
 * @property {string} name
 * @property {string} category
 * @property {number} defaultPriority
 * @property {number} confidence
 * @property {string} nodeType
 * @property {(path: object, context: object) => boolean} match
 * @property {(path: object, context: object) => object} getValueNode
 * @property {(path: object, context: object) => string} [getSinkType]
 */

function invalidConfig(message, cause) {
  const error = new Error(message);
  error.code = "INVALID_CONFIG";
  if (cause) error.cause = cause;
  return error;
}

function assertRuleObject(rule) {
  if (!rule || typeof rule !== "object" || Array.isArray(rule)) throw invalidConfig("Invalid sink rule: expected an object");
}

function assertRequiredFields(rule) {
  const missing = REQUIRED_FIELDS.filter((field) => rule[field] === undefined);
  if (missing.length) throw invalidConfig(`Invalid sink rule: missing ${missing.join(", ")}`);
}

function assertNonEmptyField(rule, field) {
  if (typeof rule[field] !== "string" || !rule[field].trim()) {
    throw invalidConfig(`Invalid sink rule ${rule.id}: ${field} must be a non-empty string`);
  }
}

function assertRuleIdentity(rule) {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(rule.id)) throw invalidConfig(`Invalid sink rule id: ${rule.id}`);
  for (const field of ["name", "category", "nodeType"]) assertNonEmptyField(rule, field);
  if (!Object.prototype.hasOwnProperty.call(t.VISITOR_KEYS, rule.nodeType)) {
    throw invalidConfig(`Invalid sink rule ${rule.id}: unsupported Babel nodeType ${rule.nodeType}`);
  }
}

function assertRuleFunctions(rule) {
  if (typeof rule.match !== "function" || typeof rule.getValueNode !== "function") throw invalidConfig(`Invalid sink rule ${rule.id}: match and getValueNode must be functions`);
  if (rule.getSinkType !== undefined && typeof rule.getSinkType !== "function") throw invalidConfig(`Invalid sink rule ${rule.id}: getSinkType must be a function`);
}

function assertPercentageField(rule, field) {
  const value = rule[field];
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw invalidConfig(`Invalid sink rule ${rule.id}: ${field} must be between 0 and 100`);
  }
}

function validateRule(rule) {
  assertRuleObject(rule);
  assertRequiredFields(rule);
  assertRuleIdentity(rule);
  assertRuleFunctions(rule);
  assertPercentageField(rule, "defaultPriority");
  assertPercentageField(rule, "confidence");
  return rule;
}

function resolveLocalModule(basePath, moduleEntry, source) {
  if (path.isAbsolute(moduleEntry) || /^[a-z][a-z0-9+.-]*:/i.test(moduleEntry)) {
    throw invalidConfig(`Invalid sink module ${moduleEntry}: only relative local paths are allowed`);
  }
  const candidate = path.resolve(basePath, moduleEntry);
  const relative = path.relative(basePath, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw invalidConfig(`Invalid sink module ${moduleEntry}: path escapes the configuration directory`);
  }
  try {
    return require.resolve(candidate);
  } catch (cause) {
    throw invalidConfig(`Unable to resolve sink module ${moduleEntry} from ${source}`, cause);
  }
}

function loadModuleRules(moduleEntries, basePath, source = basePath) {
  if (!Array.isArray(moduleEntries) || moduleEntries.some((entry) => typeof entry !== "string" || !entry.trim())) {
    throw invalidConfig("sinkModules must be an array of non-empty local paths");
  }
  const loaded = [];
  for (const moduleEntry of moduleEntries) {
    const modulePath = resolveLocalModule(basePath, moduleEntry, source);
    let exported;
    try {
      exported = require(modulePath);
    } catch (cause) {
      throw invalidConfig(`Unable to load sink module ${moduleEntry} from ${source}: ${cause.message}`, cause);
    }
    const moduleRules = Array.isArray(exported) ? exported : [exported];
    if (moduleRules.length === 0) throw invalidConfig(`Sink module ${moduleEntry} exports no rules`);
    loaded.push(...moduleRules.map(validateRule));
  }
  return loaded;
}

function assertUniqueRuleIds(availableRules) {
  const ids = new Set();
  for (const rule of availableRules) {
    if (ids.has(rule.id)) throw invalidConfig(`Duplicate sink rule id: ${rule.id}`);
    ids.add(rule.id);
  }
  return availableRules;
}

const builtInRules = assertUniqueRuleIds(require("./rules").map(validateRule));

function loadSinkRules(options = {}) {
  const availableRules = options.includeDefault === false ? [] : [...builtInRules];
  const modules = options.modules || [];
  if (modules.length) {
    const basePath = path.resolve(options.basePath || process.cwd());
    availableRules.push(...loadModuleRules(modules, basePath, "reactreach.config.json"));
  }
  return assertUniqueRuleIds(availableRules);
}

const rules = loadSinkRules();

function ruleMetadata(availableRules) {
  return availableRules.map(({ match, getValueNode, getSinkType, ...metadata }) => ({ ...metadata }));
}

function listSinkRules(options = {}) {
  const availableRules = options.rules || ((options.modules || options.includeDefault === false) ? loadSinkRules(options) : rules);
  return ruleMetadata(availableRules);
}

function selectSinkRules(config = {}, availableRules = null) {
  const sourceRules = availableRules || config.sinkRules || ((config.sinkModules?.length || config.includeDefaultSinks === false)
    ? loadSinkRules({
      modules: config.sinkModules,
      basePath: config.sinkModuleBase,
      includeDefault: config.includeDefaultSinks,
    })
    : rules);
  const included = config.sinks ? new Set(config.sinks) : null;
  const excluded = new Set(config.excludeSinks || []);
  return sourceRules
    .filter((rule) => (!included || included.has(rule.id)) && !excluded.has(rule.id))
    .map((rule) => ({ ...rule, priority: config.sinkPriorities?.[rule.id] ?? rule.defaultPriority }))
    .filter((rule) => rule.priority >= (config.minSinkPriority ?? 0));
}

module.exports = {
  builtInRules,
  rules,
  listSinkRules,
  selectSinkRules,
  validateRule,
  loadModuleRules,
  loadSinkRules,
};
