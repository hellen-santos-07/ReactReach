const groups = [
  require("./rules/jsx"),
  require("./rules/dom"),
  require("./rules/navigation"),
  require("./rules/codeExecution"),
];

const REQUIRED_FIELDS = ["id", "name", "category", "defaultPriority", "confidence", "nodeType", "match", "getValueNode"];

function validateRule(rule) {
  const missing = REQUIRED_FIELDS.filter((field) => rule[field] === undefined);
  if (missing.length) throw new Error(`Invalid sink rule: missing ${missing.join(", ")}`);
  if (typeof rule.match !== "function" || typeof rule.getValueNode !== "function") throw new Error(`Invalid sink rule ${rule.id}: match and getValueNode must be functions`);
  if (!Number.isFinite(rule.defaultPriority) || rule.defaultPriority < 0 || rule.defaultPriority > 100) throw new Error(`Invalid sink rule ${rule.id}: defaultPriority must be between 0 and 100`);
  if (!Number.isFinite(rule.confidence) || rule.confidence < 0 || rule.confidence > 100) throw new Error(`Invalid sink rule ${rule.id}: confidence must be between 0 and 100`);
  return rule;
}

const rules = groups.flat().map(validateRule);
const ids = new Set();
for (const rule of rules) {
  if (ids.has(rule.id)) throw new Error(`Duplicate sink rule id: ${rule.id}`);
  ids.add(rule.id);
}

function listSinkRules() {
  return rules.map(({ match, getValueNode, getSinkType, ...metadata }) => ({ ...metadata }));
}

function selectSinkRules(config = {}) {
  const included = config.sinks ? new Set(config.sinks) : null;
  const excluded = new Set(config.excludeSinks || []);
  return rules
    .filter((rule) => (!included || included.has(rule.id)) && !excluded.has(rule.id))
    .map((rule) => ({ ...rule, priority: config.sinkPriorities?.[rule.id] ?? rule.defaultPriority }))
    .filter((rule) => rule.priority >= (config.minSinkPriority ?? 0));
}

module.exports = { rules, listSinkRules, selectSinkRules, validateRule };
