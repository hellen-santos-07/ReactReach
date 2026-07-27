const traverse = require("@babel/traverse").default;
const { collectReferencedIdentifiers } = require("./helpers");
const { selectSinkRules } = require("./registry");

function extractSinks(parsedFiles, config = {}) {
  const sinks = [];
  const selectedRules = config.rules || selectSinkRules(config);
  const rulesByNodeType = new Map();
  for (const rule of selectedRules) {
    if (!rulesByNodeType.has(rule.nodeType)) rulesByNodeType.set(rule.nodeType, []);
    rulesByNodeType.get(rule.nodeType).push(rule);
  }

  for (const file of parsedFiles) {
    const visitors = {};
    for (const [nodeType, rules] of rulesByNodeType) {
      visitors[nodeType] = (astPath) => {
        for (const rule of rules) {
          if (!rule.match(astPath, { file })) continue;
          const valueNode = rule.getValueNode(astPath, { file });
          sinks.push({
            sinkType: rule.getSinkType?.(astPath, { file }) ?? rule.name,
            ruleId: rule.id,
            category: rule.category,
            priority: rule.priority ?? rule.defaultPriority,
            confidence: rule.confidence,
            filePath: file.filePath,
            loc: astPath.node.loc,
            identifiers: [...collectReferencedIdentifiers(valueNode)],
          });
        }
      };
    }
    traverse(file.ast, visitors);
  }
  return sinks;
}

module.exports = extractSinks;
