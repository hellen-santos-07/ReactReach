const ASTWalker = require("../ast/ASTWalker");
const { collectReferencedIdentifiers, collectReferencedBindings } = require("./helpers");
const { selectSinkRules } = require("./registry");

/**
 * Specialised AST walker and Plugin Host for sink-rule strategies.
 */
class SinkWalker extends ASTWalker {
  constructor(config = {}, options = {}) {
    super(options);
    this.config = config;
    this.selectedRules = config.rules || selectSinkRules(config, config.sinkRules || null);
    this.rulesByNodeType = new Map();
    for (const rule of this.selectedRules) {
      if (!this.rulesByNodeType.has(rule.nodeType)) this.rulesByNodeType.set(rule.nodeType, []);
      this.rulesByNodeType.get(rule.nodeType).push(rule);
    }
  }

  createFileContext() {
    return { bindingByNode: new WeakMap() };
  }

  createPreVisitors(_file, fileContext) {
    return {
      Identifier(path) {
        fileContext.bindingByNode.set(path.node, path.scope.getBinding(path.node.name) || null);
      },
    };
  }

  createVisitors(file, fileContext, _context, sinks) {
    const visitors = {};
    for (const [nodeType, rules] of this.rulesByNodeType) {
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
            referencedBindings: [...collectReferencedBindings(valueNode, fileContext.bindingByNode)],
          });
        }
      };
    }
    return visitors;
  }
}

function extractSinks(parsedFiles, config = {}) {
  return new SinkWalker(config).walk(parsedFiles);
}

module.exports = extractSinks;
module.exports.SinkWalker = SinkWalker;
