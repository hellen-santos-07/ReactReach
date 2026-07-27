const t = require("@babel/types");

module.exports = [
  {
    id: "eval",
    name: "Global eval",
    category: "code-execution",
    defaultPriority: 100,
    confidence: 100,
    nodeType: "CallExpression",
    match: (path) => t.isIdentifier(path.node.callee, { name: "eval" }) && path.node.arguments.length > 0 && !path.scope.getBinding("eval"),
    getValueNode: (path) => path.node.arguments[0],
    getSinkType: () => "eval",
  },
  {
    id: "new-function",
    name: "Function constructor",
    category: "code-execution",
    defaultPriority: 100,
    confidence: 100,
    nodeType: "NewExpression",
    match: (path) => t.isIdentifier(path.node.callee, { name: "Function" }) && path.node.arguments.length > 0 && !path.scope.getBinding("Function"),
    getValueNode: (path) => path.node.arguments.at(-1),
    getSinkType: () => "new Function",
  },
];
