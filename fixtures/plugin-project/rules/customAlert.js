module.exports = {
  id: "custom-alert",
  name: "Custom alert call",
  category: "test-plugin",
  defaultPriority: 65,
  confidence: 90,
  nodeType: "CallExpression",
  match: (path) => path.node.callee?.type === "Identifier" && path.node.callee.name === "alert" && path.node.arguments.length > 0,
  getValueNode: (path) => path.node.arguments[0],
  getSinkType: () => "custom.alert",
};
