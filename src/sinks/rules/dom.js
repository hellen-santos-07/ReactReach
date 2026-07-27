const { isNamedMember, isRefCurrent } = require("../helpers");

module.exports = [
  {
    id: "dom-html",
    name: "React ref HTML assignment",
    category: "html-injection",
    defaultPriority: 95,
    confidence: 95,
    nodeType: "AssignmentExpression",
    match: (path) => (isNamedMember(path.node.left, "innerHTML") || isNamedMember(path.node.left, "outerHTML")) && isRefCurrent(path.node.left.object),
    getValueNode: (path) => path.node.right,
    getSinkType(path) {
      const property = path.node.left.computed ? path.node.left.property.value : path.node.left.property.name;
      return `ref.${property}`;
    },
  },
  {
    id: "insert-adjacent-html",
    name: "React ref insertAdjacentHTML",
    category: "html-injection",
    defaultPriority: 95,
    confidence: 95,
    nodeType: "CallExpression",
    match: (path) => isNamedMember(path.node.callee, "insertAdjacentHTML") && isRefCurrent(path.node.callee.object) && path.node.arguments.length >= 2,
    getValueNode: (path) => path.node.arguments[1],
    getSinkType: () => "ref.insertAdjacentHTML",
  },
];
