const t = require("@babel/types");
const { isNamedMember } = require("../helpers");

function isGlobalIdentifier(path, node, name) {
  return t.isIdentifier(node, { name }) && !path.scope.getBinding(name);
}

function isGlobalLocation(path, node) {
  if (isGlobalIdentifier(path, node, "location")) return true;
  return isNamedMember(node, "location") && isGlobalIdentifier(path, node.object, "window");
}

module.exports = [{
  id: "location",
  name: "Location assignment",
  category: "url-navigation",
  defaultPriority: 80,
  confidence: 90,
  nodeType: "AssignmentExpression",
  match(path) {
    const left = path.node.left;
    return isGlobalLocation(path, left) ||
      ((isNamedMember(left, "href") || isNamedMember(left, "pathname")) && isGlobalLocation(path, left.object));
  },
  getValueNode: (path) => path.node.right,
  getSinkType: () => "location-assign",
}];
