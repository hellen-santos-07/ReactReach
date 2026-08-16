const t = require("@babel/types");

function isNonReferenceIdentifier(parent, parentKey) {
  const memberProperty = t.isMemberExpression(parent) && parentKey === "property" && !parent.computed;
  const objectKey = t.isObjectProperty(parent) && parentKey === "key" && !parent.computed && !parent.shorthand;
  return memberProperty || objectKey;
}

function visitChildNodes(node, visitor) {
  for (const key of t.VISITOR_KEYS[node.type] || []) {
    const children = Array.isArray(node[key]) ? node[key] : [node[key]];
    for (const child of children) if (t.isNode(child)) visitor(child, node, key);
  }
}

function visitReferencedIdentifiers(node, visitor, parent = null, parentKey = null) {
  if (!node) return;
  if (t.isIdentifier(node)) {
    if (!isNonReferenceIdentifier(parent, parentKey)) visitor(node);
    return;
  }
  visitChildNodes(node, (child, owner, key) => visitReferencedIdentifiers(child, visitor, owner, key));
}

function collectReferencedIdentifiers(node, identifiers = new Set()) {
  visitReferencedIdentifiers(node, (identifier) => identifiers.add(identifier.name));
  return identifiers;
}

function collectReferencedBindings(node, bindingByNode, bindings = new Set()) {
  visitReferencedIdentifiers(node, (identifier) => {
    const binding = bindingByNode.get(identifier);
    if (binding) bindings.add(binding);
  });
  return bindings;
}

function isNamedMember(node, name) {
  return t.isMemberExpression(node) && (
    (!node.computed && t.isIdentifier(node.property, { name })) ||
    (node.computed && t.isStringLiteral(node.property, { value: name }))
  );
}

function isRefCurrent(node) {
  return isNamedMember(node, "current") && t.isIdentifier(node.object);
}

module.exports = { collectReferencedIdentifiers, collectReferencedBindings, isNamedMember, isRefCurrent };
