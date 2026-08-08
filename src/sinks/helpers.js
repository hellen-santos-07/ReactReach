const t = require("@babel/types");

function collectReferencedIdentifiers(node, identifiers = new Set(), parent = null, parentKey = null) {
  if (!node) return identifiers;
  if (t.isIdentifier(node)) {
    const memberProperty = t.isMemberExpression(parent) && parentKey === "property" && !parent.computed;
    const objectKey = t.isObjectProperty(parent) && parentKey === "key" && !parent.computed && !parent.shorthand;
    if (!memberProperty && !objectKey) identifiers.add(node.name);
    return identifiers;
  }
  for (const key of t.VISITOR_KEYS[node.type] || []) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) if (t.isNode(item)) collectReferencedIdentifiers(item, identifiers, node, key);
    } else if (t.isNode(child)) {
      collectReferencedIdentifiers(child, identifiers, node, key);
    }
  }
  return identifiers;
}

function collectReferencedBindings(node, bindingByNode, bindings = new Set(), parent = null, parentKey = null) {
  if (!node) return bindings;
  if (t.isIdentifier(node)) {
    const memberProperty = t.isMemberExpression(parent) && parentKey === "property" && !parent.computed;
    const objectKey = t.isObjectProperty(parent) && parentKey === "key" && !parent.computed && !parent.shorthand;
    const binding = bindingByNode.get(node);
    if (!memberProperty && !objectKey && binding) bindings.add(binding);
    return bindings;
  }
  for (const key of t.VISITOR_KEYS[node.type] || []) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) if (t.isNode(item)) collectReferencedBindings(item, bindingByNode, bindings, node, key);
    } else if (t.isNode(child)) {
      collectReferencedBindings(child, bindingByNode, bindings, node, key);
    }
  }
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
