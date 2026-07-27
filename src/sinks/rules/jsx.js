const t = require("@babel/types");

const URL_ATTRIBUTES = new Map([
  ["href", new Set(["a", "area"])],
  ["src", new Set(["iframe", "script", "embed", "object"])],
  ["action", new Set(["form"])],
  ["data", new Set(["object"])],
  ["formAction", new Set(["button", "input"])],
]);

module.exports = [
  {
    id: "inner-html",
    name: "dangerouslySetInnerHTML",
    category: "html-injection",
    defaultPriority: 100,
    confidence: 100,
    nodeType: "JSXAttribute",
    match: (path) => path.node.name?.name === "dangerouslySetInnerHTML",
    getValueNode: (path) => path.node.value,
    getSinkType: () => "dangerouslySetInnerHTML",
  },
  {
    id: "jsx-url",
    name: "Dynamic JSX URL attribute",
    category: "url-navigation",
    defaultPriority: 70,
    confidence: 80,
    nodeType: "JSXAttribute",
    match(path) {
      const attribute = path.node.name?.name;
      const opening = path.parentPath?.node;
      return URL_ATTRIBUTES.get(attribute)?.has(opening?.name?.name) === true &&
        t.isJSXOpeningElement(opening) && t.isJSXIdentifier(opening.name) &&
        t.isJSXExpressionContainer(path.node.value);
    },
    getValueNode: (path) => path.node.value.expression,
    getSinkType: (path) => `${path.parentPath.node.name.name}.${path.node.name.name}`,
  },
];
