const traverse = require("@babel/traverse").default;
const t = require("@babel/types");

/**
 * Collects every Identifier name referenced inside an AST node.
 */
function collectIdentifiers(node) {
  const ids = new Set();
  if (!node) return ids;

  if (t.isIdentifier(node)) {
    ids.add(node.name);
    return ids;
  }

  for (const key of t.VISITOR_KEYS[node.type] || []) {
    const child = node[key];
    if (Array.isArray(child)) {
      child.forEach((c) => {
        if (t.isNode(c)) {
          collectIdentifiers(c).forEach((id) => ids.add(id));
        }
      });
    } else if (t.isNode(child)) {
      collectIdentifiers(child).forEach((id) => ids.add(id));
    }
  }

  return ids;
}

// JSX attribute names that are security-sensitive on specific elements.
// primary injection vectors in React's rendering model.
const JSX_SINK_ATTRIBUTES = new Map([
  // <a href={expr}> — XSS via javascript: protocol
  ["href", new Set(["a"])],
  // <iframe src={expr}> / <script src={expr}> / <embed src={expr}>
  ["src", new Set(["iframe", "script", "embed", "object"])],
  // <form action={expr}> — form hijacking
  ["action", new Set(["form"])],
  // <object data={expr}> — remote content loading
  ["data", new Set(["object"])],
  // <a href> / <area href> with formAction
  ["formAction", new Set(["button", "input"])]
]);

function extractSinks(parsedFiles) {
  const sinks = [];

  for (const file of parsedFiles) {
    traverse(file.ast, {

      // ----------------------------------------------
      //  REACT-SPECIFIC JSX SINKS

      JSXAttribute(path) {
        const attrName = path.node.name?.name;
        if (!attrName) return;

        // --- dangerouslySetInnerHTML={{ __html: expr }} ---
        // The #1 React XSS vector — bypasses React's auto-escaping
        if (attrName === "dangerouslySetInnerHTML") {
          const argNode = path.node.value;
          sinks.push({
            sinkType: "dangerouslySetInnerHTML",
            filePath: file.filePath,
            loc: path.node.loc,
            identifiers: [...collectIdentifiers(argNode)]
          });
          return;
        }

        // --- href, src, action, etc on security sensitive elements ---
        const targetElements = JSX_SINK_ATTRIBUTES.get(attrName);
        if (!targetElements) return;

        // Walk up to the JSXOpeningElement to check the element name
        const openingElement = path.parentPath?.node;
        if (!t.isJSXOpeningElement(openingElement)) return;

        const elemName = openingElement.name;
        if (!t.isJSXIdentifier(elemName)) return;

        if (targetElements.has(elemName.name)) {
          // Only flag when the value is a JSX expression, not a static string
          const value = path.node.value;
          if (t.isJSXExpressionContainer(value)) {
            sinks.push({
              sinkType: `${elemName.name}.${attrName}`,
              filePath: file.filePath,
              loc: path.node.loc,
              identifiers: [...collectIdentifiers(value.expression)]
            });
          }
        }
      },

      // ----------------------------------------------
      //  REF-BASED DOM ESCAPE HATCHES

      AssignmentExpression(path) {
        const left = path.node.left;

        // ref.current.innerHTML = expr / ref.current.outerHTML = expr
        if (
          left.type === "MemberExpression" &&
          !left.computed &&
          left.property.type === "Identifier" &&
          ["innerHTML", "outerHTML"].includes(left.property.name)
        ) {
          sinks.push({
            sinkType: `ref.${left.property.name}`,
            filePath: file.filePath,
            loc: path.node.loc,
            identifiers: [...collectIdentifiers(path.node.right)]
          });
        }

        // window.location / location = expr
        if (left.type === "MemberExpression") {
          const isLocationAssign =
            (left.object.type === "Identifier" && left.object.name === "location") ||
            (left.object.type === "MemberExpression" &&
              left.object.object.type === "Identifier" &&
              left.object.object.name === "window" &&
              left.object.property.type === "Identifier" &&
              left.object.property.name === "location");

          if (isLocationAssign) {
            sinks.push({
              sinkType: "location-assign",
              filePath: file.filePath,
              loc: path.node.loc,
              identifiers: [...collectIdentifiers(path.node.right)]
            });
          }
        }
      },

      // ----------------------------------------------
      //  GENERAL JS SINKS 

      CallExpression(path) {
        const callee = path.node.callee;
        const args = path.node.arguments;

        // eval(expr)
        if (callee.type === "Identifier" && callee.name === "eval" && args.length > 0) {
          sinks.push({
            sinkType: "eval",
            filePath: file.filePath,
            loc: path.node.loc,
            identifiers: [...collectIdentifiers(args[0])]
          });
        }

        // ref.current.insertAdjacentHTML(pos, expr) — via ref escape hatch
        if (
          callee.type === "MemberExpression" &&
          !callee.computed &&
          callee.property.type === "Identifier" &&
          callee.property.name === "insertAdjacentHTML" &&
          args.length >= 2
        ) {
          sinks.push({
            sinkType: "ref.insertAdjacentHTML",
            filePath: file.filePath,
            loc: path.node.loc,
            identifiers: [...collectIdentifiers(args[1])]
          });
        }
      },

      NewExpression(path) {
        if (
          path.node.callee.type === "Identifier" &&
          path.node.callee.name === "Function" &&
          path.node.arguments.length > 0
        ) {
          const lastArg = path.node.arguments[path.node.arguments.length - 1];
          sinks.push({
            sinkType: "new Function",
            filePath: file.filePath,
            loc: path.node.loc,
            identifiers: [...collectIdentifiers(lastArg)]
          });
        }
      }
    });
  }

  return sinks;
}

module.exports = extractSinks;