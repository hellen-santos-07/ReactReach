const traverse = require("@babel/traverse").default;

function extractSinks(parsedFiles) {
  const sinks = [];

  for (const file of parsedFiles) {
    traverse(file.ast, {
      JSXAttribute(path) {
        if (
          path.node.name &&
          path.node.name.name === "dangerouslySetInnerHTML"
        ) {
          sinks.push({
            sinkType: "dangerouslySetInnerHTML",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      },

      AssignmentExpression(path) {
        const left = path.node.left;

        if (
          left.type === "MemberExpression" &&
          !left.computed &&
          left.property.type === "Identifier" &&
          ["innerHTML", "outerHTML"].includes(left.property.name)
        ) {
          sinks.push({
            sinkType: left.property.name,
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      },

      CallExpression(path) {
        const callee = path.node.callee;

        if (callee.type === "Identifier" && callee.name === "eval") {
          sinks.push({
            sinkType: "eval",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }

        if (
          callee.type === "MemberExpression" &&
          !callee.computed &&
          callee.property.type === "Identifier" &&
          callee.property.name === "insertAdjacentHTML"
        ) {
          sinks.push({
            sinkType: "insertAdjacentHTML",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }

        if (
          callee.type === "MemberExpression" &&
          callee.object.type === "Identifier" &&
          callee.object.name === "document" &&
          callee.property.type === "Identifier" &&
          callee.property.name === "write"
        ) {
          sinks.push({
            sinkType: "document.write",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      },

      NewExpression(path) {
        if (
          path.node.callee.type === "Identifier" &&
          path.node.callee.name === "Function"
        ) {
          sinks.push({
            sinkType: "new Function",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      }
    });
  }

  return sinks;
}

module.exports = extractSinks;