const traverse = require("@babel/traverse").default;

function isJSXReturningFunction(node) {
  if (!node || !node.body) return false;

  if (node.body.type === "JSXElement" || node.body.type === "JSXFragment") {
    return true;
  }

  if (node.body.type === "BlockStatement") {
    return node.body.body.some(
      (statement) =>
        statement.type === "ReturnStatement" &&
        statement.argument &&
        (statement.argument.type === "JSXElement" || statement.argument.type === "JSXFragment")
    );
  }

  return false;
}

function extractComponents(parsedFiles) {
  const components = [];

  for (const file of parsedFiles) {
    traverse(file.ast, {
      FunctionDeclaration(path) {
        const name = path.node.id?.name;
        if (name && /^[A-Z]/.test(name) && isJSXReturningFunction(path.node)) {
          components.push({
            name,
            type: "FunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      },

      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;

        if (
          id?.type === "Identifier" &&
          /^[A-Z]/.test(id.name) &&
          (init?.type === "ArrowFunctionExpression" || init?.type === "FunctionExpression") &&
          isJSXReturningFunction(init)
        ) {
          components.push({
            name: id.name,
            type: "ArrowFunctionComponent",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      },

      ClassDeclaration(path) {
        const name = path.node.id?.name;
        const superClass = path.node.superClass;

        if (
          name &&
          /^[A-Z]/.test(name) &&
          superClass &&
          (
            superClass.type === "MemberExpression" ||
            superClass.type === "Identifier"
          )
        ) {
          components.push({
            name,
            type: "ClassComponent",
            filePath: file.filePath,
            loc: path.node.loc
          });
        }
      }
    });
  }

  return components;
}

module.exports = extractComponents;