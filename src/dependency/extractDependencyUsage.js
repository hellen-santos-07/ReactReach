const traverse = require("@babel/traverse").default;

function extractDependencyUsage(parsedFiles, vulnerablePackages) {
  const results = [];

  for (const file of parsedFiles) {
    const { ast, filePath } = file;

    traverse(ast, {
      ImportDeclaration(path) {
        const source = path.node.source.value;

        if (vulnerablePackages.has(source)) {
          results.push({
            type: "import",
            packageName: source,
            filePath,
            loc: path.node.loc,
            importedAs: path.node.specifiers.map((s) => s.local.name)
          });
        }
      },

      CallExpression(path) {
        const callee = path.node.callee;

        // require("pkg")
        if (
          callee.type === "Identifier" &&
          callee.name === "require" &&
          path.node.arguments.length > 0 &&
          path.node.arguments[0].type === "StringLiteral"
        ) {
          const pkgName = path.node.arguments[0].value;

          if (vulnerablePackages.has(pkgName)) {
            results.push({
              type: "require",
              packageName: pkgName,
              filePath,
              loc: path.node.loc,
              importedAs: []
            });
          }
        }
      }
    });
  }

  return results;
}

module.exports = extractDependencyUsage;