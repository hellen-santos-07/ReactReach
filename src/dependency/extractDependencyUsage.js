const traverse = require("@babel/traverse").default;

/**
 * Resolves a module specifier ("lodash/get") to the base package name that would appear in npm audit ("lodash").
 * Otherwise, returns null if no vulnerable package matches.
 */
function resolveVulnerablePackage(source, vulnerablePackages) {
  // Direct match: "lodash" = "lodash"
  if (vulnerablePackages.has(source)) {
    return source;
  }

  // Sub-path match: "lodash/get" = "lodash"
  // Handles both plain packages and scoped packages (@scope/pkg/path)
  const parts = source.startsWith("@")
    ? source.split("/").slice(0, 2)   //exemplo ["@scope", "pkg"]
    : source.split("/").slice(0, 1);  //exemplo ["lodash"]

  const basePkg = parts.join("/");
  if (basePkg !== source && vulnerablePackages.has(basePkg)) {
    return basePkg;
  }

  return null;
}

/**
 * Extracts the local binding names from a require() call's parent context.
 * Handles:
 * const foo = require("pkg") = ["foo"]
 * const { a, b: c } = require("pkg") = ["a", "c"]
 */
function extractRequireBindings(callPath) {
  const parent = callPath.parent;
  if (!parent || parent.type !== "VariableDeclarator") return [];

  const id = parent.id;
  if (id.type === "Identifier") {
    return [id.name];
  }
  if (id.type === "ObjectPattern") {
    return id.properties
      .filter((p) => p.value && p.value.type === "Identifier")
      .map((p) => p.value.name);
  }

  return [];
}

/**
 * 
 * @param {*} parsedFiles 
 * @param {*} vulnerablePackages 
 * @returns {Array<{
 * type: string,
 * packageName: string,
 * source: string,
 * filePath: string,
 * loc: object, 
 * importedAs: Array<string>, 
 * auditSeverity: string 
 * }>}
 * 
 * type: string (the type of import - "import", "require", "dynamic-import")
 * packageName: string (the base package name - "lodash")
 * source: string (the original module specifier - "lodash/get")
 * filePath: string (the absolute path to the source file where this import occurs)
 * loc: object (the location info from Babel AST, containing start and end line/column)
 * importedAs: Array<string> (the local variable names that import this package)
 * auditSeverity: string (the severity level of the vulnerability from npm audit)
 */
function extractDependencyUsage(parsedFiles, vulnerablePackages) {
  const results = [];

  for (const file of parsedFiles) {
    const { ast, filePath } = file;

    traverse(ast, {
      // static import
      ImportDeclaration(path) {
        const source = path.node.source.value;
        const pkgName = resolveVulnerablePackage(source, vulnerablePackages);

        if (pkgName) {
          results.push({
            type: "import",
            packageName: pkgName,
            source,
            filePath,
            loc: path.node.loc,
            importedAs: path.node.specifiers.map((s) => s.local.name),
            auditSeverity: vulnerablePackages.get(pkgName)?.severity ?? "unknown"
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
          const source = path.node.arguments[0].value;
          const pkgName = resolveVulnerablePackage(source, vulnerablePackages);

          if (pkgName) {
            results.push({
              type: "require",
              packageName: pkgName,
              source,
              filePath,
              loc: path.node.loc,
              importedAs: extractRequireBindings(path),
              auditSeverity: vulnerablePackages.get(pkgName)?.severity ?? "unknown"
            });
          }
        }

        // dynamic import("pkg")
        if (
          callee.type === "Import" &&
          path.node.arguments.length > 0 &&
          path.node.arguments[0].type === "StringLiteral"
        ) {
          const source = path.node.arguments[0].value;
          const pkgName = resolveVulnerablePackage(source, vulnerablePackages);

          if (pkgName) {
            results.push({
              type: "dynamic-import",
              packageName: pkgName,
              source,
              filePath,
              loc: path.node.loc,
              importedAs: [],
              auditSeverity: vulnerablePackages.get(pkgName)?.severity ?? "unknown"
            });
          }
        }
      }
    });
  }

  return results;
}

module.exports = extractDependencyUsage;