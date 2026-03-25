const traverse = require("@babel/traverse").default;

/**
 * Resolves a module specifier (e.g. "lodash/get") to the base package name
 * that would appear in npm audit (e.g. "lodash").
 * Returns null if no vulnerable package matches.
 */
function resolveVulnerablePackage(source, vulnerablePackages) {
  // Direct match: "lodash" -> "lodash"
  if (vulnerablePackages.has(source)) {
    return source;
  }

  // Sub-path match: "lodash/get" -> "lodash"
  // Handles both plain packages and scoped packages (@scope/pkg/path)
  const parts = source.startsWith("@")
    ? source.split("/").slice(0, 2)   // ["@scope", "pkg"]
    : source.split("/").slice(0, 1);  // ["lodash"]

  const basePkg = parts.join("/");
  if (basePkg !== source && vulnerablePackages.has(basePkg)) {
    return basePkg;
  }

  return null;
}

/**
 * Extracts the local binding names from a require() call's parent context.
 * Handles:
 * const foo = require("pkg") -> ["foo"]
 * const { a, b: c } = require("pkg") -> ["a", "c"]
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

function extractDependencyUsage(parsedFiles, vulnerablePackages) {
  const results = [];

  for (const file of parsedFiles) {
    const { ast, filePath } = file;

    traverse(ast, {
      // --- static import ---
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
            importedAs: path.node.specifiers.map((s) => s.local.name)
          });
        }
      },

      CallExpression(path) {
        const callee = path.node.callee;

        // --- require("pkg") ---
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
              importedAs: extractRequireBindings(path)
            });
          }
        }

        // --- dynamic import("pkg") ---
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