const fs = require("fs");
const path = require("path");
const fg = require("fast-glob");
const parser = require("@babel/parser");

function getSourceFiles(projectPath) {
  return fg.sync("src/**/*.{js,jsx,ts,tsx}", {
    cwd: projectPath,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**"
    ]
  });
}

function parseFile(filePath) {
  const code = fs.readFileSync(filePath, "utf8");

  const ast = parser.parse(code, {
    sourceType: "unambiguous",
    plugins: [
      "jsx",
      "typescript",
      "classProperties",
      "objectRestSpread",
      "optionalChaining",
      "nullishCoalescingOperator",
      "decorators-legacy"
    ]
  });

  return { code, ast };
}

/**
 * 
 * @param {*} projectPath 
 * @returns {Array<{filePath: string, code: string, ast: object}>}
 *  filePath: string (the absolute path to the source file)
 *  code: string (the raw source code of the file)
 *  ast: Babel AST (the parsed abstract syntax tree of the file)
 */
function parseProject(projectPath) {
  const files = getSourceFiles(projectPath);

  return files.map((filePath) => {
    const { code, ast } = parseFile(filePath);
    return { filePath, code, ast };
  });
}

module.exports = {
  parseProject,
  parseFile,
  getSourceFiles
};