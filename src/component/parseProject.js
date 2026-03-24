const fs = require("fs");
const path = require("path");
const glob = require("glob");
const parser = require("@babel/parser");

function getSourceFiles(projectPath) {
  return glob.sync("src/**/*.{js,jsx,ts,tsx}", {
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