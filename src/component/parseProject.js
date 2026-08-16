const fs = require("fs");
const fg = require("fast-glob");
const parser = require("@babel/parser");

function compareSourcePaths(left, right) {
  const normalizedLeft = left.replace(/\\/g, "/");
  const normalizedRight = right.replace(/\\/g, "/");
  if (normalizedLeft === normalizedRight) return 0;
  return normalizedLeft < normalizedRight ? -1 : 1;
}

function getSourceFiles(projectPath) {
  return fg.sync("src/**/*.{js,jsx,ts,tsx}", {
    cwd: projectPath,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**"
    ]
  }).sort(compareSourcePaths);
}

function parseFile(filePath) {
  let code;
  try {
    code = fs.readFileSync(filePath, "utf8");
  } catch (cause) {
    const error = new Error(`Unable to read source file ${filePath}: ${cause.message}`);
    error.code = "SOURCE_READ_FAILED";
    error.filePath = filePath;
    error.cause = cause;
    throw error;
  }

  try {
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
  } catch (cause) {
    const error = new SyntaxError(`Unable to parse source file ${filePath}: ${cause.message}`);
    error.code = "PARSE_FAILED";
    error.filePath = filePath;
    error.cause = cause;
    throw error;
  }
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
  getSourceFiles,
  compareSourcePaths,
};
