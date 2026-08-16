#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const fg = require("fast-glob");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const CONTROL_VISITORS = {
  IfStatement: () => 1,
  ConditionalExpression: () => 1,
  SwitchCase: (nodePath) => Number(Boolean(nodePath.node.test)),
  ForStatement: () => 1,
  ForInStatement: () => 1,
  ForOfStatement: () => 1,
  WhileStatement: () => 1,
  DoWhileStatement: () => 1,
  CatchClause: () => 1,
  LogicalExpression: (nodePath) => Number(["&&", "||", "??"].includes(nodePath.node.operator)),
};

function functionName(functionPath, filePath) {
  if (functionPath.node.id?.name) return functionPath.node.id.name;
  if (functionPath.isClassMethod() || functionPath.isClassPrivateMethod()) {
    const owner = functionPath.findParent((parent) => parent.isClassDeclaration() || parent.isClassExpression());
    const className = owner?.node.id?.name || "<anonymous-class>";
    const methodName = functionPath.node.key.name || functionPath.node.key.value || "<method>";
    return `${className}.${methodName}`;
  }
  const parent = functionPath.parentPath;
  if (parent.isVariableDeclarator() && parent.node.id.type === "Identifier") return parent.node.id.name;
  if (parent.isObjectProperty() || parent.isObjectMethod()) return parent.node.key.name || parent.node.key.value;
  return `<callback@${path.basename(filePath)}:${functionPath.node.loc.start.line}>`;
}

function measureFunction(functionPath, filePath) {
  let complexity = 1;
  const visitors = {
    Function(nestedPath) { nestedPath.skip(); },
  };
  for (const [nodeType, increment] of Object.entries(CONTROL_VISITORS)) {
    visitors[nodeType] = (nodePath) => { complexity += increment(nodePath); };
  }
  functionPath.traverse(visitors);
  return {
    file: filePath.replaceAll("\\", "/"),
    name: functionName(functionPath, filePath),
    line: functionPath.node.loc.start.line,
    complexity,
  };
}

function measureFile(filePath) {
  const source = fs.readFileSync(filePath, "utf8");
  const ast = parser.parse(source, { sourceType: "unambiguous", plugins: ["jsx"] });
  const functions = [];
  traverse(ast, {
    Function(functionPath) {
      if (functionPath.findParent((parent) => parent.isFunction())) return;
      functions.push(measureFunction(functionPath, filePath));
    },
  });
  return functions;
}

function main(patterns = process.argv.slice(2)) {
  const requested = patterns.length ? patterns : ["src/**/*.js"];
  const files = fg.sync(requested, { onlyFiles: true, unique: true }).sort();
  if (files.length === 0) throw new Error(`No JavaScript files matched: ${requested.join(", ")}`);
  const functions = files.flatMap(measureFile).sort((left, right) =>
    right.complexity - left.complexity || left.file.localeCompare(right.file) || left.line - right.line,
  );
  const result = {
    metric: "McCabe cyclomatic complexity",
    decisionPoints: ["if", "?:", "switch case", "loops", "catch", "&&", "||", "??"],
    files: files.length,
    functions: functions.length,
    total: functions.reduce((sum, item) => sum + item.complexity, 0),
    average: Number((functions.reduce((sum, item) => sum + item.complexity, 0) / functions.length).toFixed(2)),
    maximum: functions[0],
    functionsOver10: functions.filter((item) => item.complexity > 10),
    details: functions,
  };
  console.log(JSON.stringify(result, null, 2));
  if (result.functionsOver10.length > 0) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { measureFile, main };
