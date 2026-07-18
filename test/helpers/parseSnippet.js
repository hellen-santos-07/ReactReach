const parser = require("@babel/parser");

function parseSnippet(code, filePath = "fixture.jsx") {
  return {
    filePath,
    code,
    ast: parser.parse(code, {
      sourceType: "unambiguous",
      plugins: ["jsx", "typescript", "classProperties", "objectRestSpread", "optionalChaining", "nullishCoalescingOperator", "decorators-legacy"],
    }),
  };
}

module.exports = { parseSnippet };
