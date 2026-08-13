const test = require("node:test");
const assert = require("node:assert/strict");
const ASTWalker = require("../src/ast/ASTWalker");
const { DependencyUsageWalker } = require("../src/dependency/extractDependencyUsage");
const { ComponentWalker } = require("../src/component/extractComponents");
const { SinkWalker } = require("../src/sinks/extractSinks");
const { parseSnippet } = require("./helpers/parseSnippet");

test("ASTWalker template executes pre-pass and specialised visitor in a fixed lifecycle", () => {
  class RecordingWalker extends ASTWalker {
    createResult() { return { events: [], identifiers: 0, calls: [] }; }
    beforeWalk(_files, _context, result) { result.events.push("before-walk"); }
    createFileContext(file, _context, result) {
      result.events.push(`context:${file.filePath}`);
      return { prePassComplete: false };
    }
    createPreVisitors(_file, fileContext, _context, result) {
      return {
        Identifier() { result.identifiers += 1; },
        Program: { exit() { fileContext.prePassComplete = true; } },
      };
    }
    createVisitors(_file, fileContext, _context, result) {
      assert.equal(fileContext.prePassComplete, true);
      result.events.push("main-visitors-created");
      return { CallExpression(path) { result.calls.push(path.node.callee.name); } };
    }
    afterFile(_file, _fileContext, _context, result) { result.events.push("after-file"); }
    afterWalk(_files, _context, result) { result.events.push("after-walk"); }
    finalizeResult(result) { result.events.push("finalize"); return result; }
  }

  const result = new RecordingWalker().walk([parseSnippet("run(value);", "Lifecycle.jsx")]);
  assert.ok(result.identifiers >= 2);
  assert.deepEqual(result.calls, ["run"]);
  assert.deepEqual(result.events, [
    "before-walk",
    "context:Lifecycle.jsx",
    "main-visitors-created",
    "after-file",
    "after-walk",
    "finalize",
  ]);
});

test("ASTWalker enforces its abstract visitor hook and parsed-file contract", () => {
  assert.throws(() => new ASTWalker().walk([parseSnippet("value;")]), /must implement createVisitors/);
  assert.throws(() => new ASTWalker().walk(null), /parsedFiles must be an array/);
  assert.throws(() => new ASTWalker().walk([{}]), /must contain an ast/);
});

test("analysis walkers specialise the shared ASTWalker template", () => {
  assert.ok(new DependencyUsageWalker(new Map()) instanceof ASTWalker);
  assert.ok(new ComponentWalker() instanceof ASTWalker);
  assert.ok(new SinkWalker() instanceof ASTWalker);
});
