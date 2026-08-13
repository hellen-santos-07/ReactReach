const babelTraverse = require("@babel/traverse").default;

/**
 * Template Method for analyses that traverse every parsed source file.
 *
 * The public walk() method fixes the algorithm skeleton: create a shared
 * result, prepare each file, optionally run a pre-pass, run the specialised
 * visitor, and finalise the result. Subclasses customise only the hook methods.
 */
class ASTWalker {
  constructor(options = {}) {
    this.traverse = options.traverse || babelTraverse;
  }

  walk(parsedFiles, context = {}) {
    if (!Array.isArray(parsedFiles)) throw new TypeError("parsedFiles must be an array");
    const result = this.createResult(context);
    this.beforeWalk(parsedFiles, context, result);

    for (const file of parsedFiles) {
      if (!file || !file.ast) throw new TypeError("each parsed file must contain an ast");
      const fileContext = this.createFileContext(file, context, result);
      this.beforeFile(file, fileContext, context, result);

      const preVisitors = this.createPreVisitors(file, fileContext, context, result);
      if (preVisitors && Object.keys(preVisitors).length > 0) this.traverse(file.ast, preVisitors);

      const visitors = this.createVisitors(file, fileContext, context, result);
      if (!visitors || typeof visitors !== "object") {
        throw new TypeError(`${this.constructor.name}.createVisitors() must return a visitor object`);
      }
      this.traverse(file.ast, visitors);
      this.afterFile(file, fileContext, context, result);
    }

    this.afterWalk(parsedFiles, context, result);
    return this.finalizeResult(result, context);
  }

  createResult() { return []; }

  createFileContext() { return {}; }

  createPreVisitors() { return null; }

  createVisitors() {
    throw new Error(`${this.constructor.name} must implement createVisitors()`);
  }

  beforeWalk() {}

  beforeFile() {}

  afterFile() {}

  afterWalk() {}

  finalizeResult(result) { return result; }
}

module.exports = ASTWalker;
