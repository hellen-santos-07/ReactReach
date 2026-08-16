class ReachabilityHandler {
  constructor() {
    this.nextHandler = null;
  }

  setNext(handler) {
    this.nextHandler = handler;
    return handler;
  }

  handle(context) {
    if (this.canHandle(context)) return this.classify(context);
    return this.nextHandler ? this.nextHandler.handle(context) : null;
  }

  canHandle() {
    return false;
  }

  classify() {
    throw new Error(`${this.constructor.name} must implement classify()`);
  }
}

module.exports = ReachabilityHandler;
