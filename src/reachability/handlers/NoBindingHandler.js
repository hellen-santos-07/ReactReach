const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class NoBindingHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "usage" && context.vulnerableIdentifiers.size === 0;
  }

  classify() {
    return createClassification(REASON_CODES.NO_BINDING, "LOW");
  }
}

module.exports = NoBindingHandler;
