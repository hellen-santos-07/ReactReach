const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class NoProvenSinkPathHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "component-fallback" && !context.hasSinkPath;
  }

  classify() {
    return createClassification(REASON_CODES.NO_PROVEN_SINK_PATH, "MEDIUM");
  }
}

module.exports = NoProvenSinkPathHandler;
