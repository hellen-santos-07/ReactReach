const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class DirectSinkFlowHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "sink" && context.hasTaintOverlap && context.direct;
  }

  classify() {
    return createClassification(REASON_CODES.DIRECT_SINK_FLOW, "CRITICAL");
  }
}

module.exports = DirectSinkFlowHandler;
