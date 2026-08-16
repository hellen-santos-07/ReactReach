const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class PropagatedSinkFlowHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "sink" && context.hasTaintOverlap;
  }

  classify() {
    return createClassification(REASON_CODES.PROPAGATED_SINK_FLOW, "HIGH");
  }
}

module.exports = PropagatedSinkFlowHandler;
