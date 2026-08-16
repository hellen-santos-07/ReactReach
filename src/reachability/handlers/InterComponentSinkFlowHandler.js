const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class InterComponentSinkFlowHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "inter-component" && context.hasTaintOverlap;
  }

  classify() {
    return createClassification(REASON_CODES.INTER_COMPONENT_SINK_FLOW, "HIGH");
  }
}

module.exports = InterComponentSinkFlowHandler;
