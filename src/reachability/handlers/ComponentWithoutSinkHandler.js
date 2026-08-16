const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class ComponentWithoutSinkHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "component" && context.componentSinks.length === 0;
  }

  classify() {
    return createClassification(REASON_CODES.COMPONENT_WITHOUT_SINK, "MEDIUM");
  }
}

module.exports = ComponentWithoutSinkHandler;
