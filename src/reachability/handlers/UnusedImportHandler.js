const ReachabilityHandler = require("./ReachabilityHandler");
const { REASON_CODES, createClassification } = require("../classification");

class UnusedImportHandler extends ReachabilityHandler {
  canHandle(context) {
    return context.stage === "usage" && context.relevantComponents.length === 0;
  }

  classify() {
    return createClassification(REASON_CODES.UNUSED_IMPORT, "NONE");
  }
}

module.exports = UnusedImportHandler;
