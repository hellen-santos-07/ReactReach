const NoBindingHandler = require("./NoBindingHandler");
const UnusedImportHandler = require("./UnusedImportHandler");
const ComponentWithoutSinkHandler = require("./ComponentWithoutSinkHandler");
const DirectSinkFlowHandler = require("./DirectSinkFlowHandler");
const PropagatedSinkFlowHandler = require("./PropagatedSinkFlowHandler");
const InterComponentSinkFlowHandler = require("./InterComponentSinkFlowHandler");
const NoProvenSinkPathHandler = require("./NoProvenSinkPathHandler");

function createReachabilityChain() {
  const handlers = [
    new NoBindingHandler(),
    new UnusedImportHandler(),
    new ComponentWithoutSinkHandler(),
    new DirectSinkFlowHandler(),
    new PropagatedSinkFlowHandler(),
    new InterComponentSinkFlowHandler(),
    new NoProvenSinkPathHandler(),
  ];
  for (let index = 0; index < handlers.length - 1; index++) {
    handlers[index].setNext(handlers[index + 1]);
  }
  return handlers[0];
}

module.exports = createReachabilityChain;
