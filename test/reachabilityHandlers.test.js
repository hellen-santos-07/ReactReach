const test = require("node:test");
const assert = require("node:assert/strict");
const ReachabilityHandler = require("../src/reachability/handlers/ReachabilityHandler");
const NoBindingHandler = require("../src/reachability/handlers/NoBindingHandler");
const UnusedImportHandler = require("../src/reachability/handlers/UnusedImportHandler");
const ComponentWithoutSinkHandler = require("../src/reachability/handlers/ComponentWithoutSinkHandler");
const DirectSinkFlowHandler = require("../src/reachability/handlers/DirectSinkFlowHandler");
const PropagatedSinkFlowHandler = require("../src/reachability/handlers/PropagatedSinkFlowHandler");
const InterComponentSinkFlowHandler = require("../src/reachability/handlers/InterComponentSinkFlowHandler");
const NoProvenSinkPathHandler = require("../src/reachability/handlers/NoProvenSinkPathHandler");
const createReachabilityChain = require("../src/reachability/handlers/createReachabilityChain");

const cases = [
  [NoBindingHandler, { stage: "usage", vulnerableIdentifiers: new Set(), relevantComponents: [] }, "NO_BINDING", "LOW"],
  [UnusedImportHandler, { stage: "usage", vulnerableIdentifiers: new Set(["dependency"]), relevantComponents: [] }, "UNUSED_IMPORT", "NONE"],
  [ComponentWithoutSinkHandler, { stage: "component", componentSinks: [] }, "COMPONENT_WITHOUT_SINK", "MEDIUM"],
  [DirectSinkFlowHandler, { stage: "sink", hasTaintOverlap: true, direct: true }, "DIRECT_SINK_FLOW", "CRITICAL"],
  [PropagatedSinkFlowHandler, { stage: "sink", hasTaintOverlap: true, direct: false }, "PROPAGATED_SINK_FLOW", "HIGH"],
  [InterComponentSinkFlowHandler, { stage: "inter-component", hasTaintOverlap: true }, "INTER_COMPONENT_SINK_FLOW", "HIGH"],
  [NoProvenSinkPathHandler, { stage: "component-fallback", hasSinkPath: false }, "NO_PROVEN_SINK_PATH", "MEDIUM"],
];

for (const [Handler, context, reasonCode, reachability] of cases) {
  test(`${Handler.name} classifies ${reasonCode}`, () => {
    assert.deepEqual(new Handler().handle(context), { reasonCode, reachability });
  });
}

test("handler delegates to its successor and returns null when the chain is exhausted", () => {
  const first = new NoBindingHandler();
  const second = new UnusedImportHandler();
  assert.equal(first.setNext(second), second);
  assert.equal(first.handle({ stage: "component", componentSinks: [] }), null);
  assert.deepEqual(first.handle({
    stage: "usage",
    vulnerableIdentifiers: new Set(["dependency"]),
    relevantComponents: [],
  }), { reasonCode: "UNUSED_IMPORT", reachability: "NONE" });
});

test("default chain gives direct flow precedence over propagated flow", () => {
  const classification = createReachabilityChain().handle({
    stage: "sink",
    hasTaintOverlap: true,
    direct: true,
  });
  assert.deepEqual(classification, { reasonCode: "DIRECT_SINK_FLOW", reachability: "CRITICAL" });
});

test("base handler requires concrete classification behaviour", () => {
  assert.equal(new ReachabilityHandler().handle({}), null);
  class MatchingHandler extends ReachabilityHandler {
    canHandle() { return true; }
  }
  assert.throws(() => new MatchingHandler().handle({}), /must implement classify/);
});
