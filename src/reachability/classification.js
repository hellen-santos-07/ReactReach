const REASON_CODES = Object.freeze({
  NO_BINDING: "NO_BINDING",
  UNUSED_IMPORT: "UNUSED_IMPORT",
  COMPONENT_WITHOUT_SINK: "COMPONENT_WITHOUT_SINK",
  DIRECT_SINK_FLOW: "DIRECT_SINK_FLOW",
  PROPAGATED_SINK_FLOW: "PROPAGATED_SINK_FLOW",
  NO_PROVEN_SINK_PATH: "NO_PROVEN_SINK_PATH",
  INTER_COMPONENT_SINK_FLOW: "INTER_COMPONENT_SINK_FLOW",
});

const REASONS = Object.freeze({
  [REASON_CODES.NO_BINDING]: "Vulnerable dependency imported but no binding name captured (dynamic import or bare require)",
  [REASON_CODES.UNUSED_IMPORT]: "Vulnerable dependency imported but identifiers are never referenced in any component",
  [REASON_CODES.COMPONENT_WITHOUT_SINK]: "Vulnerable dependency used inside React component but no security sink found in this component",
  [REASON_CODES.DIRECT_SINK_FLOW]: "Vulnerable dependency identifier flows directly into a security sink",
  [REASON_CODES.PROPAGATED_SINK_FLOW]: "Variable derived from vulnerable dependency reaches a security sink via React hooks or local propagation",
  [REASON_CODES.NO_PROVEN_SINK_PATH]: "Vulnerable dependency used in a component with sinks, but no structural data path found",
  [REASON_CODES.INTER_COMPONENT_SINK_FLOW]: "Tainted data from vulnerable dependency flows through component props boundary into a security sink in a child component",
});

function createClassification(reasonCode, reachability) {
  return Object.freeze({ reasonCode, reachability });
}

module.exports = { REASON_CODES, REASONS, createClassification };
