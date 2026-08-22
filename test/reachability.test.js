const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const extractComponents = require("../src/component/extractComponents");
const extractSinks = require("../src/sinks/extractSinks");
const computeReachability = require("../src/reachability/computeReachability");
const buildComponentGraph = require("../src/component/buildComponentGraph");
const { parseSnippet } = require("./helpers/parseSnippet");

function analyze(code, importedAs = ["vulnerable"]) {
  const file = parseSnippet(code, "App.jsx");
  const usage = { packageName: "vulnerable-package", filePath: file.filePath, importedAs, auditSeverity: "high" };
  return computeReachability([usage], extractComponents([file]), extractSinks([file]));
}

test("direct flow into a sink is CRITICAL", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { return <div dangerouslySetInnerHTML={{__html: vulnerable}} />; }`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].reachability, "CRITICAL");
  assert.equal(findings[0].reasonCode, "DIRECT_SINK_FLOW");
  assert.equal(findings[0].sinkType, "dangerouslySetInnerHTML");
  assert.equal(findings[0].sinkRuleId, "inner-html");
  assert.equal(findings[0].sinkPriority, 100);
  assert.equal(findings[0].confidence, 100);
});

test("local propagation into a sink is HIGH", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { const result = transform(vulnerable); return <div dangerouslySetInnerHTML={{__html: result}} />; }`);
  assert.equal(findings[0].reachability, "HIGH");
  assert.equal(findings[0].reasonCode, "PROPAGATED_SINK_FLOW");
  assert.deepEqual(findings[0].taintedPath, ["result"]);
});

test("classification chain preserves multiple findings for one dependency usage", () => {
  const findings = analyze(`
    import vulnerable from "vulnerable-package";
    function App() {
      eval(vulnerable);
      const generated = new Function(vulnerable);
      return <div>{generated.name}</div>;
    }
  `);
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map((finding) => finding.sinkRuleId), ["eval", "new-function"]);
  assert.ok(findings.every((finding) => finding.reachability === "CRITICAL"));
});

test("unused import produces NONE", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { return <div>safe</div>; }`);
  assert.equal(findings[0].reachability, "NONE");
  assert.equal(findings[0].reasonCode, "UNUSED_IMPORT");
});

test("usage without captured binding produces LOW", () => {
  const findings = analyze(`function App() { return <div />; }`, []);
  assert.equal(findings[0].reachability, "LOW");
  assert.equal(findings[0].reasonCode, "NO_BINDING");
});

test("component usage without a sink produces MEDIUM", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { const value = vulnerable(); return <div>{value}</div>; }`);
  assert.equal(findings[0].reachability, "MEDIUM");
  assert.equal(findings[0].sinkType, null);
});

test("component with an unrelated sink produces MEDIUM", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { vulnerable(); return <div dangerouslySetInnerHTML={{__html: safeValue}} />; }`);
  assert.equal(findings[0].reachability, "MEDIUM");
  assert.match(findings[0].reason, /no structural data path/i);
});

test("taint propagates through useState initial values and setters", () => {
  const initial = analyze(`import vulnerable from "vulnerable-package"; function App() { const [value] = React.useState(vulnerable); return <div dangerouslySetInnerHTML={{__html: value}} />; }`);
  assert.equal(initial[0].reachability, "HIGH");

  const setter = analyze(`import vulnerable from "vulnerable-package"; function App() { const [value, setValue] = useState(''); setValue(vulnerable); return <div dangerouslySetInnerHTML={{__html: value}} />; }`);
  assert.equal(setter[0].reachability, "HIGH");
});

test("taint propagates across a direct component props boundary", () => {
  const file = parseSnippet(`
    import vulnerable from "vulnerable-package";
    function Parent() { const value = vulnerable(); return <Child content={value} />; }
    function Child({ content }) { return <div dangerouslySetInnerHTML={{__html: content}} />; }
  `, "Tree.jsx");
  const components = extractComponents([file]);
  const graph = buildComponentGraph(components);
  const usage = { packageName: "vulnerable-package", filePath: file.filePath, importedAs: ["vulnerable"], auditSeverity: "high" };
  const findings = computeReachability([usage], components, extractSinks([file]), graph);
  const inter = findings.find((finding) => finding.propagationType === "inter-component");
  assert.ok(inter);
  assert.equal(inter.childComponent, "Child");
  assert.equal(inter.reachability, "HIGH");
});

test("taint propagation reaches a fixed point for long reverse-ordered chains", () => {
  const findings = analyze(`
    import vulnerable from "vulnerable-package";
    function App() {
      let first, second, third, fourth;
      first = second;
      second = third;
      third = fourth;
      fourth = vulnerable();
      return <div dangerouslySetInnerHTML={{__html: first}} />;
    }
  `);
  assert.equal(findings[0].reachability, "HIGH");
  assert.deepEqual(findings[0].taintedPath, ["first"]);
});

test("bindings prevent taint from crossing a shadowed identifier", () => {
  const findings = analyze(`
    import vulnerable from "vulnerable-package";
    function App() {
      vulnerable();
      function nested(vulnerable) { eval(vulnerable); }
      return <div>safe</div>;
    }
  `);
  assert.equal(findings[0].reachability, "MEDIUM");
  assert.equal(findings[0].reasonCode, "NO_PROVEN_SINK_PATH");
});

test("taint iteration limits emit diagnostics instead of hanging", () => {
  const file = parseSnippet(`
    import vulnerable from "vulnerable-package";
    function App() {
      let first, second, third;
      first = second; second = third; third = vulnerable();
      return <div dangerouslySetInnerHTML={{__html: first}} />;
    }
  `, "Limit.jsx");
  const usage = { packageName: "vulnerable-package", filePath: file.filePath, importedAs: ["vulnerable"], auditSeverity: "high" };
  const findings = computeReachability([usage], extractComponents([file]), extractSinks([file]), null, { maxTaintIterations: 1 });
  assert.equal(findings[0].reachability, "MEDIUM");
  assert.equal(findings.diagnostics.length, 1);
  assert.equal(findings.diagnostics[0].code, "TAINT_ITERATION_LIMIT");
});

test("taint propagates through multiple component boundaries", () => {
  const file = parseSnippet(`
    import vulnerable from "vulnerable-package";
    function Parent() { const value = vulnerable(); return <Middle content={value} />; }
    function Middle({ content }) { return <GrandChild html={content} />; }
    function GrandChild({ html }) { return <div dangerouslySetInnerHTML={{__html: html}} />; }
  `, "DeepTree.jsx");
  const components = extractComponents([file]);
  const graph = buildComponentGraph(components);
  const usage = { packageName: "vulnerable-package", filePath: file.filePath, importedAs: ["vulnerable"], auditSeverity: "high" };
  const findings = computeReachability([usage], components, extractSinks([file]), graph);
  const inter = findings.find((finding) => finding.childComponent === "GrandChild");
  assert.ok(inter);
  assert.deepEqual(inter.componentPath, ["Parent", "Middle", "GrandChild"]);
  assert.equal(inter.propagationPath.length, 2);
  assert.deepEqual(inter.propagationPath.map((step) => step.props), [["content"], ["html"]]);
});

test("relative imports disambiguate components with identical names", () => {
  const projectRoot = path.resolve("project");
  const parent = parseSnippet(`
    import vulnerable from "vulnerable-package";
    import SafeTarget from "./safe/Target";
    function Parent() { const value = vulnerable(); return <SafeTarget content={value} />; }
  `, path.join(projectRoot, "src", "Parent.jsx"));
  const safe = parseSnippet(`export default function Target({ content }) { return <div>{content}</div>; }`, path.join(projectRoot, "src", "safe", "Target.jsx"));
  const dangerous = parseSnippet(`export default function Target({ content }) { return <div dangerouslySetInnerHTML={{__html: content}} />; }`, path.join(projectRoot, "src", "danger", "Target.jsx"));
  const files = [parent, safe, dangerous];
  const components = extractComponents(files);
  const graph = buildComponentGraph(components);
  const usage = { packageName: "vulnerable-package", filePath: parent.filePath, importedAs: ["vulnerable"], auditSeverity: "high" };
  const findings = computeReachability([usage], components, extractSinks(files), graph);
  assert.equal(findings.some((finding) => finding.propagationType === "inter-component"), false);
  const parentNode = graph.getNode(parent.filePath, "Parent");
  assert.equal(parentNode.children.length, 1);
  assert.equal(parentNode.children[0].component.filePath, safe.filePath);
});
