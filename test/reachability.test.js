const test = require("node:test");
const assert = require("node:assert/strict");
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
  assert.equal(findings[0].sinkType, "dangerouslySetInnerHTML");
});

test("local propagation into a sink is HIGH", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { const result = transform(vulnerable); return <div dangerouslySetInnerHTML={{__html: result}} />; }`);
  assert.equal(findings[0].reachability, "HIGH");
  assert.deepEqual(findings[0].taintedPath, ["result"]);
});

test("unused import produces NONE", () => {
  const findings = analyze(`import vulnerable from "vulnerable-package"; function App() { return <div>safe</div>; }`);
  assert.equal(findings[0].reachability, "NONE");
});

test("usage without captured binding produces LOW", () => {
  const findings = analyze(`function App() { return <div />; }`, []);
  assert.equal(findings[0].reachability, "LOW");
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
