const test = require("node:test");
const assert = require("node:assert/strict");
const extractComponents = require("../src/component/extractComponents");
const { computeTaintedBindings } = require("../src/reachability/taintPropagation");
const { parseSnippet } = require("./helpers/parseSnippet");

function componentFrom(code) {
  const file = parseSnippet(code, "Taint.jsx");
  return extractComponents([file]).find((component) => component.name === "App");
}

test("taint propagation module reaches a fixed point across local assignments and state setters", () => {
  const component = componentFrom(`
    import vulnerable from "vulnerable-package";
    function App() {
      let first, second;
      const [state, setState] = useState("");
      first = second;
      second = vulnerable();
      setState(first);
      return <div>{state}</div>;
    }
  `);
  const diagnostics = [];

  const taint = computeTaintedBindings(component, ["vulnerable"], { diagnostics });

  assert.deepEqual([...taint.names].sort(), ["first", "second", "state", "vulnerable"]);
  assert.deepEqual([...taint.sourceBindings].map((binding) => binding.identifier.name), ["vulnerable"]);
  assert.deepEqual(diagnostics, []);
});

test("taint propagation module reports a bounded non-converged pass", () => {
  const component = componentFrom(`
    import vulnerable from "vulnerable-package";
    function App() {
      let first, second;
      first = second;
      second = vulnerable();
      return <div>{first}</div>;
    }
  `);
  const diagnostics = [];

  const taint = computeTaintedBindings(component, ["vulnerable"], {
    diagnostics,
    maxIterations: 1,
  });

  assert.equal(taint.names.has("second"), true);
  assert.equal(taint.names.has("first"), false);
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0].code, "TAINT_ITERATION_LIMIT");
  assert.equal(diagnostics[0].maxIterations, 1);
});
