const test = require("node:test");
const assert = require("node:assert/strict");
const extractSinks = require("../src/sinks/extractSinks");
const { parseSnippet } = require("./helpers/parseSnippet");
const { listSinkRules, selectSinkRules, validateRule } = require("../src/sinks/registry");

test("extractSinks characterizes all currently supported sink families", () => {
  const file = parseSnippet(`
    function View({ html, url, code }) {
      ref.current.innerHTML = html;
      ref.current.outerHTML = html;
      window.location.href = url;
      eval(code);
      ref.current.insertAdjacentHTML('beforeend', html);
      const fn = new Function('value', code);
      return <><div dangerouslySetInnerHTML={{ __html: html }} /><a href={url}>go</a><iframe src={url} /><form action={url} /><object data={url} /><button formAction={url}>send</button></>;
    }
  `, "View.jsx");
  const sinks = extractSinks([file]);
  const types = sinks.map((sink) => sink.sinkType);
  for (const expected of ["ref.innerHTML", "ref.outerHTML", "location-assign", "eval", "ref.insertAdjacentHTML", "new Function", "dangerouslySetInnerHTML", "a.href", "iframe.src", "form.action", "object.data", "button.formAction"]) {
    assert.ok(types.includes(expected), `expected ${expected}`);
  }
  assert.deepEqual(sinks.find((sink) => sink.sinkType === "eval").identifiers, ["code"]);
});

test("extractSinks ignores static JSX attributes", () => {
  const sinks = extractSinks([parseSnippet(`const View = () => <a href="https://example.test">safe</a>;`)]);
  assert.equal(sinks.length, 0);
});

test("sink results expose stable rule metadata", () => {
  const [sink] = extractSinks([parseSnippet(`eval(source.payload);`)]);
  assert.equal(sink.ruleId, "eval");
  assert.equal(sink.category, "code-execution");
  assert.equal(sink.priority, 100);
  assert.equal(sink.confidence, 100);
  assert.deepEqual(sink.identifiers, ["source"]);
});

test("location rule recognizes direct and property assignments", () => {
  const sinks = extractSinks([parseSnippet(`
    location = first;
    window.location = second;
    location.href = third;
    window.location.pathname = fourth;
  `)]);
  assert.equal(sinks.filter((sink) => sink.ruleId === "location").length, 4);
});

test("rules ignore shadowed globals and unrelated HTML properties", () => {
  const sinks = extractSinks([parseSnippet(`
    function local(eval, location) {
      eval(code);
      location.href = url;
      model.innerHTML = html;
    }
  `)]);
  assert.equal(sinks.length, 0);
});

test("DOM rules support computed ref properties", () => {
  const sinks = extractSinks([parseSnippet(`ref.current["innerHTML"] = html; ref.current["insertAdjacentHTML"]("beforeend", html);`)]);
  assert.deepEqual(sinks.map((sink) => sink.ruleId), ["dom-html", "insert-adjacent-html"]);
});

test("registry selection supports include, exclude, minimum and overrides", () => {
  const selected = selectSinkRules({
    sinks: ["eval", "location"],
    excludeSinks: ["location"],
    sinkPriorities: { eval: 42 },
    minSinkPriority: 40,
  });
  assert.deepEqual(selected.map((rule) => [rule.id, rule.priority]), [["eval", 42]]);
  assert.ok(listSinkRules().every((rule) => !("match" in rule) && !("getValueNode" in rule)));
});

test("extractor applies selected rules and configured priorities", () => {
  const file = parseSnippet(`eval(code); window.location = url;`);
  const sinks = extractSinks([file], { sinks: ["eval"], sinkPriorities: { eval: 55 }, minSinkPriority: 50 });
  assert.deepEqual(sinks.map((sink) => [sink.ruleId, sink.priority]), [["eval", 55]]);
});

test("registry rejects malformed custom rules", () => {
  assert.throws(() => validateRule({ id: "invalid" }), /missing/);
});
