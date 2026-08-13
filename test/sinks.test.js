const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const extractSinks = require("../src/sinks/extractSinks");
const { parseSnippet } = require("./helpers/parseSnippet");
const { listSinkRules, selectSinkRules, validateRule, loadSinkRules } = require("../src/sinks/registry");

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

test("project configuration loads a custom strategy without changing the plugin host", () => {
  const pluginProject = path.join(__dirname, "..", "fixtures", "plugin-project");
  const sinkRules = loadSinkRules({
    modules: ["./rules/customAlert.js"],
    basePath: pluginProject,
    includeDefault: true,
  });
  assert.ok(sinkRules.some((rule) => rule.id === "eval"));
  assert.ok(sinkRules.some((rule) => rule.id === "custom-alert"));

  const sinks = extractSinks([parseSnippet("alert(message); eval(code);")], {
    sinkRules,
    sinks: ["custom-alert"],
  });
  assert.deepEqual(sinks.map((sink) => [sink.ruleId, sink.sinkType, sink.priority]), [
    ["custom-alert", "custom.alert", 65],
  ]);
});

test("plugin loading rejects missing modules as configuration errors", () => {
  const pluginProject = path.join(__dirname, "..", "fixtures", "invalid-plugin-project");
  assert.throws(
    () => loadSinkRules({ modules: ["./rules/missing.js"], basePath: pluginProject }),
    (error) => error.code === "INVALID_CONFIG" && /Unable to resolve sink module/.test(error.message),
  );
});

test("plugin modules cannot escape the configuration directory", () => {
  const pluginProject = path.join(__dirname, "..", "fixtures", "plugin-project");
  assert.throws(
    () => loadSinkRules({ modules: ["../outside.js"], basePath: pluginProject }),
    (error) => error.code === "INVALID_CONFIG" && /escapes the configuration directory/.test(error.message),
  );
});

test("project configuration can replace all built-in sink strategies", () => {
  const pluginProject = path.join(__dirname, "..", "fixtures", "plugin-project");
  const sinkRules = loadSinkRules({
    modules: ["./rules/customAlert.js"],
    basePath: pluginProject,
    includeDefault: false,
  });
  assert.deepEqual(sinkRules.map((rule) => rule.id), ["custom-alert"]);
});
