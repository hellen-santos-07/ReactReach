const test = require("node:test");
const assert = require("node:assert/strict");
const extractSinks = require("../src/sinks/extractSinks");
const { parseSnippet } = require("./helpers/parseSnippet");

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
