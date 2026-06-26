const test = require("node:test");
const assert = require("node:assert");

const { buildCommentHtml, renderComment } = require("../source/render.js");

test("wraps benign text in a paragraph", () => {
  // Plain text round-trips; an output-encoding fix leaves it unchanged.
  assert.strictEqual(buildCommentHtml("hello"), "<p>hello</p>");
});

test("renderComment returns the target element", () => {
  const element = {};
  assert.strictEqual(renderComment(element, "hello"), element);
});
