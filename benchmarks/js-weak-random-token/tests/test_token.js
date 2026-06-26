const test = require("node:test");
const assert = require("node:assert");

const { generateToken } = require("../source/token.js");

test("token keeps the session prefix", () => {
  // A crypto-strong fix still produces a "sess_"-prefixed token.
  assert.match(generateToken(), /^sess_/);
});

test("successive tokens are unique", () => {
  assert.notStrictEqual(generateToken(), generateToken());
});
