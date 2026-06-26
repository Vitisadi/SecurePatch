const test = require("node:test");
const assert = require("node:assert");

const { findUser } = require("../source/users.js");

test("finds an existing user by id", () => {
  assert.strictEqual(findUser(1).name, "ada");
});

test("returns null for a missing user", () => {
  assert.strictEqual(findUser(999), null);
});
