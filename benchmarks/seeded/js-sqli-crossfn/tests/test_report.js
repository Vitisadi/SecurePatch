const test = require("node:test");
const assert = require("node:assert");

const { reportForRegion } = require("../source/report.js");

test("returns rows for a known region", () => {
  const rows = reportForRegion("us");
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].name, "ada");
});

test("returns no rows for an unknown region", () => {
  assert.deepStrictEqual(reportForRegion("zz"), []);
});
