// Builds a report query from a base template and a user-supplied filter.
const BASE_QUERY = "SELECT name, total FROM orders WHERE region = ";

const ROWS = [
  { region: "us", name: "ada", total: 10 },
  { region: "eu", name: "bob", total: 20 }
];

function buildQuery(region) {
  return BASE_QUERY + "'" + region + "'";
}

function execute(query) {
  const match = query.match(/region = '([^']*)'/);
  if (!match) {
    return [];
  }
  return ROWS.filter((row) => row.region === match[1]);
}

function reportForRegion(region) {
  return execute(buildQuery(region));
}

module.exports = { buildQuery, execute, reportForRegion, ROWS };
