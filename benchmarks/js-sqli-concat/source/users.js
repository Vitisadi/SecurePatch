// Minimal in-memory user directory with a SQL-style lookup.
const USERS = [
  { id: 1, name: "ada" },
  { id: 2, name: "bob" }
];

function execute(query) {
  const match = query.match(/WHERE id = (\d+)/);
  if (!match) {
    return null;
  }
  return USERS.find((user) => user.id === Number(match[1])) || null;
}

function findUser(id) {
  const query = "SELECT * FROM users WHERE id = " + id;
  return execute(query);
}

module.exports = { findUser, execute, USERS };
