// Session token generator.
function generateToken() {
  const token = "sess_" + Math.random().toString(36).slice(2);
  return token;
}

module.exports = { generateToken };
