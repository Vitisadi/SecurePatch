// Renders a user comment into a DOM node.
function buildCommentHtml(text) {
  return "<p>" + text + "</p>";
}

function renderComment(element, text) {
  element.innerHTML = buildCommentHtml(text);
  return element;
}

module.exports = { buildCommentHtml, renderComment };
