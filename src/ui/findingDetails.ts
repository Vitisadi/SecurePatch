import * as vscode from "vscode";
import { SecurityFinding } from "../types/finding";

export async function openFinding(finding: SecurityFinding): Promise<void> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.filePath));
  const editor = await vscode.window.showTextDocument(document);
  const position = new vscode.Position(finding.line, finding.column);
  const range = new vscode.Range(position, position.translate(0, Math.max(1, finding.codeSnippet.length)));

  editor.selection = new vscode.Selection(position, position);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

export async function showFindingDetails(finding: SecurityFinding | undefined): Promise<void> {
  if (!finding) {
    vscode.window.showInformationMessage("[SP] Select a SecurePatch AI finding first.");
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    "securepatchFindingDetails",
    "[SP] SecurePatch AI Finding Details",
    vscode.ViewColumn.Beside,
    { enableScripts: false }
  );

  panel.webview.html = renderFindingDetails(finding);
}

function renderFindingDetails(finding: SecurityFinding): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
    h1 { font-size: 20px; margin: 0 0 16px; }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 10px 16px; }
    dt { color: var(--vscode-descriptionForeground); }
    dd { margin: 0; }
    pre { background: var(--vscode-textCodeBlock-background); padding: 12px; overflow: auto; }
  </style>
</head>
<body>
  <h1>[SP] ${escapeHtml(finding.title)}</h1>
  <dl>
    <dt>Severity</dt><dd>${escapeHtml(finding.severity)}</dd>
    <dt>File</dt><dd>${escapeHtml(finding.filePath)}</dd>
    <dt>Line</dt><dd>${finding.line + 1}</dd>
    <dt>Description</dt><dd>${escapeHtml(finding.description)}</dd>
    <dt>Recommendation</dt><dd>${escapeHtml(finding.recommendation)}</dd>
  </dl>
  <h2>Code Snippet</h2>
  <pre><code>${escapeHtml(finding.codeSnippet)}</code></pre>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
