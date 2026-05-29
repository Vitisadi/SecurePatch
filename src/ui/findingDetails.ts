import * as vscode from "vscode";
import { AiFixSuggestion } from "../types/aiSuggestion";
import { SecurityFinding } from "../types/finding";

export async function openFinding(finding: SecurityFinding): Promise<void> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.filePath));
  const editor = await vscode.window.showTextDocument(document);
  const position = new vscode.Position(finding.line, finding.column);
  const range = new vscode.Range(position, position.translate(0, Math.max(1, finding.codeSnippet.length)));

  editor.selection = new vscode.Selection(position, position);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

export async function showFindingDetails(
  finding: SecurityFinding | undefined,
  aiSuggestion?: AiFixSuggestion
): Promise<void> {
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

  panel.webview.html = renderFindingDetails(finding, aiSuggestion);
}

function renderFindingDetails(finding: SecurityFinding, aiSuggestion?: AiFixSuggestion): string {
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
    section { margin-top: 24px; }
    .confidence { text-transform: uppercase; font-weight: 600; }
    ul { margin-top: 8px; padding-left: 20px; }
    li { margin-bottom: 8px; }
    .muted { color: var(--vscode-descriptionForeground); }
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
  ${renderDependencyMetadata(finding)}
  <h2>Code Snippet</h2>
  <pre><code>${escapeHtml(finding.codeSnippet)}</code></pre>
  ${aiSuggestion ? renderAiSuggestion(aiSuggestion) : ""}
</body>
</html>`;
}

function renderDependencyMetadata(finding: SecurityFinding): string {
  const metadata = finding.metadata;
  if (finding.source !== "dependency" || !metadata) {
    return "";
  }

  const summaries = metadata.vulnerabilitySummaries ?? [];
  return `<section>
  <h2>Dependency Vulnerability Details</h2>
  <dl>
    <dt>Package</dt><dd>${escapeHtml(metadata.packageName ?? "Unknown")}</dd>
    <dt>Current Version</dt><dd>${escapeHtml(metadata.currentVersion ?? "Unknown")}</dd>
    <dt>OSV Findings</dt><dd>${metadata.vulnerabilityCount ?? summaries.length}</dd>
    <dt>Fixed Version</dt><dd>${escapeHtml(metadata.fixedVersion ?? "Not listed by OSV")}</dd>
  </dl>
  ${metadata.vulnerabilityIds?.length ? `<p class="muted">IDs: ${escapeHtml(metadata.vulnerabilityIds.join(", "))}</p>` : ""}
  ${summaries.length ? `<h3>What OSV Found</h3><ul>${summaries.map((item) => `<li><strong>${escapeHtml(item.id)}</strong>: ${escapeHtml(item.summary)}</li>`).join("")}</ul>` : ""}
</section>`;
}

function renderAiSuggestion(suggestion: AiFixSuggestion): string {
  return `<section>
  <h2>[SP] AI Suggested Fix</h2>
  <dl>
    <dt>Explanation</dt><dd>${escapeHtml(suggestion.explanation)}</dd>
    <dt>Risk</dt><dd>${escapeHtml(suggestion.risk)}</dd>
    <dt>Suggested Fix</dt><dd>${escapeHtml(suggestion.suggestedFix)}</dd>
    <dt>Confidence</dt><dd class="confidence">${escapeHtml(suggestion.confidence)}</dd>
  </dl>
  ${suggestion.patchPreview ? `<h3>Patch Preview</h3><pre><code>${escapeHtml(suggestion.patchPreview)}</code></pre>` : ""}
  ${suggestion.limitations.length > 0 ? `<h3>Limitations</h3><ul>${suggestion.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
</section>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
