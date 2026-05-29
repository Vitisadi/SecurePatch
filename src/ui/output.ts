import * as path from "path";
import * as vscode from "vscode";
import { SecurityFinding } from "../types/finding";

export function createOutputChannel(): vscode.OutputChannel {
  return vscode.window.createOutputChannel("SecurePatch AI");
}

export function printFindings(channel: vscode.OutputChannel, findings: SecurityFinding[]): void {
  channel.clear();
  channel.appendLine("SecurePatch AI Scan Results");
  channel.appendLine("===========================");
  channel.appendLine(`Findings: ${findings.length}`);
  channel.appendLine("");

  if (findings.length === 0) {
    channel.appendLine("No findings detected.");
    channel.show(true);
    return;
  }

  for (const finding of findings) {
    channel.appendLine(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    channel.appendLine(`File: ${path.basename(finding.filePath)}:${finding.line + 1}:${finding.column + 1}`);
    channel.appendLine(`Type: ${finding.type}`);
    channel.appendLine(`Description: ${finding.description}`);
    channel.appendLine(`Snippet: ${finding.codeSnippet}`);
    channel.appendLine(`Recommendation: ${finding.recommendation}`);
    channel.appendLine("");
  }

  channel.show(true);
}
