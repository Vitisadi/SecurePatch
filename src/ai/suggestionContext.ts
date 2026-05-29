import * as path from "path";
import * as vscode from "vscode";
import { AiSuggestionContext } from "./aiSuggestionProvider";
import { SecurityFinding } from "../types/finding";

export async function buildAiSuggestionContext(finding: SecurityFinding): Promise<AiSuggestionContext> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.filePath));
  const startLine = Math.max(0, finding.line - 10);
  const endLine = Math.min(document.lineCount - 1, finding.line + 10);
  const lines: string[] = [];

  for (let line = startLine; line <= endLine; line++) {
    lines.push(`${line + 1}: ${document.lineAt(line).text}`);
  }

  return {
    finding,
    language: inferLanguage(document, finding.filePath),
    surroundingCode: lines.join("\n")
  };
}

function inferLanguage(document: vscode.TextDocument, filePath: string): string {
  if (document.languageId && document.languageId !== "plaintext") {
    return document.languageId;
  }

  const extension = path.extname(filePath).toLowerCase();

  switch (extension) {
    case ".js":
      return "javascript";
    case ".ts":
      return "typescript";
    case ".py":
      return "python";
    case ".json":
      return "json";
    case ".txt":
      return "requirements";
    default:
      return "unknown";
  }
}
