import * as vscode from "vscode";
import { SecurityFinding } from "../types/finding";

export function createDiagnosticCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection("securepatch-ai");
}

export function setDiagnosticsForFile(
  collection: vscode.DiagnosticCollection,
  uri: vscode.Uri,
  findings: SecurityFinding[]
): void {
  const diagnostics = findings.map(toDiagnostic);
  collection.set(uri, diagnostics);
}

export function clearDiagnosticsForFile(collection: vscode.DiagnosticCollection, uri: vscode.Uri): void {
  collection.delete(uri);
}

function toDiagnostic(finding: SecurityFinding): vscode.Diagnostic {
  const range = new vscode.Range(
    finding.line,
    finding.column,
    finding.line,
    Math.max(finding.column + 1, finding.column + finding.codeSnippet.length)
  );
  const diagnostic = new vscode.Diagnostic(
    range,
    `[SP] ${finding.title}. ${finding.recommendation}`,
    toDiagnosticSeverity(finding.severity)
  );

  diagnostic.code = finding.id;
  diagnostic.source = "[SP] SecurePatch AI";
  diagnostic.relatedInformation = [
    new vscode.DiagnosticRelatedInformation(
      new vscode.Location(vscode.Uri.file(finding.filePath), range),
      finding.description
    )
  ];

  return diagnostic;
}

function toDiagnosticSeverity(severity: SecurityFinding["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}
