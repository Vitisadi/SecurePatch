import * as vscode from "vscode";
import { isSupportedFile, scanFile } from "./scanners";
import { SecurityFinding } from "./types/finding";
import {
  clearDiagnosticsForFile,
  createDiagnosticCollection,
  setDiagnosticsForFile
} from "./ui/diagnostics";
import { SecurePatchCodeActionProvider } from "./ui/codeActions";
import { openFinding, showFindingDetails } from "./ui/findingDetails";
import { FindingsStore } from "./ui/findingsStore";
import { FindingsTreeProvider } from "./ui/findingsTree";
import { createOutputChannel, printFindings } from "./ui/output";

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = createDiagnosticCollection();
  const output = createOutputChannel();
  const findingsStore = new FindingsStore();
  const treeProvider = new FindingsTreeProvider(findingsStore);

  context.subscriptions.push(diagnostics, output);
  context.subscriptions.push(vscode.window.registerTreeDataProvider("securepatch.findings", treeProvider));
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { language: "javascript", scheme: "file" },
        { language: "typescript", scheme: "file" },
        { language: "python", scheme: "file" },
        { pattern: "**/package.json", scheme: "file" },
        { pattern: "**/requirements.txt", scheme: "file" }
      ],
      new SecurePatchCodeActionProvider(findingsStore),
      { providedCodeActionKinds: SecurePatchCodeActionProvider.providedCodeActionKinds }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("securepatch.scanWorkspace", async () => {
      const findings = await scanWorkspace(diagnostics, findingsStore);
      printFindings(output, findings);
      vscode.window.showInformationMessage(`[SP] SecurePatch AI scan complete: ${findings.length} finding(s).`);
    }),
    vscode.commands.registerCommand("securepatch.clearFindings", () => {
      diagnostics.clear();
      findingsStore.clear();
      output.clear();
      vscode.window.showInformationMessage("[SP] SecurePatch AI findings cleared.");
    }),
    vscode.commands.registerCommand("securepatch.openFinding", async (finding: SecurityFinding) => {
      await openFinding(finding);
    }),
    vscode.commands.registerCommand("securepatch.showFindingDetails", async (finding: SecurityFinding) => {
      await showFindingDetails(finding);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => scanDocument(document, diagnostics, findingsStore)),
    vscode.workspace.onDidChangeTextDocument((event) => scanDocument(event.document, diagnostics, findingsStore)),
    vscode.workspace.onDidSaveTextDocument((document) => scanDocument(document, diagnostics, findingsStore))
  );

  const watcher = vscode.workspace.createFileSystemWatcher(
    "{**/*.js,**/*.ts,**/*.py,**/package.json,**/requirements.txt}"
  );
  context.subscriptions.push(
    watcher,
    watcher.onDidChange((uri) => scanUri(uri, diagnostics, findingsStore)),
    watcher.onDidCreate((uri) => scanUri(uri, diagnostics, findingsStore)),
    watcher.onDidDelete((uri) => {
      clearDiagnosticsForFile(diagnostics, uri);
      findingsStore.clearFile(uri.fsPath);
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    void scanDocument(document, diagnostics, findingsStore);
  }
}

export function deactivate(): void {
  // VS Code disposes registered subscriptions automatically.
}

async function scanWorkspace(
  diagnostics: vscode.DiagnosticCollection,
  findingsStore: FindingsStore
): Promise<SecurityFinding[]> {
  const files = await vscode.workspace.findFiles(
    "{**/*.js,**/*.ts,**/*.py,**/package.json,**/requirements.txt}",
    "{**/node_modules/**,**/out/**,**/.git/**,**/.venv/**,**/venv/**}"
  );
  const allFindings: SecurityFinding[] = [];

  diagnostics.clear();
  findingsStore.clear();

  for (const uri of files) {
    const document = await vscode.workspace.openTextDocument(uri);
    const findings = await scanDocument(document, diagnostics, findingsStore);
    allFindings.push(...findings);
  }

  return allFindings;
}

async function scanDocument(
  document: vscode.TextDocument,
  diagnostics: vscode.DiagnosticCollection,
  findingsStore: FindingsStore
): Promise<SecurityFinding[]> {
  if (document.uri.scheme !== "file" || !isSupportedFile(document.uri.fsPath)) {
    return [];
  }

  const findings = await scanFile(document.uri.fsPath, document.getText());
  setDiagnosticsForFile(diagnostics, document.uri, findings);
  findingsStore.setForFile(document.uri.fsPath, findings);
  return findings;
}

async function scanUri(
  uri: vscode.Uri,
  diagnostics: vscode.DiagnosticCollection,
  findingsStore: FindingsStore
): Promise<SecurityFinding[]> {
  if (uri.scheme !== "file" || !isSupportedFile(uri.fsPath)) {
    return [];
  }

  const document = await vscode.workspace.openTextDocument(uri);
  return scanDocument(document, diagnostics, findingsStore);
}
