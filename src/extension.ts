import * as vscode from "vscode";
import { OpenAiSuggestionProvider } from "./ai/openAiSuggestionProvider";
import { buildAiSuggestionContext } from "./ai/suggestionContext";
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
import { FindingsTreeProvider, SecurePatchTreeItem } from "./ui/findingsTree";
import { createOutputChannel, printFindings } from "./ui/output";
import {
  acceptPendingFix,
  acceptLatestPendingFix,
  PendingFixCodeLensProvider,
  PendingFixDecorations,
  PendingFixStore,
  rejectPendingFix,
  rejectLatestPendingFix,
  viewPendingFix
} from "./ui/pendingFixes";

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = createDiagnosticCollection();
  const output = createOutputChannel();
  const findingsStore = new FindingsStore();
  const treeProvider = new FindingsTreeProvider(findingsStore);
  const aiProvider = new OpenAiSuggestionProvider(context.secrets);
  const pendingFixStore = new PendingFixStore();
  const pendingFixDecorations = new PendingFixDecorations(pendingFixStore);

  context.subscriptions.push(diagnostics, output, pendingFixDecorations);
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
    vscode.languages.registerCodeLensProvider(
      [
        { language: "javascript", scheme: "file" },
        { language: "typescript", scheme: "file" },
        { language: "python", scheme: "file" }
      ],
      new PendingFixCodeLensProvider(pendingFixStore)
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
      pendingFixStore.clear();
      output.clear();
      vscode.window.showInformationMessage("[SP] SecurePatch AI findings cleared.");
    }),
    vscode.commands.registerCommand("securepatch.openFinding", async (findingOrNode: SecurityFinding | SecurePatchTreeItem) => {
      const finding = unwrapFinding(findingOrNode);
      if (finding) {
        await openFinding(finding);
      }
    }),
    vscode.commands.registerCommand("securepatch.showFindingDetails", async (findingOrNode: SecurityFinding | SecurePatchTreeItem) => {
      const finding = unwrapFinding(findingOrNode);
      await showFindingDetails(finding);
    }),
    vscode.commands.registerCommand("securepatch.explainFindingWithAi", async (findingOrNode: SecurityFinding | SecurePatchTreeItem) => {
      const finding = unwrapFinding(findingOrNode);
      await explainFindingWithAi(finding, aiProvider, pendingFixStore);
    }),
    vscode.commands.registerCommand("securepatch.setOpenAiApiKey", async () => {
      const apiKey = await vscode.window.showInputBox({
        title: "[SP] Set OpenAI API Key",
        prompt: "Enter your OpenAI API key. It will be stored in VS Code SecretStorage.",
        password: true,
        ignoreFocusOut: true
      });

      if (!apiKey) {
        return;
      }

      await aiProvider.setApiKey(apiKey.trim());
      vscode.window.showInformationMessage("[SP] OpenAI API key saved.");
    }),
    vscode.commands.registerCommand("securepatch.clearOpenAiApiKey", async () => {
      await aiProvider.clearApiKey();
      vscode.window.showInformationMessage("[SP] OpenAI API key cleared.");
    }),
    vscode.commands.registerCommand("securepatch.setOpenAiModel", async () => {
      const currentModel = await aiProvider.getModel();
      const model = await vscode.window.showInputBox({
        title: "[SP] Set OpenAI Model",
        prompt: "Use a faster/lower-cost model for AI suggestions.",
        value: currentModel,
        ignoreFocusOut: true
      });

      if (!model) {
        return;
      }

      await aiProvider.setModel(model.trim());
      vscode.window.showInformationMessage(`[SP] OpenAI model set to ${model.trim()}.`);
    }),
    vscode.commands.registerCommand("securepatch.acceptAiFix", async (fixId: string) => {
      await acceptPendingFix(pendingFixStore, fixId);
    }),
    vscode.commands.registerCommand("securepatch.viewAiFix", async (fixId: string) => {
      await viewPendingFix(pendingFixStore, fixId);
    }),
    vscode.commands.registerCommand("securepatch.rejectAiFix", (fixId: string) => {
      rejectPendingFix(pendingFixStore, fixId);
    }),
    vscode.commands.registerCommand("securepatch.acceptLatestAiFix", async () => {
      await acceptLatestPendingFix(pendingFixStore);
    }),
    vscode.commands.registerCommand("securepatch.rejectLatestAiFix", () => {
      rejectLatestPendingFix(pendingFixStore);
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
      pendingFixStore.clearFile(uri.fsPath);
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    void scanDocument(document, diagnostics, findingsStore);
  }
}

function unwrapFinding(value: SecurityFinding | SecurePatchTreeItem | undefined): SecurityFinding | undefined {
  if (!value) {
    return undefined;
  }

  if ("kind" in value) {
    return value.kind === "finding" ? value.finding : undefined;
  }

  return value;
}

async function explainFindingWithAi(
  finding: SecurityFinding | undefined,
  aiProvider: OpenAiSuggestionProvider,
  pendingFixStore: PendingFixStore
): Promise<void> {
  if (!finding) {
    vscode.window.showInformationMessage("[SP] Select a SecurePatch AI finding first.");
    return;
  }

  if (!await aiProvider.hasApiKey()) {
    const action = await vscode.window.showWarningMessage(
      "[SP] OpenAI API key is required for AI suggestions.",
      "Set API Key"
    );

    if (action === "Set API Key") {
      await vscode.commands.executeCommand("securepatch.setOpenAiApiKey");
    }

    return;
  }

  try {
    const suggestion = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "[SP] Generating AI fix suggestion...",
        cancellable: false
      },
      async () => {
        const aiContext = await buildAiSuggestionContext(finding);
        return aiProvider.explainFinding(aiContext);
      }
    );

    const spacerLine = await insertSuggestedLine(finding, suggestion.replacementLine);
    const pendingFix = spacerLine === undefined ? undefined : pendingFixStore.set(finding, suggestion, spacerLine);
    if (pendingFix) {
      await openFinding(finding);
      vscode.window.showInformationMessage("[SP] AI suggested fix inserted above the original line. Use Apply or Reject above the suggestion.");
    } else {
      vscode.window.showInformationMessage("[SP] AI did not provide an auto-applicable one-line fix.");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    vscode.window.showErrorMessage(`[SP] AI suggestion failed: ${message}`);
  }
}

async function insertSuggestedLine(finding: SecurityFinding, replacementLine: string | undefined): Promise<number | undefined> {
  if (!replacementLine) {
    return undefined;
  }

  const uri = vscode.Uri.file(finding.filePath);
  const document = await vscode.workspace.openTextDocument(uri);
  const line = document.lineAt(finding.line);
  const edit = new vscode.WorkspaceEdit();
  const eol = document.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n";
  edit.insert(uri, line.range.start, `${eol}${replacementLine}${eol}`);
  const applied = await vscode.workspace.applyEdit(edit);

  if (!applied) {
    return undefined;
  }

  await document.save();
  return finding.line;
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
