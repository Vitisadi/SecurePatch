import * as path from "path";
import * as vscode from "vscode";
import { AiFixSuggestion } from "../types/aiSuggestion";
import { SecurityFinding } from "../types/finding";

export interface PendingFix {
  id: string;
  finding: SecurityFinding;
  suggestion: AiFixSuggestion;
  spacerLine: number;
  insertedLine: number;
  originalLine: number;
}

export class PendingFixStore {
  private readonly fixesByFile = new Map<string, PendingFix[]>();
  private readonly onDidChangeEmitter = new vscode.EventEmitter<void>();

  readonly onDidChange = this.onDidChangeEmitter.event;

  set(finding: SecurityFinding, suggestion: AiFixSuggestion, spacerLine: number): PendingFix | undefined {
    if (!suggestion.replacementLine) {
      return undefined;
    }

    const pendingFix: PendingFix = {
      id: `${finding.filePath}:${finding.line}:${finding.column}:${Date.now()}`,
      finding,
      suggestion,
      spacerLine,
      insertedLine: spacerLine + 1,
      originalLine: spacerLine + 2
    };
    const fixes = this.fixesByFile.get(finding.filePath) ?? [];
    const updated = fixes.filter((fix) => fix.finding.line !== finding.line && fix.originalLine !== spacerLine + 2);
    updated.push(pendingFix);
    this.fixesByFile.set(finding.filePath, updated);
    this.onDidChangeEmitter.fire();
    return pendingFix;
  }

  getByFile(filePath: string): PendingFix[] {
    return this.fixesByFile.get(filePath) ?? [];
  }

  getLatest(): PendingFix | undefined {
    return [...this.fixesByFile.values()].flat().at(-1);
  }

  getForPosition(filePath: string, line: number): PendingFix | undefined {
    return this.getByFile(filePath).find((fix) => fix.insertedLine === line || fix.originalLine === line);
  }

  getById(id: string): PendingFix | undefined {
    for (const fixes of this.fixesByFile.values()) {
      const match = fixes.find((fix) => fix.id === id);
      if (match) {
        return match;
      }
    }

    return undefined;
  }

  delete(id: string): void {
    for (const [filePath, fixes] of this.fixesByFile.entries()) {
      const updated = fixes.filter((fix) => fix.id !== id);
      if (updated.length === 0) {
        this.fixesByFile.delete(filePath);
      } else {
        this.fixesByFile.set(filePath, updated);
      }
    }

    this.onDidChangeEmitter.fire();
  }

  clearFile(filePath: string): void {
    this.fixesByFile.delete(filePath);
    this.onDidChangeEmitter.fire();
  }

  clear(): void {
    this.fixesByFile.clear();
    this.onDidChangeEmitter.fire();
  }
}

export class PendingFixCodeLensProvider implements vscode.CodeLensProvider {
  private readonly onDidChangeCodeLensesEmitter = new vscode.EventEmitter<void>();

  readonly onDidChangeCodeLenses = this.onDidChangeCodeLensesEmitter.event;

  constructor(private readonly store: PendingFixStore) {
    this.store.onDidChange(() => this.onDidChangeCodeLensesEmitter.fire());
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    return this.store.getByFile(document.uri.fsPath).flatMap((fix) => {
      const range = new vscode.Range(fix.spacerLine, 0, fix.spacerLine, 0);
      return [
        new vscode.CodeLens(range, {
          command: "securepatch.acceptAiFix",
          title: "[SP] Apply",
          arguments: [fix.id]
        }),
        new vscode.CodeLens(range, {
          command: "securepatch.rejectAiFix",
          title: "[SP] Reject",
          arguments: [fix.id]
        })
      ];
    });
  }
}

export class PendingFixDecorations {
  private readonly insertedLineDecoration = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(45, 180, 95, 0.22)",
    border: "1px solid rgba(85, 220, 135, 0.75)",
    overviewRulerColor: "rgba(45, 180, 95, 0.85)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    before: {
      contentText: "[SP +] ",
      color: "#8ff0a4",
      fontWeight: "700"
    }
  });
  private readonly originalLineDecoration = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: "rgba(255, 80, 80, 0.20)",
    border: "1px solid rgba(255, 120, 120, 0.65)",
    overviewRulerColor: "rgba(255, 80, 80, 0.85)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    before: {
      contentText: "[SP -] ",
      color: "#ff8a8a",
      fontWeight: "700"
    }
  });

  constructor(private readonly store: PendingFixStore) {
    this.store.onDidChange(() => this.refreshVisibleEditors());
    vscode.window.onDidChangeVisibleTextEditors(() => this.refreshVisibleEditors());
  }

  refreshVisibleEditors(): void {
    for (const editor of vscode.window.visibleTextEditors) {
      const fixes = this.store.getByFile(editor.document.uri.fsPath);
      editor.setDecorations(this.insertedLineDecoration, fixes.map((fix) => editor.document.lineAt(fix.insertedLine).range));
      editor.setDecorations(this.originalLineDecoration, fixes.map((fix) => editor.document.lineAt(fix.originalLine).range));
    }
  }

  dispose(): void {
    this.insertedLineDecoration.dispose();
    this.originalLineDecoration.dispose();
  }
}

export async function acceptPendingFix(store: PendingFixStore, fixId: string): Promise<void> {
  const fix = store.getById(fixId);

  if (!fix?.suggestion.replacementLine) {
    vscode.window.showInformationMessage("[SP] No pending fix found.");
    return;
  }

  const uri = vscode.Uri.file(fix.finding.filePath);
  const document = await vscode.workspace.openTextDocument(uri);
  const insertedLine = document.lineAt(fix.insertedLine);
  const originalLine = document.lineAt(fix.originalLine);
  const edit = new vscode.WorkspaceEdit();
  edit.delete(uri, originalLine.rangeIncludingLineBreak);
  edit.delete(uri, document.lineAt(fix.spacerLine).rangeIncludingLineBreak);
  edit.replace(uri, insertedLine.range, fix.suggestion.replacementLine);
  const applied = await vscode.workspace.applyEdit(edit);

  if (!applied) {
    vscode.window.showErrorMessage("[SP] Failed to apply AI suggested fix.");
    return;
  }

  await document.save();
  store.delete(fixId);
  vscode.window.showInformationMessage(`[SP] Applied fix in ${path.basename(fix.finding.filePath)}.`);
}

export async function acceptLatestPendingFix(store: PendingFixStore): Promise<void> {
  const fix = store.getLatest();
  if (!fix) {
    vscode.window.showInformationMessage("[SP] No pending AI fix found.");
    return;
  }

  await acceptPendingFix(store, fix.id);
}

export async function viewPendingFix(store: PendingFixStore, fixId: string): Promise<void> {
  const fix = store.getById(fixId);

  if (!fix?.suggestion.replacementLine) {
    vscode.window.showInformationMessage("[SP] No pending fix found.");
    return;
  }

  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(fix.finding.filePath));
  const currentLine = document.lineAt(fix.originalLine).text;
  const choice = await vscode.window.showInformationMessage(
    `[SP] Suggested fix for line ${fix.finding.line + 1}\n\nCurrent: ${currentLine}\n\nSuggested: ${fix.suggestion.replacementLine}`,
    { modal: true },
    "Apply",
    "Reject"
  );

  if (choice === "Apply") {
    await acceptPendingFix(store, fixId);
  } else if (choice === "Reject") {
    rejectPendingFix(store, fixId);
  }
}

export function rejectPendingFix(store: PendingFixStore, fixId: string): void {
  const fix = store.getById(fixId);
  if (fix) {
    void removeInsertedLine(fix).then(() => store.delete(fixId));
    vscode.window.showInformationMessage("[SP] Rejected AI suggested fix.");
    return;
  }
  store.delete(fixId);
  vscode.window.showInformationMessage("[SP] Rejected AI suggested fix.");
}

export function rejectLatestPendingFix(store: PendingFixStore): void {
  const fix = store.getLatest();
  if (!fix) {
    vscode.window.showInformationMessage("[SP] No pending AI fix found.");
    return;
  }

  rejectPendingFix(store, fix.id);
}

async function removeInsertedLine(fix: PendingFix): Promise<void> {
  const uri = vscode.Uri.file(fix.finding.filePath);
  const document = await vscode.workspace.openTextDocument(uri);
  const edit = new vscode.WorkspaceEdit();
  edit.delete(uri, document.lineAt(fix.spacerLine).rangeIncludingLineBreak);
  edit.delete(uri, document.lineAt(fix.insertedLine).rangeIncludingLineBreak);
  await vscode.workspace.applyEdit(edit);
  await document.save();
}
