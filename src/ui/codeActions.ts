import * as vscode from "vscode";
import { FindingsStore } from "./findingsStore";

export class SecurePatchCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly store: FindingsStore) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range
  ): vscode.CodeAction[] {
    return this.store
      .getByFile(document.uri.fsPath)
      .filter((finding) => finding.line === range.start.line)
      .flatMap((finding) => {
        const action = new vscode.CodeAction(
          `[SP] View finding details`,
          vscode.CodeActionKind.QuickFix
        );
        action.diagnostics = [];
        action.command = {
          command: "securepatch.showFindingDetails",
          title: "Show Finding Details",
          arguments: [finding]
        };
        action.isPreferred = false;
        const aiAction = new vscode.CodeAction(
          `[SP] Explain and suggest fix with AI`,
          vscode.CodeActionKind.QuickFix
        );
        aiAction.command = {
          command: "securepatch.explainFindingWithAi",
          title: "Explain Finding With AI",
          arguments: [finding]
        };
        return [action, aiAction];
      });
  }
}
