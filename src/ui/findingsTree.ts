import * as path from "path";
import * as vscode from "vscode";
import { SecurityFinding } from "../types/finding";
import { FindingsStore } from "./findingsStore";

type TreeItem = FileNode | FindingNode;

interface FileNode {
  kind: "file";
  filePath: string;
  findings: SecurityFinding[];
}

interface FindingNode {
  kind: "finding";
  finding: SecurityFinding;
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<TreeItem | undefined | null | void>();

  readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  constructor(private readonly store: FindingsStore) {
    this.store.onDidChange(() => this.refresh());
  }

  refresh(): void {
    this.onDidChangeTreeDataEmitter.fire();
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    if (element.kind === "file") {
      const item = new vscode.TreeItem(
        `${path.basename(element.filePath)} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.description = path.dirname(element.filePath);
      item.resourceUri = vscode.Uri.file(element.filePath);
      item.contextValue = "securepatchFile";
      item.iconPath = new vscode.ThemeIcon("file");
      return item;
    }

    const finding = element.finding;
    const item = new vscode.TreeItem(
      `[SP] ${finding.severity.toUpperCase()}: ${finding.title}`,
      vscode.TreeItemCollapsibleState.None
    );
    item.description = `line ${finding.line + 1}`;
    item.tooltip = `[SP] ${finding.description}\n\nRecommendation: ${finding.recommendation}`;
    item.contextValue = "securepatchFinding";
    item.iconPath = new vscode.ThemeIcon(iconForSeverity(finding.severity));
    item.command = {
      command: "securepatch.openFinding",
      title: "Open Finding",
      arguments: [finding]
    };
    return item;
  }

  getChildren(element?: TreeItem): TreeItem[] {
    if (element?.kind === "file") {
      return element.findings.map((finding) => ({ kind: "finding", finding }));
    }

    if (element?.kind === "finding") {
      return [];
    }

    return groupFindingsByFile(this.store.getAll());
  }
}

function groupFindingsByFile(findings: SecurityFinding[]): FileNode[] {
  const byFile = new Map<string, SecurityFinding[]>();

  for (const finding of findings) {
    const fileFindings = byFile.get(finding.filePath) ?? [];
    fileFindings.push(finding);
    byFile.set(finding.filePath, fileFindings);
  }

  return [...byFile.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([filePath, fileFindings]) => ({
      kind: "file",
      filePath,
      findings: fileFindings.sort((left, right) => left.line - right.line || left.column - right.column)
    }));
}

function iconForSeverity(severity: SecurityFinding["severity"]): string {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
  }
}
