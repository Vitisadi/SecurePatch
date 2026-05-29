import * as vscode from "vscode";
import { SecurityFinding } from "../types/finding";

export class FindingsStore {
  private readonly findingsByFile = new Map<string, SecurityFinding[]>();
  private readonly onDidChangeEmitter = new vscode.EventEmitter<void>();

  readonly onDidChange = this.onDidChangeEmitter.event;

  getAll(): SecurityFinding[] {
    return [...this.findingsByFile.values()].flat();
  }

  getByFile(filePath: string): SecurityFinding[] {
    return this.findingsByFile.get(filePath) ?? [];
  }

  setForFile(filePath: string, findings: SecurityFinding[]): void {
    if (findings.length === 0) {
      this.findingsByFile.delete(filePath);
    } else {
      this.findingsByFile.set(filePath, findings);
    }

    this.onDidChangeEmitter.fire();
  }

  clearFile(filePath: string): void {
    this.findingsByFile.delete(filePath);
    this.onDidChangeEmitter.fire();
  }

  clear(): void {
    this.findingsByFile.clear();
    this.onDidChangeEmitter.fire();
  }
}
