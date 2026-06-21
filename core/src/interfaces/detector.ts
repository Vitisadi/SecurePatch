import { SecurityFinding } from "../types/finding";

/**
 * A Detector inspects a single file's content and returns security findings.
 *
 * Implementations must be pure with respect to the editor: no `vscode` imports,
 * no UI. This is what lets the same detector run inside the VS Code extension
 * and inside the headless research harness (via the CLI).
 */
export interface Detector {
  /** Stable identifier used in result rows, e.g. "regex" or "ai:claude". */
  readonly name: string;

  /**
   * Detect findings in `content`. `filePath` is used only to infer language and
   * to label findings; the file is not read from disk here.
   */
  detect(filePath: string, content: string): Promise<SecurityFinding[]>;
}
