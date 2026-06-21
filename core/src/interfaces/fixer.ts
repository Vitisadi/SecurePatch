import { SecurityFinding } from "../types/finding";

/**
 * A single edit a fixer proposes for one file. Either `newContent` (the full
 * replacement file body) or `unifiedDiff` should be set. Multi-file fixes are
 * expressed as multiple FixEdits.
 */
export interface FixEdit {
  filePath: string;
  newContent?: string;
  unifiedDiff?: string;
}

export interface FixRequest {
  finding: SecurityFinding;
  /** e.g. "javascript", "typescript", "python". */
  language: string;
  /** Numbered surrounding lines, the same context the extension builds today. */
  surroundingCode: string;
}

export interface FixResult {
  explanation: string;
  edits: FixEdit[];
  confidence: "low" | "medium" | "high";
  limitations: string[];
}

/**
 * A Fixer turns a finding into one or more concrete edits. The current
 * extension only produces single-line replacements; this interface generalizes
 * to the multi-line / multi-file patches the research harness will evaluate.
 */
export interface Fixer {
  readonly name: string;
  fix(request: FixRequest): Promise<FixResult>;
}
