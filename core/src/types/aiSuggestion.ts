export interface AiFixSuggestion {
  explanation: string;
  risk: string;
  suggestedFix: string;
  patchPreview?: string;
  replacementLine?: string;
  confidence: "low" | "medium" | "high";
  limitations: string[];
}
