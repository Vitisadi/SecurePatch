import { SecurityFinding } from "../types/finding";
import { AiFixSuggestion } from "../types/aiSuggestion";

export interface AiSuggestionContext {
  finding: SecurityFinding;
  language: string;
  surroundingCode: string;
}

export interface AiSuggestionProvider {
  explainFinding(context: AiSuggestionContext): Promise<AiFixSuggestion>;
}
