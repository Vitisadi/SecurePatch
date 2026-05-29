import * as vscode from "vscode";
import { AiFixSuggestion } from "../types/aiSuggestion";
import { AiSuggestionContext, AiSuggestionProvider } from "./aiSuggestionProvider";

const apiKeySecretKey = "securepatch.openaiApiKey";
const modelSecretKey = "securepatch.openaiModel";
const defaultModel = "gpt-4.1-mini";

interface OpenAiResponse {
  output_text?: string;
  output?: Array<{
    content?: Array<{
      type?: string;
      text?: string;
    }>;
  }>;
}

export class OpenAiSuggestionProvider implements AiSuggestionProvider {
  constructor(private readonly secrets: vscode.SecretStorage) {}

  async setApiKey(apiKey: string): Promise<void> {
    await this.secrets.store(apiKeySecretKey, apiKey);
  }

  async clearApiKey(): Promise<void> {
    await this.secrets.delete(apiKeySecretKey);
  }

  async setModel(model: string): Promise<void> {
    await this.secrets.store(modelSecretKey, model);
  }

  async getModel(): Promise<string> {
    return await this.secrets.get(modelSecretKey) ?? defaultModel;
  }

  async hasApiKey(): Promise<boolean> {
    return Boolean(await this.secrets.get(apiKeySecretKey));
  }

  async explainFinding(context: AiSuggestionContext): Promise<AiFixSuggestion> {
    const apiKey = await this.secrets.get(apiKeySecretKey);

    if (!apiKey) {
      throw new Error("OpenAI API key is not configured.");
    }
    const model = await this.getModel();

    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model,
        instructions: [
          "You are SecurePatch AI, a security-focused coding assistant inside VS Code.",
          "Explain only the provided finding. Do not invent unrelated vulnerabilities.",
          "Return compact JSON only. Do not wrap it in Markdown.",
          "When safe, return replacementLine as the complete replacement for the vulnerable line only.",
          "Do not return multi-file patches. If a one-line replacement is unsafe, omit replacementLine and explain the limitation."
        ].join(" "),
        input: buildPrompt(context)
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenAI request failed with ${response.status}: ${errorText}`);
    }

    const body = await response.json() as OpenAiResponse;
    return parseSuggestion(extractOutputText(body));
  }
}

function buildPrompt(context: AiSuggestionContext): string {
  const finding = context.finding;

  return JSON.stringify({
    task: "Explain this security finding and suggest a safe fix.",
    requiredJsonShape: {
      explanation: "string",
      risk: "string",
      suggestedFix: "string",
      patchPreview: "optional string",
      replacementLine: "optional string containing the full fixed replacement for the vulnerable line",
      confidence: "low | medium | high",
      limitations: ["string"]
    },
    finding: {
      id: finding.id,
      type: finding.type,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      source: finding.source,
      filePath: finding.filePath,
      line: finding.line + 1,
      column: finding.column + 1,
      codeSnippet: finding.codeSnippet,
      recommendation: finding.recommendation
    },
    language: context.language,
    surroundingCode: context.surroundingCode
  });
}

function extractOutputText(response: OpenAiResponse): string {
  if (response.output_text) {
    return response.output_text;
  }

  const text = response.output
    ?.flatMap((item) => item.content ?? [])
    .map((content) => content.text)
    .filter((value): value is string => Boolean(value))
    .join("\n");

  if (!text) {
    throw new Error("OpenAI response did not include text output.");
  }

  return text;
}

function parseSuggestion(rawText: string): AiFixSuggestion {
  const cleaned = rawText.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  const parsed = JSON.parse(cleaned) as Partial<AiFixSuggestion>;

  return {
    explanation: String(parsed.explanation ?? "No explanation returned."),
    risk: String(parsed.risk ?? "No risk summary returned."),
    suggestedFix: String(parsed.suggestedFix ?? "No fix suggestion returned."),
    patchPreview: parsed.patchPreview ? String(parsed.patchPreview) : undefined,
    replacementLine: parsed.replacementLine ? String(parsed.replacementLine) : undefined,
    confidence: parsed.confidence === "low" || parsed.confidence === "medium" || parsed.confidence === "high"
      ? parsed.confidence
      : "medium",
    limitations: Array.isArray(parsed.limitations) ? parsed.limitations.map(String) : []
  };
}
