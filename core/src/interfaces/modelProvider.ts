/**
 * Provider-agnostic model interface. The VS Code extension uses TS adapters; the
 * research harness implements the equivalent in Python. The shapes are kept
 * aligned so result rows from both surfaces are comparable.
 */
export interface ModelRequest {
  model: string;
  prompt: string;
  system?: string;
  temperature?: number;
  maxOutputTokens?: number;
}

export interface ModelUsage {
  inputTokens?: number;
  outputTokens?: number;
  costUsd?: number;
  latencyMs?: number;
}

export interface ModelResponse {
  text: string;
  usage: ModelUsage;
  /** Untouched provider payload, retained for provenance. */
  raw?: unknown;
}

export interface ModelProvider {
  /** "openai" | "anthropic" | "gemini" | "ollama" | ... */
  readonly id: string;
  complete(request: ModelRequest): Promise<ModelResponse>;
}
