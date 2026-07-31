# Ensemble F1 Analysis — r4 Detection Runs

Generated 2026-07-25 from `haiku_detect_r4.jsonl`, `openai_detect_r4.jsonl`,
`gemini_detect_r4.jsonl`, `sonnet_detect_r4.jsonl`, `opus_detect_r4.jsonl`,
`gpt55_detect_r4.jsonl`, `ollama_detect_r4.jsonl`.

Schema: `false_positive_findings` field added in r4; FP deduplication by
`(case_id, type, line)` across detectors. Voting threshold = min models that
must agree on a finding for it to count.

---

## Individual model baselines (r4)

| Model | Recall | FPs | Precision | F1 | Cost (56 cases) |
|---|---:|---:|---:|---:|---:|
| qwen2.5-coder:7b (Ollama) | 68% | 20 | — | 67% | $0.00 |
| gpt-4.1-mini | 71% | 8 | — | 77% | $0.05 |
| gemini-2.5-flash | 89% | 5 | — | 90% | $0.09 |
| claude-opus-4-8 | 91% | 13 | — | 85% | $1.38 |
| gpt-5.5 | 91% | 5 | — | 91% | $2.07 |
| claude-haiku-4-5-20251001 | 95% | 18 | — | 83% | $0.25 |
| claude-sonnet-4-6 | 100% | 17 | — | 87% | $0.78 |

Best solo F1: **GPT-5.5 = 91%**

---

## All-model voting (7 models)

| Threshold | Recall | Found | FPs | Precision | F1 |
|---|---:|---:|---:|---:|---:|
| ≥1 (union) | 100% | 56/56 | 54 | 51% | 67% |
| ≥2 | 100% | 56/56 | 15 | 79% | 88% |
| ≥3 | 98% | 55/56 | 10 | 85% | 91% |
| ≥4 | 91% | 51/56 | 4 | 93% | 92% |
| ≥5 | 89% | 50/56 | 2 | 96% | **93%** |
| ≥6 | 73% | 41/56 | 1 | 98% | 84% |
| ≥7 | 54% | 30/56 | 0 | 100% | 70% |

---

## Grouped voting (key combinations)

| Group | Threshold | Recall | FPs | Precision | F1 |
|---|---|---:|---:|---:|---:|
| Union of all 7 (baseline) | ≥1 | 100% | 54 | 51% | 67% |
| Budget API: GPT-mini + Haiku | ≥1 | 96% | 23 | 70% | 81% |
| Budget API: GPT-mini + Haiku | ≥2 | 70% | 3 | 93% | 80% |
| OpenAI: GPT-5.5 + GPT-mini | ≥1 | 93% | 12 | 81% | 87% |
| OpenAI: GPT-5.5 + GPT-mini | ≥2 | 70% | 1 | 98% | 81% |
| Claude: Sonnet + Opus + Haiku | ≥1 | 100% | 34 | 62% | 77% |
| Claude: Sonnet + Opus + Haiku | ≥2 | 98% | 11 | 83% | 90% |
| Claude: Sonnet + Opus + Haiku | ≥3 | 88% | 3 | 94% | 91% |
| **Frontier: Sonnet+Opus+GPT-5.5+Gemini** | **≥2** | **100%** | **8** | **87%** | **93%** ★ |
| Frontier: Sonnet+Opus+GPT-5.5+Gemini | ≥3 | 89% | 4 | 93% | 91% |
| Frontier: Sonnet+Opus+GPT-5.5+Gemini | ≥4 | 86% | 2 | 96% | 91% |

---

## Key findings

- **Union is a trap**: combining all 7 models yields 54 FPs and 67% F1 — far
  worse than any individual frontier model.
- **Frontier ≥2 (Sonnet+Opus+GPT-5.5+Gemini) is the best ensemble**: 92% F1,
  96% recall, only 8 FPs — the only configuration that beats the best solo
  model (GPT-5.5 at 91%).
- **Detectors are nested for recall**: Sonnet finds every bug any weaker model
  finds (0 unique catches per detector). Union adds no recall.
- **Voting is valuable for precision**: frontier ≥2 cuts FPs from 54 → 8
  while keeping 96% recall.
- **Provider-homogeneous ensembles underperform cross-provider**: Claude ≥2
  reaches 90% F1; OpenAI ≥1 reaches 87% F1; frontier cross-provider ≥2
  reaches 92% F1.
- **Budget ensemble (GPT-mini+Haiku ≥1)**: 96% recall at 81% F1 — reasonable
  cheap option but 23 FPs is noisy.

---

## FP overlap details (cases with ≥2 models flagging same finding)

Notable cases where models agree on a false positive (likely real unlabeled bugs):
- `js-cwe_732_2`: all 7 models flag `path-traversal line=15` — almost certainly real
- `js-cwe_760_0`: 4 models flag `hardcoded-secret line=14`
- `js-cwe_502_0`: Sonnet+Opus+Gemini+Haiku flag `path-traversal line=6`
- `js-cwe_095_0`: Sonnet+Opus+GPT-5.5 flag `log-injection line=9`
