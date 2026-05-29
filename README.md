# SecurePatch AI

SecurePatch AI is a VS Code extension MVP that scans JavaScript, TypeScript, Python, `package.json`, and `requirements.txt` files for basic security patterns.

## Current Scope

- Activates for supported source and dependency files.
- Scans open and changed files.
- Reports findings as VS Code diagnostics.
- Provides `SecurePatch AI: Scan Workspace` to scan supported files in the current workspace.
- Prints findings to the `SecurePatch AI` output channel.

## Supported Files

- `.js`
- `.ts`
- `.py`
- `package.json`
- `requirements.txt`

## MVP Limitations

The scanner is intentionally rule-based and conservative for the first version. It can produce false positives and does not call external vulnerability APIs yet.

## Development

Install dependencies:

```bash
npm install
```

Compile:

```bash
npm run compile
```

Run in VS Code:

1. Open this folder in VS Code.
2. Press `F5` to launch an Extension Development Host.
3. Open or edit a supported file.
4. Run `SecurePatch AI: Scan Workspace` from the Command Palette.

## AI Suggestions

SecurePatch AI can generate an explanation and suggested fix for a selected finding using the OpenAI Responses API.

1. Run `SecurePatch AI: Set OpenAI API Key`.
2. Enter your OpenAI API key. The key is stored with VS Code SecretStorage.
3. Optional: run `SecurePatch AI: Set OpenAI Model` to choose a faster model. The default is `gpt-4.1-mini`.
4. Run `SecurePatch AI: Scan Workspace`.
5. Right-click a finding in `SecurePatch AI Findings`.
6. Select `SecurePatch AI: Explain Finding With AI`.

You can also use the lightbulb Quick Fix menu on a highlighted issue and choose `[SP] Explain and suggest fix with AI`.

If the AI returns a one-line fix, SecurePatch AI inserts a temporary preview line above the original line. The preview line is highlighted green with `[SP +]`, and the original line is highlighted red with `[SP -]`. Use `[SP] Apply` to keep the new line and remove the old one, or `[SP] Reject` to remove the preview line.
