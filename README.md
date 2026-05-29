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
