import * as path from "path";
import { SecurityFinding } from "../types/finding";

interface Rule {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: SecurityFinding["severity"];
  recommendation: string;
  source: SecurityFinding["source"];
  pattern: RegExp;
}

const jsTsRules: Rule[] = [
  {
    id: "js-sql-concat",
    type: "sql-injection",
    title: "Possible SQL injection",
    description: "SQL text appears to be built with string concatenation or template interpolation.",
    severity: "high",
    recommendation: "Use parameterized queries instead of string concatenation.",
    source: "code",
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*(\+|\$\{)/i
  },
  {
    id: "js-child-process-exec",
    type: "command-injection",
    title: "Possible command injection",
    description: "child_process.exec can execute shell commands built from unsafe input.",
    severity: "high",
    recommendation: "Use execFile or spawn with argument arrays and validate user-controlled input.",
    source: "code",
    pattern: /\b(exec|child_process\.exec)\s*\([^"'`]*[a-zA-Z_$][\w$]*/i
  },
  {
    id: "js-math-random-security",
    type: "weak-randomness",
    title: "Weak randomness in security-sensitive context",
    description: "Math.random is not suitable for tokens, secrets, passwords, or cryptographic values.",
    severity: "medium",
    recommendation: "Use crypto.randomBytes or crypto.getRandomValues for security-sensitive randomness.",
    source: "code",
    pattern: /(token|secret|password|apiKey|api_key|nonce|session).{0,80}Math\.random|Math\.random.{0,80}(token|secret|password|apiKey|api_key|nonce|session)/i
  },
  {
    id: "js-inner-html",
    type: "xss",
    title: "Possible cross-site scripting",
    description: "Assigning to innerHTML can introduce XSS if the value contains untrusted input.",
    severity: "medium",
    recommendation: "Use textContent or sanitize input before inserting HTML.",
    source: "code",
    pattern: /\.innerHTML\s*=/
  },
  {
    id: "js-eval",
    type: "code-injection",
    title: "Possible code injection",
    description: "eval executes arbitrary code and is dangerous on untrusted input.",
    severity: "high",
    recommendation: "Avoid eval; use a safe parser or an explicit allow-list of operations.",
    source: "code",
    pattern: /\beval\s*\(/
  },
  {
    id: "js-unsafe-yaml-load",
    type: "deserialization",
    title: "Unsafe YAML deserialization",
    description: "yaml.load can instantiate arbitrary types from untrusted input.",
    severity: "high",
    recommendation: "Use a safe schema (e.g. yaml.load with JSON_SCHEMA / safeLoad).",
    source: "code",
    pattern: /\byaml\.load\s*\(/
  },
  {
    id: "js-unserialize",
    type: "deserialization",
    title: "Unsafe deserialization",
    description: "unserialize on untrusted input can lead to remote code execution.",
    severity: "high",
    recommendation: "Avoid node-serialize/unserialize on untrusted data; use JSON.",
    source: "code",
    pattern: /\bunserialize\s*\(/
  }
];

const pythonRules: Rule[] = [
  {
    id: "py-os-system",
    type: "command-injection",
    title: "Possible command injection",
    description: "os.system can execute shell commands built from unsafe input.",
    severity: "high",
    recommendation: "Use subprocess with argument arrays and shell=False.",
    source: "code",
    pattern: /\bos\.system\s*\([^"' \)]*[a-zA-Z_]\w*/i
  },
  {
    id: "py-random-security",
    type: "weak-randomness",
    title: "Weak randomness in security-sensitive context",
    description: "The random module is not suitable for tokens, secrets, passwords, or cryptographic values.",
    severity: "medium",
    recommendation: "Use the secrets module for security-sensitive randomness.",
    source: "code",
    pattern: /(token|secret|password|api_key|nonce|session).{0,80}random\.|random\..{0,80}(token|secret|password|api_key|nonce|session)/i
  },
  {
    id: "py-weak-hash",
    type: "weak-cryptography",
    title: "Weak hash algorithm",
    description: "MD5 and SHA-1 are weak for security-sensitive hashing.",
    severity: "medium",
    recommendation: "Use bcrypt, argon2, or SHA-256 depending on the use case.",
    source: "code",
    pattern: /\bhashlib\.(md5|sha1)\s*\(/i
  },
  {
    id: "py-eval-exec",
    type: "code-injection",
    title: "Possible code injection",
    description: "eval/exec execute arbitrary code and are dangerous on untrusted input.",
    severity: "high",
    recommendation: "Avoid eval/exec; use ast.literal_eval or an explicit parser.",
    source: "code",
    pattern: /\b(eval|exec)\s*\(/
  },
  {
    id: "py-unsafe-yaml-load",
    type: "deserialization",
    title: "Unsafe YAML deserialization",
    description: "yaml.load without SafeLoader can construct arbitrary Python objects.",
    severity: "high",
    recommendation: "Use yaml.safe_load or Loader=SafeLoader.",
    source: "code",
    pattern: /\byaml\.load\s*\((?![^)]*SafeLoader)/i
  },
  {
    id: "py-pickle-loads",
    type: "deserialization",
    title: "Unsafe deserialization",
    description: "pickle can execute arbitrary code while deserializing untrusted data.",
    severity: "high",
    recommendation: "Avoid pickle on untrusted data; use json or a vetted format.",
    source: "code",
    pattern: /\bpickle\.loads?\s*\(/
  },
  {
    id: "py-sql-concat",
    type: "sql-injection",
    title: "Possible SQL injection",
    description: "SQL text appears to be built with concatenation, formatting, or an f-string.",
    severity: "high",
    recommendation: "Use parameterized queries instead of building SQL from input.",
    source: "code",
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|%|\.format\(|f["'])/i
  },
  {
    id: "py-weak-rsa-key",
    type: "weak-cryptography",
    title: "Weak RSA key size",
    description: "RSA keys smaller than 2048 bits are considered insecure.",
    severity: "medium",
    recommendation: "Generate RSA keys of at least 2048 bits.",
    source: "code",
    pattern: /\bRSA\.generate\s*\(\s*(512|768|1024)\b/
  },
  {
    id: "py-ecb-mode",
    type: "weak-cryptography",
    title: "Insecure ECB cipher mode",
    description: "ECB mode leaks plaintext structure and is not semantically secure.",
    severity: "medium",
    recommendation: "Use an authenticated mode such as AES-GCM.",
    source: "code",
    pattern: /\bMODE_ECB\b/
  },
  {
    id: "py-static-iv",
    type: "weak-cryptography",
    title: "Static/zero initialization vector",
    description: "A hardcoded or all-zero IV defeats the security of CBC/CTR modes.",
    severity: "medium",
    recommendation: "Generate a fresh random IV per encryption (e.g. get_random_bytes).",
    source: "code",
    pattern: /\biv\s*=\s*b?["'](\\x00)/i
  },
  {
    id: "py-weak-cipher",
    type: "weak-cryptography",
    title: "Weak cipher algorithm",
    description: "DES, 3DES, RC4, and Blowfish are considered broken or weak.",
    severity: "medium",
    recommendation: "Use AES (GCM) or another modern, vetted cipher.",
    source: "code",
    pattern: /\b(DES|DES3|ARC4|Blowfish)\.new\s*\(/
  },
  {
    id: "py-password-fast-hash",
    type: "weak-cryptography",
    title: "Fast hash used for passwords",
    description: "General-purpose SHA-2 hashes are too fast for password storage.",
    severity: "medium",
    recommendation: "Use a slow KDF such as bcrypt, scrypt, or argon2.",
    source: "code",
    pattern: /(password|passwd|pwd)[\s\S]{0,40}hashlib\.(sha224|sha256|sha384|sha512)|hashlib\.(sha224|sha256|sha384|sha512)\s*\([^)]{0,40}(password|passwd|pwd)/i
  }
];

// Rules evaluated against the whole file (not line by line) so they can match
// calls that span multiple lines, e.g. subprocess(..., shell=True) wrapped
// across lines. The match offset is mapped back to a line number.
const pythonMultilineRules: Rule[] = [
  {
    id: "py-subprocess-shell-true",
    type: "command-injection",
    title: "subprocess shell=True",
    description: "subprocess with shell=True can expose command injection risks.",
    severity: "high",
    recommendation: "Pass arguments as a list and keep shell=False.",
    source: "code",
    pattern: /\bsubprocess\.(run|call|Popen|check_call|check_output)\s*\([\s\S]{0,200}?shell\s*=\s*True/i
  }
];

// The value must be a real literal, not a template interpolation such as
// `password = '${password}'` (which is data flow, not a hardcoded credential).
const secretPattern = /\b(api_key|apikey|token|password|secret)\b\s*[:=]\s*["'`](?!\$\{)[^"'`]{8,}["'`]/i;

export function scanCode(filePath: string, content: string): SecurityFinding[] {
  const extension = path.extname(filePath).toLowerCase();
  const rules = extension === ".py" ? pythonRules : jsTsRules;
  const findings: SecurityFinding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, index) => {
    for (const rule of rules) {
      const match = lineText.match(rule.pattern);
      if (match) {
        findings.push(createFinding(rule, filePath, index, match.index ?? 0, lineText));
      }
    }

    const secretMatch = lineText.match(secretPattern);
    if (secretMatch) {
      findings.push(createFinding({
        id: `${extension === ".py" ? "py" : "js"}-hardcoded-secret`,
        type: "hardcoded-secret",
        title: "Possible hardcoded secret",
        description: "A credential-like value appears to be hardcoded in source code.",
        severity: "critical",
        recommendation: "Move secrets to a secure secret manager or environment variable.",
        source: "code",
        pattern: secretPattern
      }, filePath, index, secretMatch.index ?? 0, lineText));
    }
  });

  if (extension === ".py") {
    for (const rule of pythonMultilineRules) {
      const match = content.match(rule.pattern);
      if (match && match.index !== undefined) {
        const line = content.slice(0, match.index).split(/\r?\n/).length - 1;
        findings.push(createFinding(rule, filePath, line, 0, lines[line] ?? ""));
      }
    }
  }

  return dedupeByTypeAndLine(findings);
}

// Overlapping rules (e.g. the generic weak-hash rule and the password-specific
// one, or the line and multiline subprocess passes) can flag the same issue
// twice. Collapse findings that share a type and line so one labeled bug is not
// counted as a true positive plus a false positive.
function dedupeByTypeAndLine(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.type}:${finding.line}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function createFinding(rule: Rule, filePath: string, line: number, column: number, codeSnippet: string): SecurityFinding {
  return {
    id: rule.id,
    type: rule.type,
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    filePath,
    line,
    column,
    codeSnippet: codeSnippet.trim(),
    recommendation: rule.recommendation,
    source: rule.source
  };
}
