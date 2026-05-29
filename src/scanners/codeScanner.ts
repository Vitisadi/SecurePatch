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
    id: "py-subprocess-shell-true",
    type: "command-injection",
    title: "subprocess shell=True",
    description: "subprocess with shell=True can expose command injection risks.",
    severity: "high",
    recommendation: "Pass arguments as a list and keep shell=False.",
    source: "code",
    pattern: /\bsubprocess\.(run|call|Popen|check_call|check_output)\s*\([\s\S]*shell\s*=\s*True/i
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
  }
];

const secretPattern = /\b(api_key|apikey|token|password|secret)\b\s*[:=]\s*["'`][^"'`]{8,}["'`]/i;

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

  return findings;
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
