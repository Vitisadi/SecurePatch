import * as path from "path";
import { SecurityFinding } from "../types/finding";

interface DependencyRule {
  packageName: string;
  safeVersion: string;
  ecosystem: "npm" | "pypi";
}

const npmRules: DependencyRule[] = [
  { packageName: "express", safeVersion: "4.18.0", ecosystem: "npm" },
  { packageName: "lodash", safeVersion: "4.17.21", ecosystem: "npm" },
  { packageName: "axios", safeVersion: "1.6.0", ecosystem: "npm" }
];

const pythonRules: DependencyRule[] = [
  { packageName: "django", safeVersion: "3.2.0", ecosystem: "pypi" },
  { packageName: "flask", safeVersion: "2.2.0", ecosystem: "pypi" },
  { packageName: "requests", safeVersion: "2.31.0", ecosystem: "pypi" }
];

export function scanDependencies(filePath: string, content: string): SecurityFinding[] {
  const baseName = path.basename(filePath).toLowerCase();

  if (baseName === "package.json") {
    return scanPackageJson(filePath, content);
  }

  if (baseName === "requirements.txt") {
    return scanRequirementsTxt(filePath, content);
  }

  return [];
}

function scanPackageJson(filePath: string, content: string): SecurityFinding[] {
  try {
    const parsed = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const dependencies = {
      ...parsed.dependencies,
      ...parsed.devDependencies
    };

    return npmRules.flatMap((rule) => {
      const version = dependencies[rule.packageName];
      if (!version || !isVersionBelow(version, rule.safeVersion)) {
        return [];
      }

      const location = findLineAndColumn(content, `"${rule.packageName}"`);
      return [createDependencyFinding(filePath, rule, version, location.line, location.column)];
    });
  } catch {
    return [];
  }
}

function scanRequirementsTxt(filePath: string, content: string): SecurityFinding[] {
  const lines = content.split(/\r?\n/);
  const findings: SecurityFinding[] = [];

  lines.forEach((lineText, index) => {
    const match = lineText.match(/^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s#]+)/);
    if (!match) {
      return;
    }

    const packageName = match[1].toLowerCase();
    const version = match[2];
    const rule = pythonRules.find((candidate) => candidate.packageName === packageName);

    if (rule && isVersionBelow(version, rule.safeVersion)) {
      findings.push(createDependencyFinding(filePath, rule, version, index, lineText.indexOf(match[1])));
    }
  });

  return findings;
}

function createDependencyFinding(
  filePath: string,
  rule: DependencyRule,
  currentVersion: string,
  line: number,
  column: number
): SecurityFinding {
  return {
    id: `${rule.ecosystem}-${rule.packageName}-outdated`,
    type: "vulnerable-dependency",
    title: `Outdated dependency: ${rule.packageName}`,
    description: `${rule.packageName} ${currentVersion} is older than the mocked safe version ${rule.safeVersion}.`,
    severity: "high",
    filePath,
    line,
    column,
    codeSnippet: `${rule.packageName}@${currentVersion}`,
    recommendation: `Upgrade ${rule.packageName} to ${rule.safeVersion} or newer.`,
    source: "dependency"
  };
}

function isVersionBelow(rawVersion: string, safeVersion: string): boolean {
  const current = normalizeVersion(rawVersion);
  const safe = normalizeVersion(safeVersion);

  for (let index = 0; index < Math.max(current.length, safe.length); index++) {
    const currentPart = current[index] ?? 0;
    const safePart = safe[index] ?? 0;

    if (currentPart < safePart) {
      return true;
    }

    if (currentPart > safePart) {
      return false;
    }
  }

  return false;
}

function normalizeVersion(version: string): number[] {
  return version
    .replace(/^[~^<>=\s]+/, "")
    .split(".")
    .map((part) => Number.parseInt(part.replace(/\D.*$/, ""), 10))
    .map((part) => Number.isNaN(part) ? 0 : part);
}

function findLineAndColumn(content: string, searchText: string): { line: number; column: number } {
  const lines = content.split(/\r?\n/);
  const line = lines.findIndex((lineText) => lineText.includes(searchText));

  if (line === -1) {
    return { line: 0, column: 0 };
  }

  return { line, column: lines[line].indexOf(searchText) };
}
