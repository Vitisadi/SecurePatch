import * as path from "path";
import { SecurityFinding } from "../types/finding";

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
  line: number;
  column: number;
}

interface DependencyRule {
  packageName: string;
  safeVersion: string;
  ecosystem: "npm" | "PyPI";
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  affected?: Array<{
    package?: {
      name?: string;
      ecosystem?: string;
    };
    ranges?: Array<{
      events?: Array<{
        fixed?: string;
      }>;
    }>;
  }>;
}

const osvCache = new Map<string, Promise<OsvVulnerability[]>>();

const npmRules: DependencyRule[] = [
  { packageName: "express", safeVersion: "4.18.0", ecosystem: "npm" },
  { packageName: "lodash", safeVersion: "4.17.21", ecosystem: "npm" },
  { packageName: "axios", safeVersion: "1.6.0", ecosystem: "npm" }
];

const pythonRules: DependencyRule[] = [
  { packageName: "django", safeVersion: "3.2.0", ecosystem: "PyPI" },
  { packageName: "flask", safeVersion: "2.2.0", ecosystem: "PyPI" },
  { packageName: "requests", safeVersion: "2.31.0", ecosystem: "PyPI" }
];

export async function scanDependencies(filePath: string, content: string): Promise<SecurityFinding[]> {
  const dependencies = parseDependencies(filePath, content);

  if (dependencies.length === 0) {
    return [];
  }

  const findings: SecurityFinding[] = [];
  let apiFailed = false;

  for (const dependency of dependencies) {
    try {
      const vulns = await queryOsv(dependency);
      const finding = createOsvFinding(filePath, dependency, vulns);
      if (finding) {
        findings.push(finding);
      }
    } catch {
      apiFailed = true;
    }
  }

  if (apiFailed) {
    findings.push(...scanMockDependencies(filePath, dependencies));
  }

  return dedupeFindings(findings);
}

function parseDependencies(filePath: string, content: string): ParsedDependency[] {
  const baseName = path.basename(filePath).toLowerCase();

  if (baseName === "package.json") {
    return parsePackageJsonDependencies(content);
  }

  if (baseName === "requirements.txt") {
    return parseRequirementsDependencies(content);
  }

  return [];
}

function parsePackageJsonDependencies(content: string): ParsedDependency[] {
  try {
    const parsed = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const dependencies = {
      ...parsed.dependencies,
      ...parsed.devDependencies
    };

    return Object.entries(dependencies).map(([name, rawVersion]) => {
      const location = findLineAndColumn(content, `"${name}"`);
      return {
        name,
        version: normalizeVersionString(rawVersion),
        ecosystem: "npm",
        line: location.line,
        column: location.column
      };
    });
  } catch {
    return [];
  }
}

function parseRequirementsDependencies(content: string): ParsedDependency[] {
  const dependencies: ParsedDependency[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, index) => {
    const match = lineText.match(/^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s#]+)/);
    if (!match) {
      return;
    }

    dependencies.push({
      name: match[1],
      version: normalizeVersionString(match[2]),
      ecosystem: "PyPI",
      line: index,
      column: lineText.indexOf(match[1])
    });
  });

  return dependencies;
}

function queryOsv(dependency: ParsedDependency): Promise<OsvVulnerability[]> {
  const cacheKey = `${dependency.ecosystem}:${dependency.name}@${dependency.version}`.toLowerCase();
  const cached = osvCache.get(cacheKey);

  if (cached) {
    return cached;
  }

  const request = fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      version: dependency.version,
      package: {
        name: dependency.name,
        ecosystem: dependency.ecosystem
      }
    })
  }).then(async (response) => {
    if (!response.ok) {
      throw new Error(`OSV request failed with ${response.status}`);
    }

    const body = await response.json() as OsvQueryResponse;
    return body.vulns ?? [];
  });

  osvCache.set(cacheKey, request);
  return request;
}

function createOsvFinding(
  filePath: string,
  dependency: ParsedDependency,
  vulnerabilities: OsvVulnerability[]
): SecurityFinding | undefined {
  if (vulnerabilities.length === 0) {
    return undefined;
  }

  const fixedVersion = findBestFixedVersion(vulnerabilities, dependency);
  const vulnerabilityIds = vulnerabilities.map((vulnerability) => vulnerability.id);
  const vulnerabilitySummaries = vulnerabilities.map((vulnerability) => ({
    id: vulnerability.id,
    summary: vulnerability.summary ?? vulnerability.details ?? "No summary provided."
  }));

  return {
    id: `osv-${dependency.ecosystem}-${dependency.name}-${dependency.version}`,
    type: "vulnerable-dependency",
    title: `Vulnerable dependency: ${dependency.name}`,
    description: `OSV reported ${vulnerabilities.length} vulnerability finding(s) for ${dependency.name} ${dependency.version}.`,
    severity: "high",
    filePath,
    line: dependency.line,
    column: dependency.column,
    codeSnippet: `${dependency.name}@${dependency.version}`,
    recommendation: fixedVersion
      ? `Upgrade ${dependency.name} to ${fixedVersion} or newer.`
      : `Upgrade ${dependency.name} to a non-vulnerable version recommended by OSV or the package maintainer.`,
    source: "dependency",
    metadata: {
      packageName: dependency.name,
      currentVersion: dependency.version,
      vulnerabilityCount: vulnerabilities.length,
      vulnerabilityIds,
      vulnerabilitySummaries,
      fixedVersion
    }
  };
}

function findBestFixedVersion(vulnerabilities: OsvVulnerability[], dependency: ParsedDependency): string | undefined {
  const fixedVersions = vulnerabilities
    .map((vulnerability) => findFixedVersion(vulnerability, dependency))
    .filter((version): version is string => Boolean(version));

  return fixedVersions.sort(compareVersions).at(-1);
}

function findFixedVersion(vulnerability: OsvVulnerability, dependency: ParsedDependency): string | undefined {
  const fixedVersions = vulnerability.affected
    ?.filter((affected) => {
      const affectedPackage = affected.package;
      return !affectedPackage?.name ||
        affectedPackage.name.toLowerCase() === dependency.name.toLowerCase();
    })
    .flatMap((affected) => affected.ranges ?? [])
    .flatMap((range) => range.events ?? [])
    .map((event) => event.fixed)
    .filter((version): version is string => Boolean(version));

  return fixedVersions?.sort(compareVersions)[0];
}

function scanMockDependencies(filePath: string, dependencies: ParsedDependency[]): SecurityFinding[] {
  const rules = [...npmRules, ...pythonRules];

  return dependencies.flatMap((dependency) => {
    const rule = rules.find((candidate) =>
      candidate.ecosystem === dependency.ecosystem &&
      candidate.packageName.toLowerCase() === dependency.name.toLowerCase()
    );

    if (!rule || !isVersionBelow(dependency.version, rule.safeVersion)) {
      return [];
    }

    return [createMockFinding(filePath, dependency, rule)];
  });
}

function createMockFinding(
  filePath: string,
  dependency: ParsedDependency,
  rule: DependencyRule
): SecurityFinding {
  return {
    id: `${rule.ecosystem.toLowerCase()}-${rule.packageName}-outdated`,
    type: "vulnerable-dependency",
    title: `Outdated dependency: ${rule.packageName}`,
    description: `${rule.packageName} ${dependency.version} is older than the offline fallback safe version ${rule.safeVersion}.`,
    severity: "high",
    filePath,
    line: dependency.line,
    column: dependency.column,
    codeSnippet: `${dependency.name}@${dependency.version}`,
    recommendation: `Upgrade ${dependency.name} to ${rule.safeVersion} or newer.`,
    source: "dependency"
  };
}

function dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();

  return findings.filter((finding) => {
    const key = `${finding.filePath}:${finding.line}:${finding.column}:${finding.id}`;
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

function normalizeVersionString(version: string): string {
  return version.replace(/^[~^<>=\s]+/, "").trim();
}

function isVersionBelow(rawVersion: string, safeVersion: string): boolean {
  return compareVersions(rawVersion, safeVersion) < 0;
}

function compareVersions(leftVersion: string, rightVersion: string): number {
  const left = normalizeVersion(leftVersion);
  const right = normalizeVersion(rightVersion);

  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const leftPart = left[index] ?? 0;
    const rightPart = right[index] ?? 0;

    if (leftPart !== rightPart) {
      return leftPart - rightPart;
    }
  }

  return 0;
}

function normalizeVersion(version: string): number[] {
  return normalizeVersionString(version)
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
