export type FindingSeverity = "low" | "medium" | "high" | "critical";

export type FindingSource = "code" | "dependency";

export interface SecurityFinding {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  filePath: string;
  line: number;
  column: number;
  codeSnippet: string;
  recommendation: string;
  source: FindingSource;
  metadata?: {
    packageName?: string;
    currentVersion?: string;
    vulnerabilityCount?: number;
    vulnerabilityIds?: string[];
    vulnerabilitySummaries?: Array<{
      id: string;
      summary: string;
    }>;
    fixedVersion?: string;
  };
}
