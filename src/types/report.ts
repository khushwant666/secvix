export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function severityMeetsThreshold(
  finding: Severity,
  threshold: Severity,
): boolean {
  return SEVERITY_RANK[finding] >= SEVERITY_RANK[threshold];
}

export interface EvaluationFinding {
  ruleId: string;
  title: string;
  message: string;
  severity: Severity;
  suiteId?: string;
  probeId?: string;
  evidence?: string;
}

export interface ProbeResult {
  probeId: string;
  suiteId: string;
  passed: boolean;
  findings: EvaluationFinding[];
  durationMs: number;
}

export interface ScanReport {
  passed: boolean;
  failOnSeverity: Severity;
  findings: EvaluationFinding[];
  probes: ProbeResult[];
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}
