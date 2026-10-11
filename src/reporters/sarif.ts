import type { EvaluationFinding, ScanReport, Severity } from "../types/report.js";

const SARIF_SCHEMA =
  "https://json.schemastore.org/sarif-2.1.0.json";

function severityToLevel(severity: Severity): "note" | "warning" | "error" {
  switch (severity) {
    case "LOW":
      return "note";
    case "MEDIUM":
      return "warning";
    case "HIGH":
    case "CRITICAL":
      return "error";
  }
}

function uniqueRules(findings: EvaluationFinding[]): EvaluationFinding[] {
  const seen = new Set<string>();
  const rules: EvaluationFinding[] = [];
  for (const f of findings) {
    if (seen.has(f.ruleId)) continue;
    seen.add(f.ruleId);
    rules.push(f);
  }
  return rules;
}

export function renderSarifReport(report: ScanReport): string {
  const rules = uniqueRules(report.findings);

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "secvix",
            informationUri: "https://github.com/khushwant666/secvix",
            rules: rules.map((r) => ({
              id: r.ruleId,
              shortDescription: { text: r.title },
              fullDescription: { text: r.message },
              defaultConfiguration: {
                level: severityToLevel(r.severity),
              },
            })),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: severityToLevel(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: "secvix://scan",
                },
              },
            },
          ],
          properties: {
            severity: f.severity,
            suiteId: f.suiteId,
            probeId: f.probeId,
            evidence: f.evidence,
          },
        })),
        invocations: [
          {
            executionSuccessful: report.passed,
            startTimeUtc: report.startedAt,
            endTimeUtc: report.finishedAt,
          },
        ],
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
