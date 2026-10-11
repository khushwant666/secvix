import chalk from "chalk";
import type { ScanReport } from "../types/report.js";

const PASS = chalk.green("✔");
const FAIL = chalk.red("✖");

export function renderTerminalReport(report: ScanReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("secvix scan report"));
  lines.push(
    chalk.dim(
      `${report.startedAt} → ${report.finishedAt} (${report.durationMs}ms)`,
    ),
  );
  lines.push(
    `Fail threshold: ${chalk.yellow(report.failOnSeverity)} and above`,
  );
  lines.push("");

  for (const probe of report.probes) {
    const icon = probe.passed ? PASS : FAIL;
    const status = probe.passed
      ? chalk.green("PASS")
      : chalk.red("FAIL");
    lines.push(
      `${icon} ${chalk.cyan(probe.suiteId)} / ${probe.probeId} ${status} ${chalk.dim(`(${probe.durationMs}ms)`)}`,
    );
    for (const finding of probe.findings) {
      const sevColor =
        finding.severity === "CRITICAL" || finding.severity === "HIGH"
          ? chalk.red
          : finding.severity === "MEDIUM"
            ? chalk.yellow
            : chalk.gray;
      lines.push(
        `    ${sevColor(finding.severity)} ${finding.ruleId}: ${finding.message}`,
      );
    }
  }

  lines.push("");
  if (report.passed) {
    lines.push(`${PASS} ${chalk.green("All probes passed within policy.")}`);
  } else {
    lines.push(
      `${FAIL} ${chalk.red("Policy violation: findings meet or exceed fail threshold.")}`,
    );
  }
  lines.push("");

  return lines.join("\n");
}
