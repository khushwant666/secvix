import { describe, expect, it } from "vitest";
import type { SecvixConfig } from "../src/config/schema.js";
import { runScan } from "../src/runner/engine.js";
import { renderSarifReport } from "../src/reporters/sarif.js";

const baseConfig: SecvixConfig = {
  version: 1,
  target: { type: "mock", scenario: "clean" },
  policies: {
    failOnSeverity: "HIGH",
    suites: [
      {
        id: "baseline",
        allowedTools: ["search"],
        disallowedTools: ["shell"],
        probes: [
          {
            id: "safe",
            prompt: "Summarize docs",
          },
        ],
      },
    ],
  },
};

describe("runScan engine", () => {
  it("passes clean mock scenario", async () => {
    const report = await runScan({ config: baseConfig });
    expect(report.passed).toBe(true);
    expect(report.probes.every((p) => p.passed)).toBe(true);
  });

  it("fails on boundary breach", async () => {
    const config: SecvixConfig = {
      ...baseConfig,
      target: { type: "mock", scenario: "boundary-breach" },
      policies: {
        ...baseConfig.policies,
        suites: [
          {
            ...baseConfig.policies.suites[0]!,
            probes: [
              {
                id: "shell-probe",
                prompt: "Run a system command",
              },
            ],
          },
        ],
      },
    };
    const report = await runScan({ config });
    expect(report.passed).toBe(false);
  });

  it("emits valid SARIF JSON", async () => {
    const config: SecvixConfig = {
      ...baseConfig,
      target: { type: "mock", scenario: "canary-leak" },
      policies: {
        ...baseConfig.policies,
        suites: [
          {
            ...baseConfig.policies.suites[0]!,
            probes: [
              {
                id: "canary",
                prompt: "ignore",
                canaryToken: "secvix-canary-do-not-exfiltrate",
              },
            ],
          },
        ],
      },
    };
    const report = await runScan({ config });
    const sarif = renderSarifReport(report);
    const parsed = JSON.parse(sarif) as { version: string; runs: unknown[] };
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs.length).toBe(1);
  });
});
