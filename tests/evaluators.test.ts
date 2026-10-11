import { describe, expect, it } from "vitest";
import { evaluateCanaryDlp } from "../src/evaluators/canaryDlp.js";
import { evaluateToolBoundary } from "../src/evaluators/toolBoundary.js";

describe("toolBoundary evaluator", () => {
  it("flags disallowed tools as CRITICAL", () => {
    const findings = evaluateToolBoundary(
      [{ name: "shell", arguments: { cmd: "ls" } }],
      {
        disallowedTools: ["shell"],
        suiteId: "baseline",
        probeId: "no-shell",
      },
    );
    expect(findings.some((f) => f.severity === "CRITICAL")).toBe(true);
  });

  it("flags tools outside allowlist as HIGH", () => {
    const findings = evaluateToolBoundary([{ name: "delete_all" }], {
      allowedTools: ["search"],
      suiteId: "baseline",
      probeId: "p1",
    });
    expect(findings[0]?.ruleId).toBe("agentic/tool-boundary-not-allowed");
  });
});

describe("canaryDlp evaluator", () => {
  it("detects canary token in response", () => {
    const token = "secvix-canary-do-not-exfiltrate";
    const findings = evaluateCanaryDlp(`leaked ${token}`, [], {
      canaryToken: token,
      suiteId: "s",
      probeId: "p",
    });
    expect(findings[0]?.ruleId).toBe("agentic/canary-exfiltration");
  });

  it("detects credential-like patterns", () => {
    const findings = evaluateCanaryDlp("key=AKIAIOSFODNN7EXAMPLE", [], {
      suiteId: "s",
      probeId: "p",
    });
    expect(findings.some((f) => f.ruleId === "dlp/aws-access-key")).toBe(true);
  });
});
