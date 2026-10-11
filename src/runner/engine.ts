import type { SecvixConfig } from "../config/schema.js";
import { HttpAgentDriver } from "../drivers/http.js";
import { MockAgentDriver } from "../drivers/mock.js";
import { evaluateCanaryDlp } from "../evaluators/canaryDlp.js";
import { evaluateToolBoundary } from "../evaluators/toolBoundary.js";
import type { AgentDriver, AgentDriverInitOptions } from "../types/driver.js";
import {
  severityMeetsThreshold,
  type ProbeResult,
  type ScanReport,
  type Severity,
} from "../types/report.js";

export interface RunScanOptions {
  config: SecvixConfig;
  failOnSeverity?: Severity | undefined;
}

function createDriver(config: SecvixConfig): AgentDriver {
  const target = config.target;
  if (target.type === "mock") {
    const driver = new MockAgentDriver();
    driver.setScenario(target.scenario ?? "clean");
    return driver;
  }

  const driver = new HttpAgentDriver();
  const pathConfig: {
    promptField?: string;
    responseTextPath?: string;
    toolCallsPath?: string;
  } = {};
  if (target.promptField) pathConfig.promptField = target.promptField;
  if (target.responseTextPath) {
    pathConfig.responseTextPath = target.responseTextPath;
  }
  if (target.toolCallsPath) pathConfig.toolCallsPath = target.toolCallsPath;
  driver.configurePaths(pathConfig);
  return driver;
}

export async function runScan(options: RunScanOptions): Promise<ScanReport> {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const failOn: Severity =
    options.failOnSeverity ?? options.config.policies.failOnSeverity;

  const driver = createDriver(options.config);
  const target = options.config.target;

  if (target.type === "http") {
    const initOptions: AgentDriverInitOptions = {
      endpoint: target.endpoint,
    };
    if (target.headers) initOptions.headers = target.headers;
    if (target.timeoutMs !== undefined) {
      initOptions.timeoutMs = target.timeoutMs;
    }
    await driver.init(initOptions);
  } else {
    await driver.init({});
  }

  const probes: ProbeResult[] = [];
  const findingsAgg: ScanReport["findings"] = [];

  try {
    for (const suite of options.config.policies.suites) {
      for (const probe of suite.probes) {
        const probeStart = Date.now();
        const dispatch = await driver.dispatch(probe.prompt);

        const boundaryFindings = evaluateToolBoundary(dispatch.toolCalls, {
          allowedTools: suite.allowedTools,
          disallowedTools: suite.disallowedTools,
          suiteId: suite.id,
          probeId: probe.id,
        });

        const dlpFindings = evaluateCanaryDlp(
          dispatch.text,
          dispatch.toolCalls,
          {
            canaryToken: probe.canaryToken,
            suiteId: suite.id,
            probeId: probe.id,
          },
        );

        const findings = [...boundaryFindings, ...dlpFindings];
        const failed = findings.some((f) =>
          severityMeetsThreshold(f.severity, failOn),
        );

        probes.push({
          probeId: probe.id,
          suiteId: suite.id,
          passed: !failed,
          findings,
          durationMs: Date.now() - probeStart,
        });
        findingsAgg.push(...findings);
      }
    }
  } finally {
    await driver.teardown();
  }

  const finished = Date.now();
  const passed = !findingsAgg.some((f) =>
    severityMeetsThreshold(f.severity, failOn),
  );

  return {
    passed,
    failOnSeverity: failOn,
    findings: findingsAgg,
    probes,
    startedAt,
    finishedAt: new Date(finished).toISOString(),
    durationMs: finished - started,
  };
}
