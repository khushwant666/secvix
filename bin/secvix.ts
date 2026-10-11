#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Command } from "commander";
import ora from "ora";
import { loadConfig } from "../src/config/loader.js";
import { DEFAULT_SECVIX_YAML } from "../src/config/schema.js";
import { runScan } from "../src/runner/engine.js";
import { renderSarifReport } from "../src/reporters/sarif.js";
import { renderTerminalReport } from "../src/reporters/terminal.js";
import { SEVERITIES, type Severity } from "../src/types/report.js";
import pkg from "../package.json" with { type: "json" };

const program = new Command();

program
  .name("secvix")
  .description(
    "Universal pre-deployment security testing harness for autonomous AI agents",
  )
  .version(pkg.version);

program
  .command("init")
  .description("Generate a starter secvix.yaml in the current directory")
  .option("-o, --output <path>", "Output path", "secvix.yaml")
  .action(async (opts: { output: string }) => {
    const outPath = resolve(opts.output);
    await writeFile(outPath, DEFAULT_SECVIX_YAML, "utf8");
    process.stdout.write(`Created ${outPath}\n`);
  });

program
  .command("scan")
  .description("Run security probes against the configured agent target")
  .option("-c, --config <path>", "Path to secvix.yaml", "secvix.yaml")
  .option(
    "--fail-on <severity>",
    `Fail when findings meet severity (${SEVERITIES.join(", ")})`,
  )
  .option("--format <format>", "Output format: console or sarif", "console")
  .option("-o, --output <file>", "Write report to file instead of stdout")
  .action(
    async (opts: {
      config: string;
      failOn?: string;
      format: string;
      output?: string;
    }) => {
      const spinner = ora("Loading configuration").start();
      let config;
      try {
        config = await loadConfig(opts.config);
        spinner.succeed("Configuration loaded");
      } catch (err) {
        spinner.fail("Configuration invalid");
        const message = err instanceof Error ? err.message : "Unknown error";
        process.stderr.write(`${message}\n`);
        process.exitCode = 1;
        return;
      }

      let failOn: Severity | undefined;
      if (opts.failOn) {
        const normalized = opts.failOn.toUpperCase() as Severity;
        if (!SEVERITIES.includes(normalized)) {
          process.stderr.write(
            `Invalid --fail-on value. Use one of: ${SEVERITIES.join(", ")}\n`,
          );
          process.exitCode = 1;
          return;
        }
        failOn = normalized;
      }

      const format = opts.format.toLowerCase();
      if (format !== "console" && format !== "sarif") {
        process.stderr.write("--format must be console or sarif\n");
        process.exitCode = 1;
        return;
      }

      const runSpinner = ora("Running security probes").start();
      let report;
      try {
        report = await runScan({ config, failOnSeverity: failOn });
        runSpinner.succeed("Probes complete");
      } catch (err) {
        runSpinner.fail("Scan failed");
        const message = err instanceof Error ? err.message : "Unknown error";
        process.stderr.write(`${message}\n`);
        process.exitCode = 1;
        return;
      }

      const output =
        format === "sarif"
          ? renderSarifReport(report)
          : renderTerminalReport(report);

      if (opts.output) {
        await writeFile(resolve(opts.output), output, "utf8");
      } else {
        process.stdout.write(output);
      }

      if (!report.passed) {
        process.exitCode = 1;
      }
    },
  );

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : "Fatal error";
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
