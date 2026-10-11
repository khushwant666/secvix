import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/loader.js";
import { secvixConfigSchema } from "../src/config/schema.js";

describe("config schema and loader", () => {
  it("rejects unknown top-level keys", () => {
    const result = secvixConfigSchema.safeParse({
      version: 1,
      target: { type: "mock" },
      policies: {
        failOnSeverity: "HIGH",
        suites: [
          {
            id: "s1",
            probes: [{ id: "p1", prompt: "hello" }],
          },
        ],
      },
      extra: true,
    });
    expect(result.success).toBe(false);
  });

  it("blocks prototype pollution keys in YAML", async () => {
    const dir = await mkdtemp(join(tmpdir(), "secvix-config-"));
    const path = join(dir, "bad.yaml");
    await writeFile(
      path,
      `version: 1
target:
  type: mock
policies:
  failOnSeverity: HIGH
  suites:
    - id: s1
      probes:
        - id: p1
          prompt: test
__proto__:
  polluted: true
`,
      "utf8",
    );
    await expect(loadConfig(path)).rejects.toThrow(/Forbidden key/);
    await rm(dir, { recursive: true, force: true });
  });

  it("substitutes environment variables", async () => {
    const dir = await mkdtemp(join(tmpdir(), "secvix-config-"));
    const path = join(dir, "env.yaml");
    process.env.SECVIX_TEST_MARKER = "from-env";
    await writeFile(
      path,
      `version: 1
target:
  type: mock
policies:
  failOnSeverity: HIGH
  suites:
    - id: s1
      probes:
        - id: p1
          prompt: "\${SECVIX_TEST_MARKER}"
`,
      "utf8",
    );
    const cfg = await loadConfig(path);
    expect(cfg.policies.suites[0]?.probes[0]?.prompt).toBe("from-env");
    delete process.env.SECVIX_TEST_MARKER;
    await rm(dir, { recursive: true, force: true });
  });
});
