import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseDocument } from "yaml";
import { secvixConfigSchema, type SecvixConfig } from "./schema.js";

const ENV_VAR_PATTERN = /\$\{([A-Z_][A-Z0-9_]*)\}/g;

function substituteEnvVars(source: string): string {
  return source.replace(ENV_VAR_PATTERN, (_match, name: string) => {
    const value = process.env[name];
    if (value === undefined) {
      throw new Error(`Missing environment variable referenced in config: ${name}`);
    }
    return value;
  });
}

function assertPlainYaml(value: unknown, path = "root"): void {
  if (value === null || typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      assertPlainYaml(value[i], `${path}[${i}]`);
    }
    return;
  }
  const obj = value as Record<string, unknown>;
  if (Object.getPrototypeOf(obj) !== Object.prototype) {
    throw new Error(`Invalid YAML object at ${path}: prototype pollution risk`);
  }
  for (const [key, child] of Object.entries(obj)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new Error(`Forbidden key in config at ${path}.${key}`);
    }
    assertPlainYaml(child, `${path}.${key}`);
  }
}

export async function loadConfig(configPath: string): Promise<SecvixConfig> {
  const absolute = resolve(configPath);
  const raw = await readFile(absolute, "utf8");
  const withEnv = substituteEnvVars(raw);

  const doc = parseDocument(withEnv, { strict: true });
  if (doc.errors.length > 0) {
    const msg = doc.errors.map((e) => e.message).join("; ");
    throw new Error(`YAML parse error: ${msg}`);
  }

  const parsed: unknown = doc.toJSON();
  assertPlainYaml(parsed);

  const result = secvixConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    throw new Error(`Invalid secvix configuration: ${issues}`);
  }

  return result.data;
}
