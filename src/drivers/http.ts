import type {
  AgentDispatchResult,
  AgentDriver,
  AgentDriverInitOptions,
  ToolCall,
} from "../types/driver.js";
import {
  readResponseTextLimited,
  safeFetch,
  assertUrlAllowed,
} from "../http/safeFetch.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getByPath(root: unknown, path: string): unknown {
  const segments = path.split(".").filter(Boolean);
  let current: unknown = root;
  for (const segment of segments) {
    if (!isRecord(current) && !Array.isArray(current)) return undefined;
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isInteger(index)) return undefined;
      current = current[index];
      continue;
    }
    current = current[segment];
  }
  return current;
}

function normalizeToolCalls(raw: unknown): ToolCall[] {
  if (!Array.isArray(raw)) return [];
  const calls: ToolCall[] = [];
  for (const item of raw) {
    if (!isRecord(item)) continue;
    const name = item.name;
    if (typeof name !== "string" || name.length === 0) continue;
    const args = item.arguments ?? item.args;
    const argumentsValue =
      isRecord(args) ? (args as Record<string, unknown>) : undefined;
    calls.push(
      argumentsValue !== undefined
        ? { name, arguments: argumentsValue }
        : { name },
    );
  }
  return calls;
}

export class HttpAgentDriver implements AgentDriver {
  readonly id = "http";
  private endpoint = "";
  private headers: Record<string, string> = {};
  private timeoutMs = 30_000;
  private promptField = "prompt";
  private responseTextPath = "text";
  private toolCallsPath = "tool_calls";

  async init(options: AgentDriverInitOptions): Promise<void> {
    if (!options.endpoint) {
      throw new Error("HTTP driver requires target.endpoint");
    }
    await assertUrlAllowed(options.endpoint);
    this.endpoint = options.endpoint;
    this.headers = options.headers ?? {};
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  configurePaths(config: {
    promptField?: string;
    responseTextPath?: string;
    toolCallsPath?: string;
  }): void {
    if (config.promptField) this.promptField = config.promptField;
    if (config.responseTextPath) this.responseTextPath = config.responseTextPath;
    if (config.toolCallsPath) this.toolCallsPath = config.toolCallsPath;
  }

  async dispatch(prompt: string): Promise<AgentDispatchResult> {
    const body = JSON.stringify({ [this.promptField]: prompt });
    const response = await safeFetch(this.endpoint, {
      method: "POST",
      headers: this.headers,
      body,
      timeoutMs: this.timeoutMs,
    });

    if (!response.ok) {
      throw new Error(`Agent endpoint returned HTTP ${response.status}`);
    }

    const text = await readResponseTextLimited(response);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      return { text, toolCalls: [], raw: text };
    }

    const responseTextRaw = getByPath(parsed, this.responseTextPath);
    const responseText =
      typeof responseTextRaw === "string" ? responseTextRaw : text;
    const toolCalls = normalizeToolCalls(getByPath(parsed, this.toolCallsPath));

    return {
      text: responseText,
      toolCalls,
      raw: parsed,
    };
  }

  async teardown(): Promise<void> {
    // Stateless HTTP driver — nothing to release
  }
}
