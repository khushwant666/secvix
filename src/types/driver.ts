export interface ToolCall {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface AgentDispatchResult {
  text: string;
  toolCalls: ToolCall[];
  raw?: unknown;
}

export interface AgentDriverInitOptions {
  endpoint?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export interface AgentDriver {
  readonly id: string;
  init(options: AgentDriverInitOptions): Promise<void>;
  dispatch(prompt: string): Promise<AgentDispatchResult>;
  teardown(): Promise<void>;
}
