import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
]);

function isPrivateIpv4(octets: number[]): boolean {
  if (octets.length !== 4) return true;
  const a = octets[0]!;
  const b = octets[1]!;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80")) return true;
  return false;
}

function parseIpv4ToOctets(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function assertIpAllowed(ip: string): void {
  const kind = isIP(ip);
  if (kind === 4) {
    const octets = parseIpv4ToOctets(ip);
    if (octets && isPrivateIpv4(octets)) {
      throw new Error("Request blocked: private or link-local IPv4 address");
    }
  } else if (kind === 6) {
    if (isPrivateIpv6(ip)) {
      throw new Error("Request blocked: private or link-local IPv6 address");
    }
  }
}

export function sanitizeRequestHeaders(
  headers: Record<string, string> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === "host" || lower === "content-length") continue;
    if (/[\r\n]/.test(key) || /[\r\n]/.test(value)) {
      throw new Error("Invalid header: control characters not allowed");
    }
    out[key] = value;
  }
  return out;
}

export async function assertUrlAllowed(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid target URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed");
  }

  const hostname = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error("Request blocked: hostname is not allowed");
  }

  if (hostname.endsWith(".internal") || hostname.endsWith(".local")) {
    throw new Error("Request blocked: internal hostname suffix");
  }

  const ipKind = isIP(hostname);
  if (ipKind) {
    assertIpAllowed(hostname);
    return url;
  }

  const records = await lookup(hostname, { all: true, verbatim: true });
  if (records.length === 0) {
    throw new Error("DNS lookup returned no addresses");
  }
  for (const rec of records) {
    assertIpAllowed(rec.address);
  }

  return url;
}

export interface SafeFetchOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export async function safeFetch(
  rawUrl: string,
  options: SafeFetchOptions = {},
): Promise<Response> {
  const url = await assertUrlAllowed(rawUrl);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = sanitizeRequestHeaders(options.headers);
    const requestInit: RequestInit = {
      method: options.method ?? "GET",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        ...headers,
      },
      signal: controller.signal,
      redirect: "manual",
    };
    if (options.body !== undefined) {
      requestInit.body = options.body;
    }
    const response = await fetch(url.toString(), requestInit);

    if (response.status >= 300 && response.status < 400) {
      throw new Error("HTTP redirects are not followed (SSRF hardening)");
    }

    return response;
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`Request timed out after ${timeoutMs}ms`);
    }
    if (err instanceof Error) {
      throw new Error(err.message);
    }
    throw new Error("Request failed");
  } finally {
    clearTimeout(timer);
  }
}

export async function readResponseTextLimited(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";

  const chunks: Uint8Array[] = [];
  let total = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Response body exceeds size limit");
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}
