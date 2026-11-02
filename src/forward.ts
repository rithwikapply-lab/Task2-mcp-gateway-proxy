import { Request, Response } from "express";
import http from "node:http";
import { Readable } from "node:stream";
import { GatewayConfig } from "./config.js";
import { ErrorCodes, JsonRpcId } from "./jsonrpc.js";

const HOP_BY_HOP_HEADERS = new Set([
  "authorization",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "host",
  "content-length"
]);

export class ForwardError extends Error {
  public status: number;
  public rpcCode: number;
  public echoId: JsonRpcId;

  constructor(status: number, rpcCode: number, message: string, echoId: JsonRpcId = null) {
    super(message);
    this.name = "ForwardError";
    this.status = status;
    this.rpcCode = rpcCode;
    this.echoId = echoId;
  }
}

export function prepareForwardHeaders(incomingHeaders: http.IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(incomingHeaders)) {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerKey)) {
      continue;
    }
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const v of value) {
        headers.append(lowerKey, v);
      }
    } else {
      headers.set(lowerKey, value);
    }
  }

  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  return headers;
}

export async function forwardSingleStream(
  req: Request,
  res: Response,
  rawBody: Buffer | string,
  config: GatewayConfig,
  echoId: JsonRpcId
): Promise<void> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.downstreamTimeoutMs);

  let response: globalThis.Response;
  try {
    const headers = prepareForwardHeaders(req.headers);
    const bodyInit: BodyInit = typeof rawBody === "string" ? rawBody : new Uint8Array(rawBody);
    response = await fetch(config.downstreamUrl, {
      method: "POST",
      headers,
      body: bodyInit,
      signal: controller.signal
    });
  } catch (err: any) {
    if (err.name === "AbortError" || controller.signal.aborted) {
      throw new ForwardError(504, ErrorCodes.DOWNSTREAM_TIMEOUT, "Gateway Timeout", echoId);
    }
    throw new ForwardError(502, ErrorCodes.DOWNSTREAM_UNAVAILABLE, "Bad Gateway", echoId);
  } finally {
    clearTimeout(timeoutId);
  }

  res.status(response.status);

  const contentType = response.headers.get("content-type");
  if (contentType) {
    res.setHeader("content-type", contentType);
  }

  const mcpSessionId = response.headers.get("mcp-session-id");
  if (mcpSessionId) {
    res.setHeader("mcp-session-id", mcpSessionId);
  }

  if (response.body) {
    Readable.fromWeb(response.body as any).pipe(res);
  } else {
    res.end();
  }
}

export async function forwardBatchJson(
  batchItems: unknown[],
  incomingHeaders: http.IncomingHttpHeaders,
  config: GatewayConfig,
  echoId: JsonRpcId
): Promise<{ status: number; data: unknown }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.downstreamTimeoutMs);

  let response: globalThis.Response;
  try {
    const headers = prepareForwardHeaders(incomingHeaders);
    response = await fetch(config.downstreamUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(batchItems),
      signal: controller.signal
    });
  } catch (err: any) {
    if (err.name === "AbortError" || controller.signal.aborted) {
      throw new ForwardError(504, ErrorCodes.DOWNSTREAM_TIMEOUT, "Gateway Timeout", echoId);
    }
    throw new ForwardError(502, ErrorCodes.DOWNSTREAM_UNAVAILABLE, "Bad Gateway", echoId);
  } finally {
    clearTimeout(timeoutId);
  }

  if (response.status === 202) {
    return { status: 202, data: null };
  }

  const text = await response.text();
  if (!text || text.trim().length === 0) {
    return { status: response.status, data: null };
  }

  try {
    const data = JSON.parse(text);
    return { status: response.status, data };
  } catch {
    throw new ForwardError(
      502,
      ErrorCodes.DOWNSTREAM_UNAVAILABLE,
      "Bad Gateway",
      echoId
    );
  }
}
