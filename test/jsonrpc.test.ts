import { describe, it, expect } from "vitest";
import {
  parseJsonRpcPayload,
  validateItem,
  ErrorCodes,
  extractEchoId,
  isClientResponse
} from "../src/jsonrpc.js";

describe("JSON-RPC Wire Format Parsing", () => {
  it("rejects non-object scalars with invalid request", () => {
    for (const scalar of [123, "test", true, false, null]) {
      const res = parseJsonRpcPayload(scalar);
      expect(res.error).toBeDefined();
      expect(res.error?.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.error?.id).toBeNull();
    }
  });

  it("rejects empty batch with -32600 and id null", () => {
    const res = parseJsonRpcPayload([]);
    expect(res.error).toBeDefined();
    expect(res.error?.error.code).toBe(ErrorCodes.INVALID_REQUEST);
    expect(res.error?.id).toBeNull();
  });

  it("validates single request and preserves string id", () => {
    const res = parseJsonRpcPayload({
      jsonrpc: "2.0",
      id: "req-123",
      method: "tools/list"
    });
    expect(res.payload?.isBatch).toBe(false);
    if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
    expect(res.payload.item.kind).toBe("request");
    if (res.payload.item.kind !== "request") return;
    expect(res.payload.item.id).toBe("req-123");
    expect(res.payload.item.isNotification).toBe(false);
    expect(res.payload.item.request.method).toBe("tools/list");
  });

  it("validates single request and preserves numeric and null id", () => {
    for (const id of [42, 0, -1, null]) {
      const res = parseJsonRpcPayload({
        jsonrpc: "2.0",
        id,
        method: "ping"
      });
      if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
      expect(res.payload.item.kind).toBe("request");
      if (res.payload.item.kind !== "request") return;
      expect(res.payload.item.id).toBe(id);
      expect(res.payload.item.isNotification).toBe(false);
    }
  });

  it("identifies notifications when id is omitted", () => {
    const res = parseJsonRpcPayload({
      jsonrpc: "2.0",
      method: "notifications/initialized"
    });
    if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
    expect(res.payload.item.kind).toBe("request");
    if (res.payload.item.kind !== "request") return;
    expect(res.payload.item.isNotification).toBe(true);
    expect(res.payload.item.id).toBeNull();
  });

  it("rejects invalid jsonrpc versions", () => {
    for (const badVersion of ["1.0", "2.1", "3.0", undefined, 2]) {
      const res = parseJsonRpcPayload({
        jsonrpc: badVersion,
        id: "err-1",
        method: "tools/list"
      });
      if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
      expect(res.payload.item.kind).toBe("error");
      if (res.payload.item.kind !== "error") return;
      expect(res.payload.item.error.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.payload.item.error.id).toBe("err-1");
    }
  });

  it("rejects non-string method", () => {
    for (const badMethod of [123, null, {}, [], true]) {
      const res = parseJsonRpcPayload({
        jsonrpc: "2.0",
        id: "err-method",
        method: badMethod
      });
      if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
      expect(res.payload.item.kind).toBe("error");
      if (res.payload.item.kind !== "error") return;
      expect(res.payload.item.error.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.payload.item.error.id).toBe("err-method");
    }
  });

  it("rejects invalid params type (non-object, non-array)", () => {
    for (const badParams of ["string", 123, true, null]) {
      const res = parseJsonRpcPayload({
        jsonrpc: "2.0",
        id: "err-params",
        method: "tools/call",
        params: badParams
      });
      if (!res.payload || res.payload.isBatch) throw new Error("Expected single item");
      expect(res.payload.item.kind).toBe("error");
      if (res.payload.item.kind !== "error") return;
      expect(res.payload.item.error.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.payload.item.error.id).toBe("err-params");
    }
  });

  it("recognizes client responses with result or error and no method", () => {
    const successRes = parseJsonRpcPayload({
      jsonrpc: "2.0",
      id: "resp-1",
      result: { ok: true }
    });
    if (!successRes.payload || successRes.payload.isBatch) throw new Error("Expected single item");
    expect(successRes.payload.item.kind).toBe("client_response");
    expect(isClientResponse(successRes.payload.item.raw)).toBe(true);

    const errorRes = parseJsonRpcPayload({
      jsonrpc: "2.0",
      id: "resp-2",
      error: { code: -32000, message: "Client error" }
    });
    if (!errorRes.payload || errorRes.payload.isBatch) throw new Error("Expected single item");
    expect(errorRes.payload.item.kind).toBe("client_response");
    expect(isClientResponse(errorRes.payload.item.raw)).toBe(true);
  });

  it("processes batches and validates each item independently", () => {
    const batch = [
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { jsonrpc: "invalid", id: 2, method: "ping" },
      { jsonrpc: "2.0", method: "notify" }
    ];
    const res = parseJsonRpcPayload(batch);
    expect(res.payload?.isBatch).toBe(true);
    if (!res.payload || !res.payload.isBatch) throw new Error("Expected batch");
    expect(res.payload.items).toHaveLength(3);
    expect(res.payload.items[0].kind).toBe("request");
    expect(res.payload.items[1].kind).toBe("error");
    if (res.payload.items[1].kind === "error") {
      expect(res.payload.items[1].error.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.payload.items[1].error.id).toBe(2);
    }
    expect(res.payload.items[2].kind).toBe("request");
    if (res.payload.items[2].kind === "request") {
      expect(res.payload.items[2].isNotification).toBe(true);
    }
  });

  it("extracts echo id accurately", () => {
    expect(extractEchoId({ id: "abc" })).toBe("abc");
    expect(extractEchoId({ id: 123 })).toBe(123);
    expect(extractEchoId({ id: null })).toBeNull();
    expect(extractEchoId({ id: true })).toBeNull();
    expect(extractEchoId({ id: {} })).toBeNull();
    expect(extractEchoId(null)).toBeNull();
  });
});
