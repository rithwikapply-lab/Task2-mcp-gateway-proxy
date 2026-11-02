import { describe, it, expect } from "vitest";
import { authorize, normalizeToolName } from "../src/policy.js";
import { ErrorCodes, JsonRpcRequest } from "../src/jsonrpc.js";

describe("Policy Authorization Matrix", () => {
  it("allows tools/list for both admin and viewer", () => {
    const listReq: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    expect(authorize("admin", listReq)).toEqual({ allowed: true });
    expect(authorize("viewer", listReq)).toEqual({ allowed: true });
    expect(authorize("ADMIN", listReq)).toEqual({ allowed: true });
  });

  it("allows non-admin tool get_status for both admin and viewer", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "get_status", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    expect(authorize("viewer", callReq)).toEqual({ allowed: true });
  });

  it("authorizes exact admin_reset_key for admin, denies for viewer", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "admin_reset_key", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });

    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
    if (viewerDec.allowed) return;
    expect(viewerDec.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
    expect(viewerDec.message).toBe("Unauthorized Tool Call");
    expect(viewerDec.data).toEqual({ tool: "admin_reset_key", requiredRole: "admin" });
  });

  it("authorizes tool named exactly 'admin_' for admin, denies for viewer", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "admin_", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
    if (viewerDec.allowed) return;
    expect(viewerDec.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
  });

  it("enforces normalized hardening: Admin_reset_key", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "Admin_reset_key", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
    if (viewerDec.allowed) return;
    expect(viewerDec.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
  });

  it("enforces normalized hardening: ADMIN_reset_key", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "ADMIN_reset_key", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
  });

  it("enforces normalized hardening: leading space ' admin_x'", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: " admin_x", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
  });

  it("allows 'xadmin_y' for both admin and viewer", () => {
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "xadmin_y", arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    expect(authorize("viewer", callReq)).toEqual({ allowed: true });
  });

  it("enforces normalized hardening: full-width unicode 'ａｄｍｉｎ_x'", () => {
    const fullWidth = "ａｄｍｉｎ_x";
    expect(normalizeToolName(fullWidth)).toBe("admin_x");
    const callReq: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: fullWidth, arguments: {} }
    };
    expect(authorize("admin", callReq)).toEqual({ allowed: true });
    const viewerDec = authorize("viewer", callReq);
    expect(viewerDec.allowed).toBe(false);
  });

  it("rejects tools/call with missing or invalid params with -32602", () => {
    const reqNoParams: JsonRpcRequest = { jsonrpc: "2.0", id: 10, method: "tools/call" };
    const decNoParams = authorize("admin", reqNoParams);
    expect(decNoParams.allowed).toBe(false);
    if (decNoParams.allowed) return;
    expect(decNoParams.code).toBe(ErrorCodes.INVALID_PARAMS);

    const reqArrayParams: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: ["item"]
    };
    const decArray = authorize("admin", reqArrayParams);
    expect(decArray.allowed).toBe(false);
    if (decArray.allowed) return;
    expect(decArray.code).toBe(ErrorCodes.INVALID_PARAMS);
  });

  it("rejects tools/call with invalid name type (number, null, empty, array)", () => {
    for (const badName of [123, null, "", [], {}]) {
      const callReq: JsonRpcRequest = {
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: { name: badName as any }
      };
      const dec = authorize("admin", callReq);
      expect(dec.allowed).toBe(false);
      if (dec.allowed) return;
      expect(dec.code).toBe(ErrorCodes.INVALID_PARAMS);
    }
  });

  it("allows arbitrary other methods (e.g. initialize, ping) for any authenticated role", () => {
    for (const method of ["initialize", "ping", "notifications/initialized", "custom_method"]) {
      const req: JsonRpcRequest = { jsonrpc: "2.0", id: 13, method };
      expect(authorize("admin", req)).toEqual({ allowed: true });
      expect(authorize("viewer", req)).toEqual({ allowed: true });
    }
  });
});
