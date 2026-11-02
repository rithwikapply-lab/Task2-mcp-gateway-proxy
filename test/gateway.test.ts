import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import http from "node:http";
import { createApp } from "../src/app.js";
import { createMockServer, MockServerInstance } from "../mock/downstream.js";
import { GatewayConfig } from "../src/config.js";
import { createTestJwt } from "../src/auth.js";
import { Logger } from "../src/logger.js";
import { ErrorCodes } from "../src/jsonrpc.js";

const JWT_SECRET = "super-secret-jwt-key-32-chars-min-len";
const STATIC_TOKENS: Record<string, string> = {
  "admin-token": "admin",
  "viewer-token": "viewer",
  "upper-token": "ADMIN"
};

describe("Gateway Integration & Denial Proof", () => {
  let mockServer: MockServerInstance;
  let mockHttpServer: http.Server;
  let mockPort: number;
  let config: GatewayConfig;
  let logLines: string[] = [];
  let testLogger: Logger;
  let app: any;

  beforeAll(async () => {
    mockServer = createMockServer();
    mockHttpServer = await mockServer.listen(0);
    mockPort = (mockHttpServer.address() as any).port;

    config = {
      port: 8080,
      downstreamUrl: `http://127.0.0.1:${mockPort}/mcp`,
      downstreamTimeoutMs: 500,
      jwtSecret: JWT_SECRET,
      staticTokens: STATIC_TOKENS,
      maxBodyBytes: 1048576
    };

    testLogger = new Logger((line) => {
      logLines.push(line);
    });

    app = createApp(config, testLogger);
  });

  afterAll(async () => {
    await mockServer.close();
  });

  beforeEach(() => {
    mockServer.reset();
    logLines.length = 0;
  });

  describe("Route Guard & HTTP Methods", () => {
    it("GET /healthz returns 200 { status: 'ok' } unauthenticated", async () => {
      const res = await request(app).get("/healthz");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "ok" });
      expect(res.headers["x-request-id"]).toBeDefined();
    });

    it("POST /healthz returns 404", async () => {
      const res = await request(app).post("/healthz");
      expect(res.status).toBe(404);
    });

    it("GET /unknown returns 404", async () => {
      const res = await request(app).get("/unknown");
      expect(res.status).toBe(404);
    });

    it("wrong method on /mcp returns 405 with Allow: POST", async () => {
      for (const method of ["get", "put", "delete", "patch"] as const) {
        const res = await (request(app) as any)[method]("/mcp");
        expect(res.status).toBe(405);
        expect(res.headers["allow"]).toBe("POST");
      }
    });

    it("POST /mcp with non-json content-type returns 415", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "text/plain")
        .send('{"jsonrpc":"2.0","method":"ping"}');
      expect(res.status).toBe(415);
    });

    it("POST /mcp with missing content-type returns 415", async () => {
      const res = await request(app)
        .post("/mcp")
        .unset("Content-Type")
        .send('{"jsonrpc":"2.0","method":"ping"}');
      expect(res.status).toBe(415);
    });

    it("POST /mcp exceeding max body size returns 413", async () => {
      const smallConfig: GatewayConfig = { ...config, maxBodyBytes: 100 };
      const smallApp = createApp(smallConfig, testLogger);
      const largeBody = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "ping",
        padding: "x".repeat(300)
      });

      const res = await request(smallApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send(largeBody);
      expect(res.status).toBe(413);
    });
  });

  describe("HTTP-Level Wire-Format Validation", () => {
    it("malformed JSON returns 400 -32700 with id null", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send('{"jsonrpc":"2.0", method');

      expect(res.status).toBe(400);
      expect(res.body.jsonrpc).toBe("2.0");
      expect(res.body.id).toBeNull();
      expect(res.body.error.code).toBe(ErrorCodes.PARSE_ERROR);
      expect(res.body.error.message).toBe("Parse error");
      expect(mockServer.getStats().count).toBe(0);
    });

    it("empty body returns 400 with id null", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send("");

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCodes.PARSE_ERROR);
      expect(res.body.id).toBeNull();
      expect(mockServer.getStats().count).toBe(0);
    });

    it("JSON scalar returns 400 -32600 with id null", async () => {
      for (const scalar of ["123", '"plain-string"', "true", "null"]) {
        const res = await request(app)
          .post("/mcp")
          .set("Content-Type", "application/json")
          .set("Authorization", "Bearer admin-token")
          .send(scalar);

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe(ErrorCodes.INVALID_REQUEST);
        expect(res.body.id).toBeNull();
        expect(mockServer.getStats().count).toBe(0);
      }
    });

    it("empty batch [] returns 400 -32600 with id null", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send("[]");

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.body.id).toBeNull();
      expect(mockServer.getStats().count).toBe(0);
    });

    it("wrong jsonrpc version returns 400 -32600 with echoed id", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "1.0", id: "echo-test", method: "ping" });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.body.id).toBe("echo-test");
      expect(mockServer.getStats().count).toBe(0);
    });

    it("method not a string returns 400 -32600 with echoed id", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: 42, method: 12345 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCodes.INVALID_REQUEST);
      expect(res.body.id).toBe(42);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("preserves IDs '1', 1, and null exactly in -32001 responses", async () => {
      const ids = ["1", 1, null];
      for (const id of ids) {
        const res = await request(app)
          .post("/mcp")
          .set("Content-Type", "application/json")
          .set("Authorization", "Bearer viewer-token")
          .send({
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: { name: "admin_reset_key", arguments: {} }
          });

        expect(res.status).toBe(200);
        expect(res.body.error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
        expect(res.body.id).toBe(id);
      }
    });

    it("client response objects forwarded untouched", async () => {
      const clientResp = { jsonrpc: "2.0", id: "cr-1", result: { ack: true } };
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send(clientResp);

      expect(res.status).toBe(200);
      expect(mockServer.getStats().count).toBe(1);
    });
  });

  describe("Authentication Failures & Downstream Isolation", () => {
    it("rejects missing authorization with 401 and zero downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(res.headers["www-authenticate"]).toBe("Bearer");
      expect(res.body.error.code).toBe(ErrorCodes.AUTHENTICATION_REQUIRED);
      expect(res.body.id).toBeNull();
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects non-Bearer scheme (Basic) with 401 and 0 downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Basic dXNlcjpwYXNz")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe(ErrorCodes.AUTHENTICATION_REQUIRED);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects empty Bearer with 401 and 0 downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer ")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("accepts lowercase 'bearer' scheme", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "bearer admin-token")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(200);
      expect(mockServer.getStats().count).toBe(1);
    });

    it("rejects double space in header with 401 and 0 downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer  admin-token")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects unknown static token with 401 and 0 downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer unknown-static-token")
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects JWT with bad signature with 401 and 0 downstream calls", async () => {
      const badJwt = createTestJwt({ role: "admin" }, "wrong-secret-123456789012345");
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${badJwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects JWT with alg none with 401 and 0 downstream calls", async () => {
      const noneJwt = createTestJwt({ role: "admin" }, JWT_SECRET, { alg: "none", typ: "JWT" });
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${noneJwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects JWT with alg HS512 with 401 and 0 downstream calls", async () => {
      const hs512Jwt = createTestJwt({ role: "admin" }, JWT_SECRET, { alg: "HS512", typ: "JWT" });
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${hs512Jwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects expired JWT with 401 and 0 downstream calls", async () => {
      const expiredJwt = createTestJwt(
        { role: "admin", exp: Math.floor(Date.now() / 1000) - 15 },
        JWT_SECRET
      );
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${expiredJwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects future nbf JWT with 401 and 0 downstream calls", async () => {
      const futureJwt = createTestJwt(
        { role: "admin", nbf: Math.floor(Date.now() / 1000) + 15 },
        JWT_SECRET
      );
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${futureJwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects JWT missing or non-string role with 401 and 0 downstream calls", async () => {
      const noRoleJwt = createTestJwt({ foo: "bar" }, JWT_SECRET);
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${noRoleJwt}`)
        .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });

      expect(res.status).toBe(401);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("treats role 'ADMIN' as authenticated non-admin: tools/list allowed, admin tool denied", async () => {
      const listRes = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer upper-token")
        .send({ jsonrpc: "2.0", id: "list-1", method: "tools/list" });

      expect(listRes.status).toBe(200);
      expect(mockServer.getStats().count).toBe(1);

      const callRes = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer upper-token")
        .send({
          jsonrpc: "2.0",
          id: "call-1",
          method: "tools/call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      expect(callRes.status).toBe(200);
      expect(callRes.body.error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
      expect(mockServer.getStats().count).toBe(1);
    });
  });

  describe("Notifications Behavior", () => {
    it("denied single notification returns 202 with empty body and zero mock calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          method: "tools/call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      expect(res.status).toBe(202);
      expect(res.text).toBe("");
      expect(mockServer.getStats().count).toBe(0);
    });

    it("allowed single notification forwarded and returns 202 empty", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          method: "ping"
        });

      expect(res.status).toBe(202);
      expect(res.text).toBe("");
      expect(mockServer.getStats().count).toBe(1);
    });

    it("batch [allowed request, denied notification] returns exactly 1 entry", async () => {
      const batch = [
        { jsonrpc: "2.0", id: "req-1", method: "tools/list" },
        { jsonrpc: "2.0", method: "tools/call", params: { name: "admin_reset_key", arguments: {} } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].id).toBe("req-1");
      expect(res.body[0].result).toBeDefined();

      // Mock receives only the allowed tools/list call
      const stats = mockServer.getStats();
      expect(stats.count).toBe(1);
      expect(stats.calls[0].method).toBe("tools/list");
    });
  });

  describe("Method-Level Authorization & Denial Proof", () => {
    it("rejects non-canonical tools/call methods with -32601 and 0 downstream calls", async () => {
      const nonCanonicalMethods = [
        "Tools/Call",
        "TOOLS/CALL",
        "tools/call ",
        "tools/call\u0000"
      ];

      for (let i = 0; i < nonCanonicalMethods.length; i++) {
        mockServer.reset();
        const m = nonCanonicalMethods[i];
        const res = await request(app)
          .post("/mcp")
          .set("Content-Type", "application/json")
          .set("Authorization", "Bearer viewer-token")
          .send({
            jsonrpc: "2.0",
            id: `norm-${i}`,
            method: m,
            params: { name: "admin_reset_key", arguments: {} }
          });

        expect(res.status).toBe(200);
        expect(res.body.jsonrpc).toBe("2.0");
        expect(res.body.id).toBe(`norm-${i}`);
        expect(res.body.error.code).toBe(ErrorCodes.METHOD_NOT_FOUND);
        expect(res.body.error.message).toBe("Method not found");
        expect(mockServer.getStats().count).toBe(0);
      }
    });

    it("returns 202 empty for non-canonical tools/call notification with 0 downstream calls", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          method: "Tools/Call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      expect(res.status).toBe(202);
      expect(res.text).toBe("");
      expect(mockServer.getStats().count).toBe(0);
    });

    it("rejects non-canonical tools/call in batches with -32601 and 0 downstream calls", async () => {
      const batch = [
        { jsonrpc: "2.0", id: 101, method: "Tools/Call", params: { name: "admin_reset_key" } },
        { jsonrpc: "2.0", id: 102, method: "TOOLS/CALL", params: { name: "admin_reset_key" } },
        { jsonrpc: "2.0", id: 103, method: "tools/call ", params: { name: "admin_reset_key" } },
        { jsonrpc: "2.0", id: 104, method: "tools/call\u0000", params: { name: "admin_reset_key" } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(4);
      for (let i = 0; i < 4; i++) {
        expect(res.body[i].id).toBe(101 + i);
        expect(res.body[i].error.code).toBe(ErrorCodes.METHOD_NOT_FOUND);
        expect(res.body[i].error.message).toBe("Method not found");
      }
      expect(mockServer.getStats().count).toBe(0);
    });

    it("handles mixed batch with allowed call and non-canonical tools/call", async () => {
      const batch = [
        { jsonrpc: "2.0", id: "ok-1", method: "tools/list" },
        { jsonrpc: "2.0", id: "bad-1", method: "Tools/Call", params: { name: "admin_reset_key" } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(2);
      expect(res.body[0].id).toBe("ok-1");
      expect(res.body[0].result.tools).toBeDefined();
      expect(res.body[1].id).toBe("bad-1");
      expect(res.body[1].error.code).toBe(ErrorCodes.METHOD_NOT_FOUND);
      expect(mockServer.getStats().count).toBe(1);
    });

    it("forwards tools/list unmodified for viewer and admin", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({ jsonrpc: "2.0", id: 10, method: "tools/list" });

      expect(res.status).toBe(200);
      expect(res.body.result.tools).toHaveLength(4);
      expect(mockServer.getStats().count).toBe(1);
    });

    it("intercepts admin_reset_key for viewer: returns -32001, mock call count UNCHANGED", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          id: 20,
          method: "tools/call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      expect(res.status).toBe(200);
      expect(res.body.jsonrpc).toBe("2.0");
      expect(res.body.id).toBe(20);
      expect(res.body.error).toEqual({
        code: ErrorCodes.UNAUTHORIZED_TOOL_CALL,
        message: "Unauthorized Tool Call",
        data: {
          tool: "admin_reset_key",
          requiredRole: "admin"
        }
      });
      expect(mockServer.getStats().count).toBe(0);
    });

    it("proves downstream count unchanged for all unauthorized admin tool variants", async () => {
      const variants = [
        "admin_",
        "Admin_reset_key",
        "ADMIN_reset_key",
        " admin_x",
        "ａｄｍｉｎ_x"
      ];

      let reqId = 100;
      for (const tool of variants) {
        reqId++;
        const res = await request(app)
          .post("/mcp")
          .set("Content-Type", "application/json")
          .set("Authorization", "Bearer viewer-token")
          .send({
            jsonrpc: "2.0",
            id: reqId,
            method: "tools/call",
            params: { name: tool, arguments: {} }
          });

        expect(res.status).toBe(200);
        expect(res.body.error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
        expect(mockServer.getStats().count).toBe(0);
      }
    });

    it("allows non-admin tool get_status for viewer", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          id: 30,
          method: "tools/call",
          params: { name: "get_status", arguments: {} }
        });

      expect(res.status).toBe(200);
      expect(res.body.result.content[0].text).toBe("System is healthy");
      expect(mockServer.getStats().count).toBe(1);
    });

    it("allows admin_reset_key for admin", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({
          jsonrpc: "2.0",
          id: 40,
          method: "tools/call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      expect(res.status).toBe(200);
      expect(res.body.result.content[0].text).toBe("Key reset successfully");
      expect(mockServer.getStats().count).toBe(1);
    });

    it("returns -32602 directly when params or tool name is invalid", async () => {
      const resNoParams = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({ jsonrpc: "2.0", id: 50, method: "tools/call" });

      expect(resNoParams.status).toBe(200);
      expect(resNoParams.body.error.code).toBe(ErrorCodes.INVALID_PARAMS);
      expect(mockServer.getStats().count).toBe(0);

      const resBadName = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({ jsonrpc: "2.0", id: 51, method: "tools/call", params: { name: 123 } });

      expect(resBadName.status).toBe(200);
      expect(resBadName.body.error.code).toBe(ErrorCodes.INVALID_PARAMS);
      expect(mockServer.getStats().count).toBe(0);
    });
  });

  describe("Forwarding Integrity & Header Allowlist", () => {
    it("forwards ONLY allowlisted headers and drops Cookie, X-Forwarded-For, X-Role, Authorization", async () => {
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/plain")
        .set("mcp-session-id", "session-xyz-123")
        .set("mcp-protocol-version", "2024-11-05")
        .set("Authorization", "Bearer admin-token")
        .set("Cookie", "session_id=secret123")
        .set("X-Forwarded-For", "10.0.0.1")
        .set("X-Role", "admin")
        .send({ jsonrpc: "2.0", id: 60, method: "ping" });

      const stats = mockServer.getStats();
      expect(stats.count).toBe(1);
      const headers = stats.calls[0].receivedHeaders;

      // Allowlisted headers are present
      expect(headers).toContain("content-type");
      expect(headers).toContain("accept");
      expect(headers).toContain("mcp-session-id");
      expect(headers).toContain("mcp-protocol-version");

      // Non-allowlisted headers are NEVER present
      expect(headers).not.toContain("authorization");
      expect(headers).not.toContain("cookie");
      expect(headers).not.toContain("x-forwarded-for");
      expect(headers).not.toContain("x-role");
    });

    it("tools/list body fetched through gateway is byte-for-byte identical to direct mock response", async () => {
      // 1. Direct call to mock
      const mockDirect = await request(mockHttpServer)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .send({ jsonrpc: "2.0", id: "byte-cmp", method: "tools/list" });

      // 2. Proxied call through gateway
      const gatewayProxied = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "byte-cmp", method: "tools/list" });

      expect(gatewayProxied.status).toBe(mockDirect.status);
      expect(gatewayProxied.text).toBe(mockDirect.text);
    });

    it("passes through mcp-session-id response header and content-type on initialize", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "init-1", method: "initialize" });

      expect(res.status).toBe(200);
      expect(res.headers["mcp-session-id"]).toBe("mock-session-12345");
      expect(res.headers["content-type"]).toContain("application/json");
    });

    it("streams SSE text/event-stream chunks without buffering", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "sse-1", method: "test/sse" });

      expect(res.status).toBe(200);
      expect(res.headers["content-type"]).toContain("text/event-stream");
      expect(res.text).toBe("event: message\ndata: chunk-one\n\nevent: message\ndata: chunk-two\n\n");
    });
  });

  describe("Batch Handling & Queue Reply Matching", () => {
    it("handles [ok, denied, ok]: 3 ordered replies, one -32001, downstream receives exactly 2", async () => {
      const batch = [
        { jsonrpc: "2.0", id: "b1", method: "tools/list" },
        { jsonrpc: "2.0", id: "b2", method: "tools/call", params: { name: "admin_reset_key", arguments: {} } },
        { jsonrpc: "2.0", id: "b3", method: "tools/call", params: { name: "get_status", arguments: {} } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body).toHaveLength(3);

      expect(res.body[0].id).toBe("b1");
      expect(res.body[0].result).toBeDefined();

      expect(res.body[1].id).toBe("b2");
      expect(res.body[1].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);

      expect(res.body[2].id).toBe("b3");
      expect(res.body[2].result).toBeDefined();

      const stats = mockServer.getStats();
      expect(stats.count).toBe(2);
      expect(stats.calls.map((c) => c.method)).toEqual(["tools/list", "tools/call"]);
      expect(stats.calls.map((c) => c.tool)).toEqual([undefined, "get_status"]);
    });

    it("handles two allowed calls with the same duplicate id without dropping either", async () => {
      const batch = [
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 1, method: "ping" }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(2);
      expect(res.body[0].id).toBe(1);
      expect(res.body[0].result.tools).toBeDefined();
      expect(res.body[1].id).toBe(1);
      expect(res.body[1].result).toEqual({});
    });

    it("handles allowed id 1 plus denied id 1 without collision", async () => {
      const batch = [
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "admin_reset_key", arguments: {} } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(2);
      expect(res.body[0].id).toBe(1);
      expect(res.body[0].result.tools).toBeDefined();
      expect(res.body[1].id).toBe(1);
      expect(res.body[1].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
    });

    it("handles allowed request with id: null expecting a response", async () => {
      const batch = [
        { jsonrpc: "2.0", id: null, method: "tools/list" }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].id).toBeNull();
      expect(res.body[0].result.tools).toBeDefined();
    });

    it("handles all-denied batch: returns -32001 errors, zero downstream calls", async () => {
      const batch = [
        { jsonrpc: "2.0", id: "d1", method: "tools/call", params: { name: "admin_reset_key", arguments: {} } },
        { jsonrpc: "2.0", id: "d2", method: "tools/call", params: { name: "admin_delete_user", arguments: {} } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(2);
      expect(res.body[0].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
      expect(res.body[1].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);
      expect(mockServer.getStats().count).toBe(0);
    });

    it("handles notifications-only batch: returns 202 with empty body", async () => {
      const batch = [
        { jsonrpc: "2.0", method: "ping" }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(202);
      expect(res.text).toBe("");
      expect(mockServer.getStats().count).toBe(1);
    });

    it("prevents viewer smuggling attempt [list, admin call]", async () => {
      const batch = [
        { jsonrpc: "2.0", id: "s1", method: "tools/list" },
        { jsonrpc: "2.0", id: "s2", method: "tools/call", params: { name: "admin_delete_user", arguments: {} } }
      ];

      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send(batch);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(2);
      expect(res.body[0].id).toBe("s1");
      expect(res.body[0].result).toBeDefined();
      expect(res.body[1].id).toBe("s2");
      expect(res.body[1].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);

      expect(mockServer.getStats().count).toBe(1);
      expect(mockServer.getStats().calls[0].method).toBe("tools/list");
    });
  });

  describe("Downstream Errors (502 / 504)", () => {
    it("returns 502 with code -32003 when downstream is down, never leaking URL", async () => {
      const deadConfig: GatewayConfig = {
        ...config,
        downstreamUrl: "http://127.0.0.1:49999/mcp"
      };
      const deadApp = createApp(deadConfig, testLogger);

      const res = await request(deadApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "dead-1", method: "tools/list" });

      expect(res.status).toBe(502);
      expect(res.body.jsonrpc).toBe("2.0");
      expect(res.body.id).toBe("dead-1");
      expect(res.body.error.code).toBe(ErrorCodes.DOWNSTREAM_UNAVAILABLE);
      expect(res.body.error.message).toBe("Bad Gateway");
      expect(JSON.stringify(res.body)).not.toContain("49999");
      expect(JSON.stringify(res.body)).not.toContain("ECONNREFUSED");
    });

    it("returns 504 with code -32004 on downstream timeout, never leaking URL", async () => {
      const slowServer = http.createServer((_req, res) => {
        setTimeout(() => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
        }, 2000);
      });
      await new Promise<void>((resolve) => slowServer.listen(0, resolve));
      const slowPort = (slowServer.address() as any).port;

      const timeoutConfig: GatewayConfig = {
        ...config,
        downstreamUrl: `http://127.0.0.1:${slowPort}/mcp`,
        downstreamTimeoutMs: 100
      };
      const timeoutApp = createApp(timeoutConfig, testLogger);

      const res = await request(timeoutApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "timeout-1", method: "tools/list" });

      slowServer.close();

      expect(res.status).toBe(504);
      expect(res.body.jsonrpc).toBe("2.0");
      expect(res.body.id).toBe("timeout-1");
      expect(res.body.error.code).toBe(ErrorCodes.DOWNSTREAM_TIMEOUT);
      expect(res.body.error.message).toBe("Gateway Timeout");
      expect(JSON.stringify(res.body)).not.toContain(`${slowPort}`);
    });
  });

  describe("Security, Logger & Error Middleware", () => {
    it("ensures logs NEVER contain tokens or Authorization headers across denied, 401, and downstream-down cases", async () => {
      // 1. Success call
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: 91, method: "tools/list" });

      // 2. Denied call
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer viewer-token")
        .send({
          jsonrpc: "2.0",
          id: 92,
          method: "tools/call",
          params: { name: "admin_reset_key", arguments: {} }
        });

      // 3. 401 Auth failure
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer bad-token-12345")
        .send({ jsonrpc: "2.0", id: 93, method: "tools/list" });

      // 4. Downstream down
      const deadConfig: GatewayConfig = {
        ...config,
        downstreamUrl: "http://127.0.0.1:49999/mcp"
      };
      const deadApp = createApp(deadConfig, testLogger);
      await request(deadApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: 94, method: "tools/list" });

      expect(logLines.length).toBeGreaterThanOrEqual(4);
      for (const line of logLines) {
        expect(line).not.toContain("admin-token");
        expect(line).not.toContain("viewer-token");
        expect(line).not.toContain("bad-token-12345");
        expect(line).not.toContain("Bearer");
        expect(line).not.toContain("bearer");
      }
    });

    it("handles forced throw via injected forwarder with 500 -32603 and no stack or secrets in response", async () => {
      const injectedApp = createApp(config, testLogger, {
        forwardSingleStream: async () => {
          throw new Error("SecretDatabasePasswordFailure: db://root:secret@10.0.0.1");
        }
      });

      const res = await request(injectedApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "throw-1", method: "ping" });

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe(ErrorCodes.INTERNAL_ERROR);
      expect(res.body.error.message).toBe("Internal error");
      expect(res.body.id).toBeNull();
      expect(JSON.stringify(res.body)).not.toContain("SecretDatabasePasswordFailure");
      expect(JSON.stringify(res.body)).not.toContain("secret@10.0.0.1");
      expect(JSON.stringify(res.body)).not.toContain("stack");
    });
  });
});
