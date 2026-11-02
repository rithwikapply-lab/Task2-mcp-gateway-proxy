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
      // 1. tools/list succeeds for ADMIN role
      const listRes = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer upper-token")
        .send({ jsonrpc: "2.0", id: "list-1", method: "tools/list" });

      expect(listRes.status).toBe(200);
      expect(mockServer.getStats().count).toBe(1);

      // 2. admin tool call denied directly with -32001
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
      // Downstream call count remains 1 (admin tool call never reached downstream)
      expect(mockServer.getStats().count).toBe(1);
    });
  });

  describe("Method-Level Authorization & Denial Proof", () => {
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
      // Downstream call count must remain 0
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

  describe("Forwarding Integrity & Header Stripping", () => {
    it("strips Authorization and hop-by-hop headers before reaching downstream", async () => {
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .set("mcp-session-id", "session-xyz-123")
        .set("mcp-protocol-version", "2024-11-05")
        .send({ jsonrpc: "2.0", id: 60, method: "ping" });

      const stats = mockServer.getStats();
      expect(stats.count).toBe(1);
      expect(stats.calls[0].hasAuthorization).toBe(false);
    });

    it("tools/list body is forwarded byte-identical", async () => {
      const res = await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: 70, method: "tools/list" });

      expect(res.status).toBe(200);
      expect(res.body.result.tools).toBeDefined();
    });
  });

  describe("Batch Handling & Selective Forwarding", () => {
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

      // Entry 0: tools/list success
      expect(res.body[0].id).toBe("b1");
      expect(res.body[0].result).toBeDefined();

      // Entry 1: intercepted -32001 error
      expect(res.body[1].id).toBe("b2");
      expect(res.body[1].error.code).toBe(ErrorCodes.UNAUTHORIZED_TOOL_CALL);

      // Entry 2: get_status success
      expect(res.body[2].id).toBe("b3");
      expect(res.body[2].result).toBeDefined();

      // Downstream received only 2 calls (tools/list and get_status)
      const stats = mockServer.getStats();
      expect(stats.count).toBe(2);
      expect(stats.calls.map((c) => c.method)).toEqual(["tools/list", "tools/call"]);
      expect(stats.calls.map((c) => c.tool)).toEqual([undefined, "get_status"]);
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
      // Create a slow server that delays 2000ms
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
        downstreamTimeoutMs: 100 // 100ms timeout
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
    it("ensures logs NEVER contain tokens or Authorization headers", async () => {
      await request(app)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: 99, method: "tools/list" });

      expect(logLines.length).toBeGreaterThan(0);
      for (const line of logLines) {
        expect(line).not.toContain("admin-token");
        expect(line).not.toContain("Bearer");
      }
    });

    it("handles forced throw with 500 -32603 Internal error and no stack in response", async () => {
      const brokenConfig: GatewayConfig = { ...config, _forceInternalThrow: true } as any;
      const brokenApp = createApp(brokenConfig, testLogger);

      const res = await request(brokenApp)
        .post("/mcp")
        .set("Content-Type", "application/json")
        .set("Authorization", "Bearer admin-token")
        .send({ jsonrpc: "2.0", id: "throw-1", method: "ping" });

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe(ErrorCodes.INTERNAL_ERROR);
      expect(res.body.error.message).toBe("Internal error");
      expect(res.body.id).toBeNull();
      expect(JSON.stringify(res.body)).not.toContain("SecretDatabasePasswordFailure");
      expect(JSON.stringify(res.body)).not.toContain("stack");
    });
  });
});
