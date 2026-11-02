import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, ChildProcess } from "node:child_process";
import net from "node:net";
import path from "node:path";

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

async function waitForHttp(url: string, maxAttempts = 50): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch(url);
      if (res.status < 500) return;
    } catch {
      // Server not ready yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Server at ${url} failed to start in time`);
}

describe("End-to-End Spawned Process Tests", () => {
  let mockProcess: ChildProcess;
  let gatewayProcess: ChildProcess;
  let mockPort: number;
  let gatewayPort: number;
  let gatewayUrl: string;
  let mockUrl: string;

  beforeAll(async () => {
    mockPort = await getFreePort();
    gatewayPort = await getFreePort();

    mockUrl = `http://127.0.0.1:${mockPort}`;
    gatewayUrl = `http://127.0.0.1:${gatewayPort}`;

    // 1. Spawn Mock Downstream Server
    mockProcess = spawn(
      "node",
      [path.resolve(process.cwd(), "dist/mock/downstream.js")],
      {
        env: {
          ...process.env,
          PORT: String(mockPort)
        },
        stdio: "pipe"
      }
    );

    await waitForHttp(`${mockUrl}/__stats`);

    // 2. Spawn Gateway Process
    gatewayProcess = spawn(
      "node",
      [path.resolve(process.cwd(), "dist/src/index.js")],
      {
        env: {
          ...process.env,
          PORT: String(gatewayPort),
          DOWNSTREAM_URL: `${mockUrl}/mcp`,
          DOWNSTREAM_TIMEOUT_MS: "5000",
          GATEWAY_STATIC_TOKENS: JSON.stringify({
            "e2e-admin": "admin",
            "e2e-viewer": "viewer"
          })
        },
        stdio: "pipe"
      }
    );

    await waitForHttp(`${gatewayUrl}/healthz`);
  }, 15000);

  afterAll(async () => {
    if (gatewayProcess && !gatewayProcess.killed) {
      gatewayProcess.kill("SIGKILL");
    }
    if (mockProcess && !mockProcess.killed) {
      mockProcess.kill("SIGKILL");
    }
  });

  it("GET /healthz returns ok on the live gateway process", async () => {
    const res = await fetch(`${gatewayUrl}/healthz`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ status: "ok" });
    expect(res.headers.get("x-request-id")).toBeDefined();
  });

  it("handles full lifecycle: viewer allowed list, viewer denied admin call, admin allowed admin call", async () => {
    // 1. Reset mock stats
    await fetch(`${mockUrl}/__reset`, { method: "POST" });

    // 2. Viewer calls tools/list -> allowed & forwarded
    const listRes = await fetch(`${gatewayUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer e2e-viewer"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: "e2e-1", method: "tools/list" })
    });
    expect(listRes.status).toBe(200);
    const listBody = await listRes.json();
    expect(listBody.result.tools).toHaveLength(4);

    // 3. Viewer attempts admin_reset_key -> intercepted by gateway directly
    const deniedRes = await fetch(`${gatewayUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer e2e-viewer"
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "e2e-2",
        method: "tools/call",
        params: { name: "admin_reset_key", arguments: {} }
      })
    });
    expect(deniedRes.status).toBe(200);
    const deniedBody = await deniedRes.json();
    expect(deniedBody.error.code).toBe(-32001);
    expect(deniedBody.error.message).toBe("Unauthorized Tool Call");
    expect(deniedBody.error.data).toEqual({
      tool: "admin_reset_key",
      requiredRole: "admin"
    });

    // 4. Admin calls admin_reset_key -> forwarded & executed
    const adminRes = await fetch(`${gatewayUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer e2e-admin"
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "e2e-3",
        method: "tools/call",
        params: { name: "admin_reset_key", arguments: {} }
      })
    });
    expect(adminRes.status).toBe(200);
    const adminBody = await adminRes.json();
    expect(adminBody.result.content[0].text).toBe("Key reset successfully");

    // 5. Query mock server stats: prove downstream received exactly 2 calls (never the viewer's admin call)
    const statsRes = await fetch(`${mockUrl}/__stats`);
    const statsBody = await statsRes.json();
    expect(statsBody.count).toBe(2);
    expect(statsBody.calls[0].method).toBe("tools/list");
    expect(statsBody.calls[1].method).toBe("tools/call");
    expect(statsBody.calls[1].tool).toBe("admin_reset_key");
    // Also prove Authorization header was stripped before downstream received calls
    expect(statsBody.calls[0].hasAuthorization).toBe(false);
    expect(statsBody.calls[1].hasAuthorization).toBe(false);
  });
});
