import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createApp } from "../src/app.js";
import { GatewayConfig } from "../src/config.js";

describe("Real SSE Streaming Verification (node:http)", () => {
  let downstreamServer: http.Server;
  let downstreamPort: number;
  let gatewayServer: http.Server;
  let gatewayPort: number;

  beforeAll(async () => {
    // 1. Start throwaway downstream SSE server
    downstreamServer = http.createServer((req, res) => {
      if (req.url === "/mcp" && req.method === "POST") {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive"
        });
        res.write("event: message\ndata: chunk 1\n\n");
        setTimeout(() => {
          res.write("event: message\ndata: chunk 2\n\n");
          res.end();
        }, 1500);
        return;
      }
      res.writeHead(404).end();
    });

    await new Promise<void>((resolve) => downstreamServer.listen(0, resolve));
    downstreamPort = (downstreamServer.address() as any).port;

    // 2. Start gateway app on dynamic port
    const config: GatewayConfig = {
      port: 0,
      downstreamUrl: `http://127.0.0.1:${downstreamPort}/mcp`,
      downstreamTimeoutMs: 5000,
      jwtSecret: "test-secret-key-32-chars-long-0123",
      staticTokens: { "admin-token": "admin" },
      maxBodyBytes: 1048576
    };

    const app = createApp(config);
    gatewayServer = http.createServer(app);
    await new Promise<void>((resolve) => gatewayServer.listen(0, resolve));
    gatewayPort = (gatewayServer.address() as any).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => downstreamServer.close(() => resolve()));
    await new Promise<void>((resolve) => gatewayServer.close(() => resolve()));
  });

  it("proves chunk 1 arrives well before chunk 2 (gap > 1000ms) with text/event-stream", async () => {
    const chunkEvents: { time: number; chunk: string }[] = [];
    let contentTypeHeader: string | undefined;
    let statusCode: number | undefined;

    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: gatewayPort,
          path: "/mcp",
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "Authorization": "Bearer admin-token"
          }
        },
        (res) => {
          statusCode = res.statusCode;
          contentTypeHeader = res.headers["content-type"];

          res.on("data", (chunk) => {
            chunkEvents.push({
              time: Date.now(),
              chunk: chunk.toString("utf8")
            });
          });

          res.on("end", () => {
            resolve();
          });
        }
      );

      req.on("error", reject);
      req.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
      req.end();
    });

    expect(statusCode).toBe(200);
    expect(contentTypeHeader).toBe("text/event-stream");
    expect(chunkEvents.length).toBeGreaterThanOrEqual(2);

    const firstChunk = chunkEvents[0];
    const secondChunk = chunkEvents[1];

    expect(firstChunk.chunk).toContain("chunk 1");
    expect(secondChunk.chunk).toContain("chunk 2");

    const gapMs = secondChunk.time - firstChunk.time;
    // Expected delay is 1500 ms; must be well above 1000 ms to prove true unbuffered streaming
    expect(gapMs).toBeGreaterThan(1000);
    expect(gapMs).toBeLessThan(2500);
  }, 10000);
});
