import express, { Request, Response } from "express";
import http from "node:http";
import { fileURLToPath } from "node:url";

export interface RecordedCall {
  method: string;
  tool?: string;
  hasAuthorization: boolean;
  timestamp: string;
}

export interface MockServerInstance {
  app: express.Express;
  server?: http.Server;
  getStats: () => { count: number; calls: RecordedCall[] };
  reset: () => void;
  listen: (port?: number) => Promise<http.Server>;
  close: () => Promise<void>;
}

export function createMockServer(): MockServerInstance {
  const app = express();
  const recordedCalls: RecordedCall[] = [];

  // Parse raw text/json bodies
  app.use(express.json({ limit: "10mb" }));

  app.get("/__stats", (_req: Request, res: Response) => {
    res.json({
      count: recordedCalls.length,
      calls: [...recordedCalls]
    });
  });

  app.post("/__reset", (_req: Request, res: Response) => {
    recordedCalls.length = 0;
    res.json({ status: "reset" });
  });

  function handleSingle(reqObj: any, hasAuth: boolean): any {
    const isNotification = !("id" in reqObj);
    const id = isNotification ? null : reqObj.id;
    const method = reqObj.method;
    const tool = reqObj.params && typeof reqObj.params === "object" ? reqObj.params.name : undefined;

    recordedCalls.push({
      method,
      tool,
      hasAuthorization: hasAuth,
      timestamp: new Date().toISOString()
    });

    if (isNotification) {
      return null;
    }

    if (method === "initialize") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "mock-downstream-mcp",
            version: "1.0.0"
          }
        }
      };
    }

    if (method === "ping") {
      return {
        jsonrpc: "2.0",
        id,
        result: {}
      };
    }

    if (method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: [
            { name: "get_status", description: "Get system status" },
            { name: "list_users", description: "List users" },
            { name: "admin_reset_key", description: "Reset system API key" },
            { name: "admin_delete_user", description: "Delete user record" }
          ]
        }
      };
    }

    if (method === "tools/call") {
      const toolName = reqObj.params?.name;
      if (toolName === "get_status") {
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: "System is healthy" }] }
        };
      }
      if (toolName === "list_users") {
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(["alice", "bob"]) }] }
        };
      }
      if (toolName === "admin_reset_key") {
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: "Key reset successfully" }] }
        };
      }
      if (toolName === "admin_delete_user") {
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: "User deleted" }] }
        };
      }

      // Unknown tool name
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32602,
          message: `Unknown tool: ${toolName}`
        }
      };
    }

    // Unknown method
    return {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32601,
        message: `Method not found: ${method}`
      }
    };
  }

  app.post("/mcp", (req: Request, res: Response) => {
    const hasAuth = Boolean(req.headers.authorization);
    const body = req.body;

    if (Array.isArray(body)) {
      const results: any[] = [];
      for (const item of body) {
        const itemRes = handleSingle(item, hasAuth);
        if (itemRes !== null) {
          results.push(itemRes);
        }
      }
      if (results.length === 0) {
        res.status(202).end();
        return;
      }
      res.json(results);
      return;
    }

    const singleRes = handleSingle(body, hasAuth);
    if (singleRes === null) {
      res.status(202).end();
      return;
    }
    res.json(singleRes);
  });

  let runningServer: http.Server | undefined;

  return {
    app,
    getStats: () => ({ count: recordedCalls.length, calls: [...recordedCalls] }),
    reset: () => {
      recordedCalls.length = 0;
    },
    listen: (port: number = 4001) => {
      return new Promise<http.Server>((resolve) => {
        runningServer = app.listen(port, () => {
          resolve(runningServer!);
        });
      });
    },
    close: () => {
      return new Promise<void>((resolve, reject) => {
        if (!runningServer) {
          resolve();
          return;
        }
        runningServer.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  };
}

// Standalone execution entrypoint
const currentFilePath = fileURLToPath(import.meta.url);
if (process.argv[1] && currentFilePath === process.argv[1]) {
  const port = process.env.PORT ? Number(process.env.PORT) : 4001;
  const mockInstance = createMockServer();
  mockInstance.listen(port).then(() => {
    process.stderr.write(`[mock-downstream] Listening on port ${port}\n`);
  });
}
