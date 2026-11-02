import express, { Request, Response, NextFunction } from "express";
import crypto from "node:crypto";
import { GatewayConfig } from "./config.js";
import { Logger, logger as defaultLogger } from "./logger.js";
import { authenticate } from "./auth.js";
import {
  ErrorCodes,
  ErrorHttpStatuses,
  createJsonRpcError,
  parseJsonRpcPayload,
  JsonRpcId,
  ParsedItem
} from "./jsonrpc.js";
import { authorize } from "./policy.js";
import {
  ForwardError,
  forwardBatchJson as defaultForwardBatchJson,
  forwardSingleStream as defaultForwardSingleStream
} from "./forward.js";

export interface AppDependencies {
  forwardSingleStream?: typeof defaultForwardSingleStream;
  forwardBatchJson?: typeof defaultForwardBatchJson;
}

export function createApp(
  config: GatewayConfig,
  customLogger?: Logger,
  deps?: AppDependencies
): express.Express {
  const app = express();
  const log = customLogger || defaultLogger;
  const forwardStream = deps?.forwardSingleStream || defaultForwardSingleStream;
  const forwardBatch = deps?.forwardBatchJson || defaultForwardBatchJson;

  // 1. Request ID middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    const reqId = crypto.randomUUID();
    (req as any).reqId = reqId;
    (req as any).startTime = Date.now();
    res.setHeader("X-Request-Id", reqId);
    next();
  });

  // 2. Route guard
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === "/healthz") {
      if (req.method === "GET") {
        res.status(200).json({ status: "ok" });
        return;
      }
      res.status(404).end();
      return;
    }

    if (req.path === "/mcp") {
      if (req.method !== "POST") {
        res.setHeader("Allow", "POST");
        res.status(405).end();
        return;
      }
      next();
      return;
    }

    res.status(404).end();
  });

  // 3. Content-Type check & raw body parsing
  app.use("/mcp", (req: Request, res: Response, next: NextFunction) => {
    const contentType = req.headers["content-type"];
    if (!contentType) {
      res.status(415).end();
      return;
    }

    const mediaType = contentType.split(";")[0].trim().toLowerCase();
    if (mediaType !== "application/json") {
      res.status(415).end();
      return;
    }

    next();
  });

  app.use(
    "/mcp",
    express.raw({
      type: "*/*",
      limit: config.maxBodyBytes
    })
  );

  // 4. Main MCP handler
  app.post("/mcp", async (req: Request, res: Response, next: NextFunction) => {
    const reqId = (req as any).reqId as string;
    const startTime = (req as any).startTime as number;

    try {
      // Authenticate
      const authHeader = req.headers.authorization;
      const authRes = authenticate(authHeader, config.staticTokens, config.jwtSecret);

      if (!authRes.authenticated) {
        res.setHeader("WWW-Authenticate", "Bearer");
        const authError = createJsonRpcError(
          ErrorCodes.AUTHENTICATION_REQUIRED,
          "Authentication required",
          null
        );
        res.status(401).json(authError);

        log.warn({
          reqId,
          role: null,
          method: null,
          tool: null,
          decision: "deny",
          status: 401,
          durationMs: Date.now() - startTime
        });
        return;
      }

      const role = authRes.role;

      // Parse JSON body
      const rawBuffer = req.body as Buffer;
      if (!rawBuffer || rawBuffer.length === 0) {
        const parseErr = createJsonRpcError(ErrorCodes.PARSE_ERROR, "Parse error", null);
        res.status(400).json(parseErr);
        log.error({
          reqId,
          role,
          method: null,
          tool: null,
          decision: "error",
          status: 400,
          durationMs: Date.now() - startTime
        });
        return;
      }

      const rawText = rawBuffer.toString("utf8");
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(rawText);
      } catch {
        const parseErr = createJsonRpcError(ErrorCodes.PARSE_ERROR, "Parse error", null);
        res.status(400).json(parseErr);
        log.error({
          reqId,
          role,
          method: null,
          tool: null,
          decision: "error",
          status: 400,
          durationMs: Date.now() - startTime
        });
        return;
      }

      const { error: payloadErr, payload } = parseJsonRpcPayload(parsedJson);
      if (payloadErr) {
        res.status(400).json(payloadErr);
        log.error({
          reqId,
          role,
          method: null,
          tool: null,
          decision: "error",
          status: 400,
          durationMs: Date.now() - startTime
        });
        return;
      }

      if (!payload) {
        const invalidReq = createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", null);
        res.status(400).json(invalidReq);
        return;
      }

      // Handle single item
      if (!payload.isBatch) {
        const item: ParsedItem = payload.item;

        if (item.kind === "client_response") {
          await forwardStream(req, res, rawBuffer, config, item.id);
          log.info({
            reqId,
            role,
            method: null,
            tool: null,
            decision: "allow",
            status: res.statusCode || 200,
            durationMs: Date.now() - startTime
          });
          return;
        }

        if (item.kind === "error") {
          res.status(400).json(item.error);
          log.warn({
            reqId,
            role,
            method: null,
            tool: null,
            decision: "error",
            status: 400,
            durationMs: Date.now() - startTime
          });
          return;
        }

        // item.kind === "request"
        const toolName =
          item.request.params && typeof item.request.params === "object" && !Array.isArray(item.request.params)
            ? (item.request.params as Record<string, unknown>).name
            : undefined;

        const decision = authorize(role, item.request);
        if (!decision.allowed) {
          // If the denied item is a notification (no id), omit response body
          if (item.isNotification) {
            res.status(202).end();
            log.warn({
              reqId,
              role,
              method: item.request.method,
              tool: typeof toolName === "string" ? toolName : null,
              decision: "deny",
              status: 202,
              durationMs: Date.now() - startTime
            });
            return;
          }

          const status = ErrorHttpStatuses[decision.code] || 200;
          const errRes = createJsonRpcError(
            decision.code,
            decision.message,
            item.id,
            decision.data
          );
          res.status(status).json(errRes);

          log.warn({
            reqId,
            role,
            method: item.request.method,
            tool: typeof toolName === "string" ? toolName : null,
            decision: "deny",
            status,
            durationMs: Date.now() - startTime
          });
          return;
        }

        // Forward allowed single request unmodified
        await forwardStream(req, res, rawBuffer, config, item.id);
        log.info({
          reqId,
          role,
          method: item.request.method,
          tool: typeof toolName === "string" ? toolName : null,
          decision: "allow",
          status: res.statusCode || 200,
          durationMs: Date.now() - startTime
        });
        return;
      }

      // Handle batch
      const items = payload.items;
      const finalResponses: any[] = new Array(items.length);
      const toForward: Array<{ originalIndex: number; item: unknown; id: JsonRpcId; isNotification: boolean }> = [];

      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        if (it.kind === "error") {
          finalResponses[i] = it.error;
          continue;
        }

        if (it.kind === "client_response") {
          toForward.push({
            originalIndex: i,
            item: it.raw,
            id: it.id,
            isNotification: false
          });
          continue;
        }

        // it.kind === "request"
        const decision = authorize(role, it.request);
        if (!decision.allowed) {
          // Omit response for denied notifications
          if (!it.isNotification) {
            finalResponses[i] = createJsonRpcError(
              decision.code,
              decision.message,
              it.id,
              decision.data
            );
          }
        } else {
          toForward.push({
            originalIndex: i,
            item: it.raw,
            id: it.id,
            isNotification: it.isNotification
          });
        }
      }

      // If nothing to forward, return the local errors
      if (toForward.length === 0) {
        const filtered = finalResponses.filter((x) => x !== undefined && x !== null);
        if (filtered.length === 0) {
          res.status(202).end();
        } else {
          res.status(200).json(filtered);
        }
        log.info({
          reqId,
          role,
          method: "batch",
          tool: null,
          decision: "deny",
          status: filtered.length === 0 ? 202 : 200,
          durationMs: Date.now() - startTime
        });
        return;
      }

      // Forward only allowed items
      const batchPayload = toForward.map((tf) => tf.item);
      const downstreamResult = await forwardBatch(
        batchPayload,
        req.headers,
        config,
        null
      );

      if (downstreamResult.status === 202 || downstreamResult.data === null) {
        const filtered = finalResponses.filter((x) => x !== undefined && x !== null);
        if (filtered.length === 0) {
          res.status(202).end();
        } else {
          res.status(200).json(filtered);
        }
        return;
      }

      // Map downstream replies into finalResponses using queue per id (handles duplicate ids and id: null)
      const downstreamData = downstreamResult.data;
      if (Array.isArray(downstreamData)) {
        const idToQueue = new Map<JsonRpcId, number[]>();
        const openForwardSlots: number[] = [];

        for (const tf of toForward) {
          if (!tf.isNotification) {
            const key = tf.id;
            let queue = idToQueue.get(key);
            if (!queue) {
              queue = [];
              idToQueue.set(key, queue);
            }
            queue.push(tf.originalIndex);
          } else {
            openForwardSlots.push(tf.originalIndex);
          }
        }

        for (const reply of downstreamData) {
          const replyId: JsonRpcId =
            reply && typeof reply === "object" && "id" in reply ? reply.id : null;
          const queue = idToQueue.get(replyId);
          if (queue && queue.length > 0) {
            const idx = queue.shift()!;
            finalResponses[idx] = reply;
          } else if (openForwardSlots.length > 0) {
            const idx = openForwardSlots.shift()!;
            finalResponses[idx] = reply;
          }
        }
      } else if (typeof downstreamData === "object" && downstreamData !== null) {
        if (toForward.length === 1) {
          finalResponses[toForward[0].originalIndex] = downstreamData;
        }
      }

      const merged = finalResponses.filter((x) => x !== undefined && x !== null);
      if (merged.length === 0) {
        res.status(202).end();
      } else {
        res.status(200).json(merged);
      }

      log.info({
        reqId,
        role,
        method: "batch",
        tool: null,
        decision: "allow",
        status: merged.length === 0 ? 202 : 200,
        durationMs: Date.now() - startTime
      });
    } catch (err) {
      next(err);
    }
  });

  // 5. Error handling middleware
  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    const reqId = ((req as any).reqId as string) || crypto.randomUUID();
    const startTime = ((req as any).startTime as number) || Date.now();

    if (err.status === 413 || err.type === "entity.too.large") {
      res.status(413).end();
      log.warn({
        reqId,
        role: null,
        method: null,
        tool: null,
        decision: "error",
        status: 413,
        durationMs: Date.now() - startTime
      });
      return;
    }

    if (err instanceof ForwardError) {
      const errResponse = createJsonRpcError(err.rpcCode, err.message, err.echoId);
      res.status(err.status).json(errResponse);
      log.error({
        reqId,
        role: null,
        method: null,
        tool: null,
        decision: "error",
        status: err.status,
        durationMs: Date.now() - startTime
      });
      return;
    }

    // Uncaught exception -> -32603 Internal error
    process.stderr.write(`[INTERNAL ERROR] ${err.stack || err.message}\n`);
    const internalErr = createJsonRpcError(ErrorCodes.INTERNAL_ERROR, "Internal error", null);
    res.status(500).json(internalErr);

    log.error({
      reqId,
      role: null,
      method: null,
      tool: null,
      decision: "error",
      status: 500,
      durationMs: Date.now() - startTime
    });
  });

  return app;
}
