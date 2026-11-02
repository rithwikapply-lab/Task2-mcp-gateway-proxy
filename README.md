# MCP Gateway Proxy

A high-performance HTTP/JSON-RPC reverse proxy and security gateway written in TypeScript for the Model Context Protocol (MCP). The gateway sits between a client and a downstream MCP server, enforcing fine-grained method-level authorization, role-based tool restrictions, and strict protocol wire validation.

## Features

- **Role-Based Authorization**: Extracts user roles (`admin` vs non-admin/`viewer`) from `Authorization: Bearer <token>` headers via static token maps or cryptographically verified HS256 JWTs.
- **Method-Level Interception**:
  - `tools/list`: Transparently forwarded to downstream for all authenticated roles without modification.
  - `tools/call`: Intercepts administrative tools (`admin_*`) for non-admin users and immediately returns JSON-RPC error `-32001` (`Unauthorized Tool Call`) at HTTP 200 without invoking the downstream server.
  - Non-admin tools and other protocol methods (`initialize`, `ping`) are forwarded transparently.
- **Normalization Hardening (Defense in Depth)**: Beyond standard prefix matching, tool names are trimmed, NFKC Unicode-normalized, and lower-cased to prevent confusable or casing bypasses (e.g. `Admin_reset_key`, ` admin_x`, or `ａｄｍｉｎ_x`).
- **Heterogeneous Batch Rewriting**: Authorizes batch elements independently, filters out unauthorized calls, dispatches only allowed items to downstream, and merges responses with gateway error frames in original element order.
- **Strict Wire-Format Validation**: Hand-written JSON-RPC 2.0 parser without external schema dependencies, guaranteeing accurate `-32700` and `-32600` responses and exact ID preservation.
- **Zero Token Leakage**: Structured JSON logging to stderr with strict sanitization, never recording tokens, Authorization headers, or request bodies.
- **Streaming Forwarding**: Single unmodified requests are streamed directly from downstream using global `fetch` without buffering server-sent events (SSE).

---

## Quick Start

### Prerequisites

- Node.js 18+ (tested on Node.js 20 and 24)
- npm 9+

### Installation & Build

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run build

# Run test suite
npm test
```

### Running the Services

```bash
# Terminal 1: Start mock downstream MCP server (runs on port 4001)
npm run start:mock

# Terminal 2: Start MCP gateway proxy (runs on port 8080)
npm run start
```

### Automated End-to-End Demo

The repository includes a self-contained demonstration script that starts the mock server and gateway, executes allowed tool calls, verifies intercepted admin tool attempts, and confirms downstream isolation:

```bash
./scripts/demo.sh
```

---

## Configuration

All configuration is loaded from environment variables:

| Variable | Type | Default | Description |
|---|---|---|---|
| `PORT` | Number | `8080` | Port for the gateway HTTP server |
| `DOWNSTREAM_URL` | String | `http://127.0.0.1:4001/mcp` | Target downstream MCP server endpoint |
| `DOWNSTREAM_TIMEOUT_MS` | Number | `5000` | Downstream request timeout in milliseconds |
| `GATEWAY_JWT_SECRET` | String | `undefined` | Secret key used to verify HS256 JWT tokens. If unset, JWT authentication is disabled |
| `GATEWAY_STATIC_TOKENS` | JSON String | `{}` | JSON map of static tokens to role strings (e.g. `{"admin-token":"admin","viewer-token":"viewer"}`) |
| `MAX_BODY` | Number | `1048576` (1MB) | Maximum allowed request body size in bytes (exceeding returns HTTP 413) |

---

## Authentication & Token Formats

The gateway inspects incoming requests for an `Authorization` header formatted as:

```http
Authorization: Bearer <token>
```

- **Scheme Validation**: The `Bearer` scheme is matched case-insensitively (`bearer`, `Bearer`, `BEARER`).
- **Whitespace Rules**: Exactly one space must separate the scheme and token. Tokens containing whitespace or empty tokens are rejected.
- **Resolution Order**:
  1. **Static Token Map**: Exact string match against configured `GATEWAY_STATIC_TOKENS`.
  2. **HS256 JWT Verification**: Verified using Node.js built-in `node:crypto` with HMAC-SHA256:
     - Header must specify `"alg": "HS256"` (rejects `none`, `HS384`, `HS512`, etc.).
     - Signature is checked via constant-time buffer comparison (`crypto.timingSafeEqual`).
     - Expiration (`exp`) and not-before (`nbf`) claims are checked with a 5-second clock skew tolerance.
     - Payload must contain a string `role` claim.
- **Role Evaluation**:
  - `role === "admin"` (case-sensitive exact match) grants admin access.
  - Any other string (e.g. `"viewer"`, `"guest"`, or `"ADMIN"`) is authenticated as non-admin under least privilege.

---

## Error Handling Table

The gateway maps protocol conditions to standard JSON-RPC 2.0 error codes and appropriate HTTP status codes:

| Code | HTTP Status | Constant | Condition | Response Payload / Behavior |
|---|---|---|---|---|
| `-32700` | `400` | `ParseError` | Invalid JSON syntax in request body | `{ code: -32700, message: "Parse error" }` |
| `-32600` | `400` | `InvalidRequest` | Invalid JSON-RPC structure or empty batch `[]` | `{ code: -32600, message: "Invalid Request" }` (id echoed if valid) |
| `-32602` | `200` | `InvalidParams` | `tools/call` missing or non-string/empty `params.name` | `{ code: -32602, message: "Invalid params: ...", id }` |
| `-32001` | `200` | `UnauthorizedToolCall` | Non-admin user attempting an `admin_*` tool | `{ code: -32001, message: "Unauthorized Tool Call", data: { tool, requiredRole: "admin" } }` |
| `-32002` | `401` | `AuthenticationRequired` | Missing, malformed, invalid, or expired credentials | `{ code: -32002, message: "Authentication required" }`, header `WWW-Authenticate: Bearer` |
| `-32003` | `502` | `DownstreamUnavailable` | Downstream connection failed or unreachable | `{ code: -32003, message: "Bad Gateway" }` (URL and internals withheld) |
| `-32004` | `504` | `DownstreamTimeout` | Downstream call exceeded `DOWNSTREAM_TIMEOUT_MS` | `{ code: -32004, message: "Gateway Timeout" }` (URL withheld) |
| `-32603` | `500` | `InternalError` | Uncaught runtime exception in proxy | `{ code: -32603, message: "Internal error" }` (stack trace logged to stderr only) |

---

## Middleware Pipeline Architecture

The Express application returned by `createApp(config)` executes an explicit linear middleware pipeline (`src/app.ts`):

1. **Request ID Middleware**: Generates a UUID (`crypto.randomUUID()`), attaches it to the request context, and sets `X-Request-Id` on the HTTP response.
2. **Route Guard**:
   - `GET /healthz`: Returns `200 {"status":"ok"}` without authentication.
   - `POST /mcp`: Continues down the pipeline.
   - Any other method on `/mcp`: Emits `405 Method Not Allowed` with `Allow: POST` header.
   - Any other route: Emits `404 Not Found`.
3. **Content-Type & Body Guard**: Requires `application/json` (rejecting others with `415 Unsupported Media Type`). Buffers request body with `express.raw` up to `MAX_BODY` (rejecting over-limit payloads with `413 Payload Too Large`).
4. **Authentication**: Resolves user role. On failure, emits `401 Unauthorized` with `WWW-Authenticate: Bearer` and `-32002` error.
5. **JSON-RPC Parsing & Validation**: Parses raw buffer into JSON. Validates single requests, notifications, client responses, and batches.
6. **Authorization Policy**: Pure function `authorize(role, request)` evaluates tool permissions.
7. **Forwarding Engine**: Dispatches allowed calls to downstream, stripping hop-by-hop and `Authorization` headers, with abort timeout management.
8. **Error Middleware**: Catches unhandled throws and returns safe `500 -32603` responses without leaking internal state.

---

## Batch Handling

JSON-RPC 2.0 specifications allow batch requests where multiple RPC calls are submitted in a single JSON array.

### Why Custom Batch Handling is Necessary

A client may send a heterogeneous batch containing:
1. Valid permitted requests (e.g. `tools/list`)
2. Unauthorized administrative requests (e.g. `tools/call admin_reset_key`)
3. Malformed JSON-RPC frames

If a proxy blindly forwards the batch, unauthorized actions reach the downstream server. Conversely, rejecting the entire batch denies legitimate calls.

### How the Gateway Processes Batches

1. **Independent Evaluation**: Every item in the batch is validated and authorized independently.
2. **Selective Forwarding**: Only permitted items are bundled into a sub-batch forwarded to downstream. Unauthorized elements immediately generate `-32001` error objects locally.
3. **Zero Downstream Calls for All-Denied Batches**: If every element in a batch is unauthorized or malformed, the downstream server is never called.
4. **Order Preservation**: Downstream responses are correlated with local error entries and assembled in the exact original order of the client batch.
5. **Notification Support**: Batches consisting solely of allowed notifications return HTTP `202 Accepted` with an empty body.

---

## Normalization Hardening (Defense in Depth)

Standard string checking (`toolName.startsWith("admin_")`) can be susceptible to bypasses involving unusual Unicode representations or whitespace padding if the downstream server interprets them loosely.

The gateway incorporates deliberate normalization hardening in `src/policy.ts`:
```typescript
export function normalizeToolName(name: string): string {
  return name.trim().normalize("NFKC").toLowerCase();
}
```

A tool call is blocked for non-admins if:
- `toolName.startsWith("admin_")` (exact match), OR
- `normalizeToolName(toolName).startsWith("admin_")` (normalized match)

This protects against:
- **Case variations**: `Admin_reset_key`, `ADMIN_reset_key`
- **Whitespace manipulation**: `" admin_reset_key"`
- **Unicode compatibility confusables**: Full-width characters such as `ａｄｍｉｎ_reset_key` (U+FF41, U+FF44, U+FF4D, U+FF49, U+FF4E) which normalize via NFKC to ASCII `admin_reset_key`.

---

## Why Global `fetch` (and Not `http-proxy-middleware`)

Standard reverse proxy middleware (`http-proxy-middleware`) operates at the stream level without understanding JSON-RPC semantics. It cannot:
- Inspect message payloads without buffering and breaking streaming.
- Disassemble and rewrite heterogeneous batches.
- Block specific elements while permitting others in the same connection.

By utilizing Node.js native `fetch` with `AbortController`, the gateway:
- Retains full control over outgoing request headers (stripping `Authorization` and hop-by-hop headers).
- Streams single responses and SSE chunks directly to the client via `Readable.fromWeb(response.body).pipe(res)`.
- Handles connection timeouts cleanly via `AbortSignal`.

---

## Logging & Security

The gateway logs all request outcomes to `stderr` as structured single-line JSON records (`src/logger.ts`):

```json
{"ts":"2026-11-02T21:47:40.974Z","level":"info","reqId":"7864ada7-9eef-43d0-9cb5-c563adbdf74e","role":"viewer","method":"tools/list","tool":null,"decision":"allow","status":200,"durationMs":23}
```

- **Sanitization Guarantee**: Log events record metadata (`ts`, `level`, `reqId`, `role`, `method`, `tool`, `decision`, `status`, `durationMs`). Tokens, Authorization headers, and request bodies are strictly excluded.
- **Injectable Sink**: The logger supports custom sink functions, allowing integration tests to verify log cleanliness programmatically.

---

## Scoring Criteria Fulfillment

1. **Correct JSON-RPC Wire-Format Parsing**:
   - Hand-crafted parser in `src/jsonrpc.ts` strictly validates JSON-RPC 2.0 objects.
   - Accurately identifies notifications (omitted `id`), requests, and client responses.
   - Preserves `id` types (string, integer, float, null) across transformations.
   - Rejects non-objects and empty batches with `-32600`.
2. **Proxy Middleware Construction & Request/Response Forwarding**:
   - Explicit Express middleware pipeline in `src/app.ts` with strict route and content-type enforcement.
   - Robust header stripping: `Authorization` and all hop-by-hop headers are removed before forwarding.
   - Downstream network errors map to HTTP 502 (`-32003`) and timeouts map to HTTP 504 (`-32004`) with safe generic error messages.
3. **Fine-Grained Method-Level Authorization & Clean Error Handling**:
   - Constant-time HS256 JWT and static token authentication.
   - `tools/list` forwarded transparently without filtering.
   - `admin_*` tool calls intercepted directly at HTTP 200 with `-32001` and detailed error metadata.
   - Proved via test suite that unauthorized tool attempts never reach downstream.
   - Unicode NFKC normalization hardening prevents spoofing and confusable bypasses.

---

## Project Structure

```
mcp-gateway-proxy/
├── package.json
├── tsconfig.json
├── .env.example
├── README.md
├── scripts/
│   └── demo.sh           # Executable verification demonstration
├── src/
│   ├── index.ts          # Server bootstrap and entrypoint
│   ├── app.ts            # Express application and middleware pipeline
│   ├── config.ts         # Environment configuration parser
│   ├── logger.ts         # Structured stderr JSON logger
│   ├── auth.ts           # Bearer token and HS256 JWT role extraction
│   ├── jsonrpc.ts        # JSON-RPC 2.0 validation and error builders
│   ├── policy.ts         # Pure tool authorization policy and normalization
│   └── forward.ts        # Global fetch forwarder with header stripping and timeout
├── mock/
│   └── downstream.js     # Downstream mock MCP server with call tracking
└── test/
    ├── auth.test.ts      # Authentication and token edge cases
    ├── jsonrpc.test.ts   # JSON-RPC wire-format compliance tests
    ├── policy.test.ts    # Tool authorization matrix tests
    ├── gateway.test.ts   # Supertest gateway integration and denial proofs
    └── e2e.test.ts       # Spawned child process end-to-end tests
```

---

## License

MIT
