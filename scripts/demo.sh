#!/usr/bin/env bash
set -euo pipefail

MOCK_PORT=4001
GATEWAY_PORT=8080

echo "=== MCP Gateway Proxy Demo ==="

# 1. Build TypeScript project
echo "Building project..."
npm run build > /dev/null

# 2. Start mock downstream server
echo "Starting mock downstream server on port ${MOCK_PORT}..."
PORT=${MOCK_PORT} node dist/mock/downstream.js &
MOCK_PID=$!

# 3. Start gateway server
echo "Starting gateway proxy on port ${GATEWAY_PORT}..."
PORT=${GATEWAY_PORT} \
DOWNSTREAM_URL="http://127.0.0.1:${MOCK_PORT}/mcp" \
GATEWAY_STATIC_TOKENS='{"admin-token":"admin","viewer-token":"viewer"}' \
GATEWAY_JWT_SECRET="demo-secret-key-change-in-production" \
node dist/src/index.js &
GATEWAY_PID=$!

cleanup() {
  echo "Shutting down servers..."
  kill "${GATEWAY_PID}" "${MOCK_PID}" 2>/dev/null || true
  wait "${GATEWAY_PID}" "${MOCK_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# 4. Wait for servers to be ready
echo "Waiting for servers to become ready..."
for i in {1..30}; do
  if curl -sf "http://127.0.0.1:${GATEWAY_PORT}/healthz" > /dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "Servers ready!"
echo ""

# 5. tools/list for viewer
echo "[1] Calling tools/list as viewer (allowed):"
curl -s -X POST "http://127.0.0.1:${GATEWAY_PORT}/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer viewer-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
echo -e "\n"

# 6. tools/list for admin
echo "[2] Calling tools/list as admin (allowed):"
curl -s -X POST "http://127.0.0.1:${GATEWAY_PORT}/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo -e "\n"

# 7. tools/call admin_reset_key for viewer (intercepted with -32001)
echo "[3] Calling admin_reset_key as viewer (intercepted directly by gateway with -32001):"
curl -s -X POST "http://127.0.0.1:${GATEWAY_PORT}/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer viewer-token" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"admin_reset_key","arguments":{}}}'
echo -e "\n"

# 8. tools/call admin_reset_key for admin (allowed and forwarded)
echo "[4] Calling admin_reset_key as admin (allowed and executed by downstream):"
curl -s -X POST "http://127.0.0.1:${GATEWAY_PORT}/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"admin_reset_key","arguments":{}}}'
echo -e "\n"

# 9. Verify downstream stats
echo "[5] Downstream stats (proves viewer admin call never reached downstream):"
curl -s "http://127.0.0.1:${MOCK_PORT}/__stats"
echo -e "\n"

echo "=== Demo completed successfully ==="
