import { JsonRpcRequest, ErrorCodes } from "./jsonrpc.js";

export interface PolicyAllow {
  allowed: true;
}

export interface PolicyDeny {
  allowed: false;
  code: number;
  message: string;
  data?: unknown;
}

export type PolicyDecision = PolicyAllow | PolicyDeny;

/**
 * Normalizes tool name by trimming whitespace, applying NFKC Unicode normalization,
 * and converting to lower case. This provides defense-in-depth against Unicode confusable
 * or casing bypasses for admin tool names.
 */
export function normalizeToolName(name: string): string {
  return name.trim().normalize("NFKC").toLowerCase();
}

/**
 * Pure authorization policy function.
 * - tools/list: allowed for any authenticated role.
 * - tools/call: requires params object with non-empty string 'name' (else -32602).
 *   If tool name starts with "admin_" (case-sensitive) or normalized name starts with "admin_",
 *   the role must be "admin", otherwise returns -32001 with data { tool, requiredRole: "admin" }.
 * - all other methods: forwarded transparently for any authenticated role.
 */
export function authorize(role: string, request: JsonRpcRequest): PolicyDecision {
  const method = request.method;

  if (method === "tools/list") {
    return { allowed: true };
  }

  if (method === "tools/call") {
    const params = request.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) {
      return {
        allowed: false,
        code: ErrorCodes.INVALID_PARAMS,
        message: "Invalid params: tools/call requires a params object"
      };
    }

    const toolName = (params as Record<string, unknown>).name;
    if (typeof toolName !== "string" || toolName.length === 0) {
      return {
        allowed: false,
        code: ErrorCodes.INVALID_PARAMS,
        message: "Invalid params: tools/call requires a non-empty string 'name'"
      };
    }

    const isExactAdmin = toolName.startsWith("admin_");
    const normalized = normalizeToolName(toolName);
    const isNormalizedAdmin = normalized.startsWith("admin_");

    if (isExactAdmin || isNormalizedAdmin) {
      if (role !== "admin") {
        return {
          allowed: false,
          code: ErrorCodes.UNAUTHORIZED_TOOL_CALL,
          message: "Unauthorized Tool Call",
          data: {
            tool: toolName,
            requiredRole: "admin"
          }
        };
      }
    }

    return { allowed: true };
  }

  // All other methods (initialize, ping, notifications, custom) are allowed for authenticated roles
  return { allowed: true };
}
