export type JsonRpcId = string | number | null;

export interface JsonRpcErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  error: JsonRpcErrorObject;
}

export interface JsonRpcSuccessResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result: unknown;
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  method: string;
  id?: JsonRpcId;
  params?: Record<string, unknown> | unknown[];
}

export interface JsonRpcClientResponse {
  jsonrpc?: string;
  id?: JsonRpcId;
  result?: unknown;
  error?: unknown;
}

export const ErrorCodes = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  UNAUTHORIZED_TOOL_CALL: -32001,
  AUTHENTICATION_REQUIRED: -32002,
  DOWNSTREAM_UNAVAILABLE: -32003,
  DOWNSTREAM_TIMEOUT: -32004,
} as const;

export const ErrorHttpStatuses: Record<number, number> = {
  [-32700]: 400,
  [-32600]: 400,
  [-32601]: 200,
  [-32602]: 200,
  [-32001]: 200,
  [-32002]: 401,
  [-32003]: 502,
  [-32004]: 504,
  [-32603]: 500,
};

export function createJsonRpcError(
  code: number,
  message: string,
  id: JsonRpcId = null,
  data?: unknown
): JsonRpcErrorResponse {
  const errorObj: JsonRpcErrorObject = { code, message };
  if (data !== undefined) {
    errorObj.data = data;
  }
  return {
    jsonrpc: "2.0",
    id,
    error: errorObj
  };
}

export function extractEchoId(raw: unknown): JsonRpcId {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const candidate = (raw as Record<string, unknown>).id;
    if (typeof candidate === "string" || typeof candidate === "number" || candidate === null) {
      return candidate;
    }
  }
  return null;
}

export function isClientResponse(raw: unknown): boolean {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>;
    return !("method" in obj) && ("result" in obj || "error" in obj);
  }
  return false;
}

export type ParsedItem =
  | {
      kind: "request";
      raw: Record<string, unknown>;
      request: JsonRpcRequest;
      isNotification: boolean;
      id: JsonRpcId;
    }
  | {
      kind: "client_response";
      raw: Record<string, unknown>;
      isNotification: false;
      id: JsonRpcId;
    }
  | {
      kind: "error";
      raw: unknown;
      error: JsonRpcErrorResponse;
      isNotification: false;
      id: JsonRpcId;
    };

export function validateItem(raw: unknown): ParsedItem {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {
      kind: "error",
      raw,
      error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", null),
      isNotification: false,
      id: null
    };
  }

  const obj = raw as Record<string, unknown>;

  if (isClientResponse(obj)) {
    return {
      kind: "client_response",
      raw: obj,
      isNotification: false,
      id: extractEchoId(obj)
    };
  }

  const echoId = extractEchoId(obj);

  if (obj.jsonrpc !== "2.0") {
    return {
      kind: "error",
      raw: obj,
      error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", echoId),
      isNotification: false,
      id: echoId
    };
  }

  if (typeof obj.method !== "string") {
    return {
      kind: "error",
      raw: obj,
      error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", echoId),
      isNotification: false,
      id: echoId
    };
  }

  if ("id" in obj) {
    const idVal = obj.id;
    if (typeof idVal !== "string" && typeof idVal !== "number" && idVal !== null) {
      return {
        kind: "error",
        raw: obj,
        error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", null),
        isNotification: false,
        id: null
      };
    }
  }

  if ("params" in obj) {
    const paramsVal = obj.params;
    if (typeof paramsVal !== "object" || paramsVal === null) {
      return {
        kind: "error",
        raw: obj,
        error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", echoId),
        isNotification: false,
        id: echoId
      };
    }
  }

  const isNotification = !("id" in obj);
  const id = isNotification ? null : (obj.id as JsonRpcId);

  const request: JsonRpcRequest = {
    jsonrpc: "2.0",
    method: obj.method,
    ...(isNotification ? {} : { id }),
    ...("params" in obj ? { params: obj.params as Record<string, unknown> | unknown[] } : {})
  };

  return {
    kind: "request",
    raw: obj,
    request,
    isNotification,
    id
  };
}

export type ParsedPayload =
  | {
      isBatch: false;
      item: ParsedItem;
    }
  | {
      isBatch: true;
      items: ParsedItem[];
    };

export function parseJsonRpcPayload(parsedJson: unknown): { error?: JsonRpcErrorResponse; payload?: ParsedPayload } {
  if (Array.isArray(parsedJson)) {
    if (parsedJson.length === 0) {
      return {
        error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", null)
      };
    }
    const items = parsedJson.map((entry) => validateItem(entry));
    return {
      payload: {
        isBatch: true,
        items
      }
    };
  }

  if (typeof parsedJson === "object" && parsedJson !== null) {
    const item = validateItem(parsedJson);
    return {
      payload: {
        isBatch: false,
        item
      }
    };
  }

  return {
    error: createJsonRpcError(ErrorCodes.INVALID_REQUEST, "Invalid Request", null)
  };
}
