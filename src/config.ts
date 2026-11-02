export interface GatewayConfig {
  port: number;
  downstreamUrl: string;
  downstreamTimeoutMs: number;
  jwtSecret?: string;
  staticTokens: Record<string, string>;
  maxBodyBytes: number;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function parseConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  let port = 8080;
  if (env.PORT !== undefined && env.PORT !== "") {
    const parsed = Number(env.PORT);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
      throw new ConfigError(`Invalid PORT: must be an integer between 1 and 65535, received "${env.PORT}"`);
    }
    port = parsed;
  }

  const downstreamUrl = env.DOWNSTREAM_URL || "http://127.0.0.1:4001/mcp";
  try {
    const url = new URL(downstreamUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new ConfigError(`Invalid DOWNSTREAM_URL protocol: must be http or https, received "${downstreamUrl}"`);
    }
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError(`Invalid DOWNSTREAM_URL: "${downstreamUrl}" is not a valid URL`);
  }

  let downstreamTimeoutMs = 5000;
  if (env.DOWNSTREAM_TIMEOUT_MS !== undefined && env.DOWNSTREAM_TIMEOUT_MS !== "") {
    const parsed = Number(env.DOWNSTREAM_TIMEOUT_MS);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new ConfigError(`Invalid DOWNSTREAM_TIMEOUT_MS: must be a positive number, received "${env.DOWNSTREAM_TIMEOUT_MS}"`);
    }
    downstreamTimeoutMs = Math.round(parsed);
  }

  const jwtSecret = env.GATEWAY_JWT_SECRET && env.GATEWAY_JWT_SECRET.trim().length > 0
    ? env.GATEWAY_JWT_SECRET
    : undefined;

  let staticTokens: Record<string, string> = {};
  if (env.GATEWAY_STATIC_TOKENS !== undefined && env.GATEWAY_STATIC_TOKENS !== "") {
    try {
      const parsed = JSON.parse(env.GATEWAY_STATIC_TOKENS);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("must be a JSON object");
      }
      for (const [key, val] of Object.entries(parsed)) {
        if (typeof key !== "string" || typeof val !== "string") {
          throw new Error("all keys and values in GATEWAY_STATIC_TOKENS must be strings");
        }
      }
      staticTokens = parsed;
    } catch (err: any) {
      throw new ConfigError(`Invalid GATEWAY_STATIC_TOKENS: ${err.message}`);
    }
  }

  let maxBodyBytes = 1048576; // 1MB default
  if (env.MAX_BODY !== undefined && env.MAX_BODY !== "") {
    const parsed = Number(env.MAX_BODY);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw new ConfigError(`Invalid MAX_BODY: must be a positive integer, received "${env.MAX_BODY}"`);
    }
    maxBodyBytes = parsed;
  }

  return {
    port,
    downstreamUrl,
    downstreamTimeoutMs,
    jwtSecret,
    staticTokens,
    maxBodyBytes
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  try {
    return parseConfig(env);
  } catch (err: any) {
    process.stderr.write(`[CONFIG ERROR] ${err.message}\n`);
    process.exit(1);
  }
}
