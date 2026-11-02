import crypto from "node:crypto";

export interface AuthSuccess {
  authenticated: true;
  role: string;
  isAdmin: boolean;
}

export interface AuthFailure {
  authenticated: false;
  error: string;
}

export type AuthResult = AuthSuccess | AuthFailure;

export function parseAuthorizationHeader(authHeader: string | undefined): { token?: string; error?: string } {
  if (!authHeader) {
    return { error: "Missing authorization header" };
  }

  const spaceIndex = authHeader.indexOf(" ");
  if (spaceIndex === -1) {
    return { error: "Malformed authorization header: missing space separator" };
  }

  const scheme = authHeader.substring(0, spaceIndex);
  if (scheme.toLowerCase() !== "bearer") {
    return { error: `Unsupported authorization scheme: "${scheme}"` };
  }

  // Exactly one space: next character must not be whitespace
  if (authHeader[spaceIndex + 1] === " ") {
    return { error: "Malformed authorization header: multiple spaces after scheme" };
  }

  const token = authHeader.substring(spaceIndex + 1);
  if (!token || token.length === 0) {
    return { error: "Malformed authorization header: empty token" };
  }

  if (/\s/.test(token)) {
    return { error: "Malformed authorization header: token contains whitespace" };
  }

  return { token };
}

function base64urlDecode(str: string): string {
  return Buffer.from(str, "base64url").toString("utf8");
}

export function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf.toString("base64url");
}

export function verifyJwt(token: string, secret: string | undefined): { valid: boolean; role?: string; error?: string } {
  if (!secret) {
    return { valid: false, error: "JWT authentication disabled: no secret configured" };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return { valid: false, error: "Invalid JWT structure: must have exactly 3 parts" };
  }

  let header: any;
  let payload: any;

  try {
    header = JSON.parse(base64urlDecode(parts[0]));
    payload = JSON.parse(base64urlDecode(parts[1]));
  } catch {
    return { valid: false, error: "Invalid JWT: header or payload is not valid JSON" };
  }

  if (!header || typeof header !== "object" || header.alg !== "HS256") {
    return { valid: false, error: `Invalid JWT algorithm: expected "HS256", received "${header?.alg}"` };
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expectedSig = crypto.createHmac("sha256", secret).update(signingInput).digest();
  let receivedSig: Buffer;
  try {
    receivedSig = Buffer.from(parts[2], "base64url");
  } catch {
    return { valid: false, error: "Invalid JWT signature encoding" };
  }

  if (receivedSig.length !== expectedSig.length) {
    return { valid: false, error: "Invalid JWT signature length" };
  }

  if (!crypto.timingSafeEqual(receivedSig, expectedSig)) {
    return { valid: false, error: "Invalid JWT signature" };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const skewSec = 5;

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number" || nowSec > payload.exp + skewSec) {
      return { valid: false, error: "JWT expired" };
    }
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number" || nowSec < payload.nbf - skewSec) {
      return { valid: false, error: "JWT not active yet (nbf)" };
    }
  }

  if (typeof payload.role !== "string") {
    return { valid: false, error: "JWT payload missing string role claim" };
  }

  return { valid: true, role: payload.role };
}

export function authenticate(
  authHeader: string | undefined,
  staticTokens: Record<string, string>,
  jwtSecret?: string
): AuthResult {
  const parsed = parseAuthorizationHeader(authHeader);
  if (!parsed.token) {
    return { authenticated: false, error: parsed.error || "Authentication required" };
  }

  const token = parsed.token;

  // 1. Static token map check
  if (Object.prototype.hasOwnProperty.call(staticTokens, token)) {
    const rawRole = staticTokens[token];
    const isAdmin = rawRole === "admin";
    return {
      authenticated: true,
      role: rawRole,
      isAdmin
    };
  }

  // 2. JWT verification
  const jwtRes = verifyJwt(token, jwtSecret);
  if (jwtRes.valid && jwtRes.role !== undefined) {
    const rawRole = jwtRes.role;
    const isAdmin = rawRole === "admin";
    return {
      authenticated: true,
      role: rawRole,
      isAdmin
    };
  }

  return {
    authenticated: false,
    error: jwtRes.error || "Invalid token"
  };
}

export function createTestJwt(
  payload: Record<string, unknown>,
  secret: string,
  headerOverride: Record<string, unknown> = { alg: "HS256", typ: "JWT" }
): string {
  const headerB64 = base64urlEncode(JSON.stringify(headerOverride));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  let sigB64: string;
  if (headerOverride.alg === "none") {
    sigB64 = "";
  } else {
    const sig = crypto.createHmac("sha256", secret).update(signingInput).digest();
    sigB64 = sig.toString("base64url");
  }

  return `${signingInput}.${sigB64}`;
}
