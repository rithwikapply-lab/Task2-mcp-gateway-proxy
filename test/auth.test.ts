import { describe, it, expect } from "vitest";
import {
  authenticate,
  createTestJwt,
  parseAuthorizationHeader,
  verifyJwt
} from "../src/auth.js";

const TEST_SECRET = "test-secret-key-for-jwt-verification-12345";
const STATIC_TOKENS: Record<string, string> = {
  "admin-token": "admin",
  "viewer-token": "viewer",
  "upper-token": "ADMIN"
};

describe("Authentication & Header Parsing", () => {
  it("rejects missing authorization header", () => {
    const res = authenticate(undefined, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects non-Bearer scheme (e.g. Basic)", () => {
    const res = authenticate("Basic dXNlcjpwYXNz", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects empty Bearer token", () => {
    const res = authenticate("Bearer ", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("accepts lowercase scheme 'bearer'", () => {
    const res = authenticate("bearer admin-token", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(true);
    if (!res.authenticated) return;
    expect(res.role).toBe("admin");
    expect(res.isAdmin).toBe(true);
  });

  it("accepts uppercase scheme 'BEARER'", () => {
    const res = authenticate("BEARER viewer-token", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(true);
    if (!res.authenticated) return;
    expect(res.role).toBe("viewer");
    expect(res.isAdmin).toBe(false);
  });

  it("rejects double space after scheme", () => {
    const res = authenticate("Bearer  admin-token", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects tokens containing whitespace", () => {
    const res = authenticate("Bearer admin token", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("resolves static tokens exactly", () => {
    const adminRes = authenticate("Bearer admin-token", STATIC_TOKENS, TEST_SECRET);
    expect(adminRes.authenticated).toBe(true);
    if (!adminRes.authenticated) return;
    expect(adminRes.role).toBe("admin");
    expect(adminRes.isAdmin).toBe(true);

    const viewerRes = authenticate("Bearer viewer-token", STATIC_TOKENS, TEST_SECRET);
    expect(viewerRes.authenticated).toBe(true);
    if (!viewerRes.authenticated) return;
    expect(viewerRes.role).toBe("viewer");
    expect(viewerRes.isAdmin).toBe(false);
  });

  it("treats role 'ADMIN' as authenticated non-admin", () => {
    const res = authenticate("Bearer upper-token", STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(true);
    if (!res.authenticated) return;
    expect(res.role).toBe("ADMIN");
    expect(res.isAdmin).toBe(false);
  });

  it("verifies valid HS256 JWT for admin and viewer", () => {
    const adminJwt = createTestJwt({ role: "admin" }, TEST_SECRET);
    const adminRes = authenticate(`Bearer ${adminJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(adminRes.authenticated).toBe(true);
    if (!adminRes.authenticated) return;
    expect(adminRes.role).toBe("admin");
    expect(adminRes.isAdmin).toBe(true);

    const viewerJwt = createTestJwt({ role: "viewer" }, TEST_SECRET);
    const viewerRes = authenticate(`Bearer ${viewerJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(viewerRes.authenticated).toBe(true);
    if (!viewerRes.authenticated) return;
    expect(viewerRes.role).toBe("viewer");
    expect(viewerRes.isAdmin).toBe(false);
  });

  it("rejects JWT when no secret is configured", () => {
    const jwt = createTestJwt({ role: "admin" }, TEST_SECRET);
    const res = authenticate(`Bearer ${jwt}`, STATIC_TOKENS, undefined);
    expect(res.authenticated).toBe(false);
  });

  it("rejects JWT with bad signature", () => {
    const badJwt = createTestJwt({ role: "admin" }, "different-secret-key-12345");
    const res = authenticate(`Bearer ${badJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects JWT with alg none", () => {
    const noneJwt = createTestJwt({ role: "admin" }, TEST_SECRET, { alg: "none", typ: "JWT" });
    const res = authenticate(`Bearer ${noneJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects JWT with alg HS512", () => {
    const hs512Jwt = createTestJwt({ role: "admin" }, TEST_SECRET, { alg: "HS512", typ: "JWT" });
    const res = authenticate(`Bearer ${hs512Jwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects expired JWT beyond 5-second skew", () => {
    const pastExp = Math.floor(Date.now() / 1000) - 10;
    const expiredJwt = createTestJwt({ role: "admin", exp: pastExp }, TEST_SECRET);
    const res = authenticate(`Bearer ${expiredJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("accepts expired JWT within 5-second clock skew", () => {
    const pastExp = Math.floor(Date.now() / 1000) - 2;
    const activeJwt = createTestJwt({ role: "admin", exp: pastExp }, TEST_SECRET);
    const res = authenticate(`Bearer ${activeJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(true);
  });

  it("rejects JWT with future nbf beyond 5-second skew", () => {
    const futureNbf = Math.floor(Date.now() / 1000) + 10;
    const futureJwt = createTestJwt({ role: "admin", nbf: futureNbf }, TEST_SECRET);
    const res = authenticate(`Bearer ${futureJwt}`, STATIC_TOKENS, TEST_SECRET);
    expect(res.authenticated).toBe(false);
  });

  it("rejects JWT missing role claim or with non-string role", () => {
    for (const badPayload of [{}, { role: 123 }, { role: true }, { role: null }, { role: {} }]) {
      const jwt = createTestJwt(badPayload, TEST_SECRET);
      const res = authenticate(`Bearer ${jwt}`, STATIC_TOKENS, TEST_SECRET);
      expect(res.authenticated).toBe(false);
    }
  });

  it("rejects unknown static token when secret not configured", () => {
    const res = authenticate("Bearer random-token-xyz", STATIC_TOKENS, undefined);
    expect(res.authenticated).toBe(false);
  });
});
