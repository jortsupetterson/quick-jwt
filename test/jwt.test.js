import assert from "node:assert/strict";
import { test, beforeEach, afterEach } from "node:test";
import { generateKeyset } from "zeyra";
import { JWT } from "../src/index.js";

const KID = "test-key";
let publicJwk;
let privateJwk;
const originalFetch = global.fetch;

beforeEach(async () => {
  const keyset = await generateKeyset();
  publicJwk = { ...keyset.publicJwk, kid: KID };
  privateJwk = { ...keyset.privateJwk, kid: KID };
});

afterEach(() => {
  global.fetch = originalFetch;
});

const mockFetch = (jwks) => async (url) => {
  assert.match(
    url,
    /https:\/\/example\.com\/\.well-known\/jwks\.json/,
    "verify should request the issuer JWKS"
  );
  return {
    ok: true,
    json: async () => ({ keys: jwks }),
  };
};

test("sign and verify returns the subject", async () => {
  const jwt = new JWT(KID, "example.com", "user-123", 60);
  global.fetch = mockFetch([publicJwk]);

  const token = await JWT.sign(privateJwk, jwt);
  const sub = await JWT.verify(token);

  assert.equal(sub, "user-123");
});

test("expired token is rejected", async () => {
  const jwt = new JWT(KID, "example.com", "user-123", -10);
  global.fetch = mockFetch([publicJwk]);

  const token = await JWT.sign(privateJwk, jwt);
  const sub = await JWT.verify(token);

  assert.equal(sub, false);
});

test("verification fails when JWKS does not contain the kid", async () => {
  const jwt = new JWT(KID, "example.com", "user-123", 60);
  global.fetch = mockFetch([{ ...publicJwk, kid: "other-key" }]);

  const token = await JWT.sign(privateJwk, jwt);
  const sub = await JWT.verify(token);

  assert.equal(sub, false);
});

test("malformed token fails fast", async () => {
  const sub = await JWT.verify("not-a-jwt");
  assert.equal(sub, false);
});
