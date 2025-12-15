# quick-jwt

Minimal ES256 JWT signer/verifier that pulls public keys from your JWKS endpoint. No custom claims, no middlemen—just subjects, issuers, and keys.

**Highlights**

- Opinionated: ES256 only, compact JWTs, subjects-only payloads
- JWKS native: verification fetches `https://<iss>/.well-known/jwks.json`
- Type-safe: bundled TypeScript defs for IntelliSense/IntelliCode
- Shipping ready: tests + micro-benchmark via `npm test`

## Install

```bash
npm install quick-jwt
```

Requires Node 18+ (for native `fetch` and WebCrypto).

## Quick start

```js
import { generateKeyset } from "zeyra";
import { JWT } from "quick-jwt";

const kid = "2025Q4";
const issuer = "api.example.com";
const subject = "user-123";

// Generate ES256 keys (P-256)
const { privateJwk, publicJwk } = await generateKeyset();

// Create & sign a token (exp is seconds from now or an epoch in ms)
const token = await JWT.sign(
  privateJwk,
  new JWT(kid, issuer, subject, 60) // 60 seconds from now
);

// In production, serve your JWKS at:
//   https://api.example.com/.well-known/jwks.json
// For tests/local dev, mock fetch with your public key:
global.fetch = async () => ({
  ok: true,
  json: async () => ({ keys: [{ kid, ...publicJwk }] }),
});

const verifiedSub = await JWT.verify(token);
console.log(verifiedSub); // "user-123" when valid, otherwise false
```

## API

- `new JWT(kid, iss, sub, exp)`
  - `kid`: key identifier that must match the JWK served in your JWKS
  - `iss`: issuer domain (no protocol)
  - `sub`: stable subject identifier
  - `exp`: either seconds from now (e.g. `60`) or an absolute epoch in milliseconds
- `JWT.sign(privateJwk, jwt) -> Promise<string>`
  - Signs the JWT with an ES256 private JWK (P-256). `kid` should be set on the key.
- `JWT.verify(token) -> Promise<string | false>`
  - Fetches the issuer JWKS, selects the matching `kid`, verifies the signature and expiration, and returns the subject when valid.

### JWKS example

Serve the public key that matches your `kid`:

```json
{
  "keys": [
    {
      "kid": "2025Q4",
      "kty": "EC",
      "crv": "P-256",
      "x": "…",
      "y": "…",
      "key_ops": ["verify"]
    }
  ]
}
```

## Tests and benchmarks

- Run tests + micro-benchmark: `npm test`
- Benchmark only: `npm run bench`
- Tweak iterations: `BENCH_ITERS=500 npm run bench`

Example output:

```
quick-jwt benchmark (lower ms is better)
task     iterations  total (ms)  avg (ms)  ops/sec
sign     150         80.5        0.5368    1863
verify   150         78.3        0.5219    1916
```

## IntelliSense

Type definitions ship with the package (`types/index.d.ts`), so editors and TypeScript projects get completions, parameter help, and return types out of the box.

## Notes

- Claims other than `iss`, `sub`, `iat`, and `exp` are intentionally excluded—keep authorization decisions at the resource layer.
- Make sure your JWKS is cache-friendly and rotates keys by updating both the `kid` in new tokens and the published key set.
