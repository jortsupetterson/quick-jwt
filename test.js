import { generateKeyset } from "zeyra";
import { JWT } from "./src/index.js";

const kid = "demo-key";
const issuer = "api.example.com";
const subject = crypto.randomUUID();

const { privateJwk, publicJwk } = await generateKeyset();

// In production, serve this JWKS at https://api.example.com/.well-known/jwks.json.
// For local testing, mock fetch so verify never leaves your machine.
global.fetch = async () => ({
  ok: true,
  json: async () => ({ keys: [{ ...publicJwk, kid }] }),
});

const token = await JWT.sign(
  { ...privateJwk, kid },
  new JWT(kid, issuer, subject, 60 * 60) // expires in 1 hour
);

const verifiedSubject = await JWT.verify(token);

console.log({ token, verifiedSubject });
