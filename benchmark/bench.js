import { performance } from "node:perf_hooks";
import { generateKeyset } from "zeyra";
import { JWT } from "../src/index.js";

const ITERATIONS = Number(process.env.BENCH_ITERS) || 150;
const KID = "bench-key";
const originalFetch = global.fetch;

const fmt = (num, digits = 2) => Number(num.toFixed(digits));

async function run() {
  const keyset = await generateKeyset();
  const publicJwk = { ...keyset.publicJwk, kid: KID };
  const privateJwk = { ...keyset.privateJwk, kid: KID };
  const jwt = new JWT(KID, "example.com", "bench-subject", 300);
  const signingInput = () => JWT.sign(privateJwk, jwt);

  global.fetch = async () => ({
    ok: true,
    json: async () => ({ keys: [publicJwk] }),
  });

  const token = await signingInput();

  const results = [];

  const bench = async (label, fn) => {
    const start = performance.now();
    for (let i = 0; i < ITERATIONS; i += 1) {
      await fn();
    }
    const durationMs = performance.now() - start;
    const opsPerSec = 1000 / (durationMs / ITERATIONS);
    results.push({
      task: label,
      iterations: ITERATIONS,
      "total (ms)": fmt(durationMs),
      "avg (ms)": fmt(durationMs / ITERATIONS, 4),
      "ops/sec": fmt(opsPerSec),
    });
  };

  await bench("sign", signingInput);
  await bench("verify", () => JWT.verify(token));

  console.log("\nquick-jwt benchmark (lower ms is better)");
  console.table(results);
}

run()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => {
    global.fetch = originalFetch;
  });
