// Central configuration: environment variables + protocol constants.
// All secrets come from env only. Never hard-code a secret here.
//
// Env vars:
//   AGENT_GAMES_HMAC_SECRET   32-byte secret from the dashboard (shown once at registration)
//   HMAC_SECRET_ENCODING      "utf8" (default) or "hex" — how to decode AGENT_GAMES_HMAC_SECRET
//   HMAC_ALGORITHM            default "sha256" (UNCONFIRMED — confirm via preflight)
//   HMAC_ENCODING             "hex" (default) or "base64" — header value encoding
//   HMAC_PREFIX               default "" — e.g. "sha256=" if the platform prefixes the value
//   KURIER_API_KEY            free key from kurier.xyz (optional; Kurier is skipped if unset)
//   PORT                      listen port (Fly.io sets this); default 8080
//   HOST                      listen host; default 0.0.0.0
//   STATE_FILE                persistent seen-set + idempotency store; default ./data/state.json
//   LOG_FILE                  append-only JSONL log; default ./data/agent.log
//   PROVE_TIMEOUT_MS          budget for snarkjs fullProve per task; default 40000 (40s)
//                             The platform deadline is 60s; if proving exceeds the budget
//                             we return the decision WITHOUT a proof rather than timing out.
//   ZKVERIFY_EXPLORER_API     base URL of the zkVerify explorer API for check 7.
//                             Unset = check 7 lookup is skipped (see onchain.mjs).
//   ONCHAIN_INCONCLUSIVE      what to do when the check-7 lookup is inconclusive:
//                             "pass" (default) or "reject". See onchain.mjs for why the
//                             default is "pass" while the lookup method is unconfirmed.
//   REQUIRE_HMAC              "true" (default) — reject unsigned requests when a secret is set.
//                             If AGENT_GAMES_HMAC_SECRET is unset, HMAC is skipped with a
//                             loud warning (testing only — never run live without a secret).
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

export const config = {
  port: Number(env("PORT", "8080")),
  host: env("HOST", "0.0.0.0"),
  hmacSecret: env("AGENT_GAMES_HMAC_SECRET", ""),
  hmacSecretEncoding: env("HMAC_SECRET_ENCODING", "utf8"),
  hmacAlgorithm: env("HMAC_ALGORITHM", "sha256"),
  hmacEncoding: env("HMAC_ENCODING", "hex"),
  hmacPrefix: env("HMAC_PREFIX", ""),
  kurierApiKey: env("KURIER_API_KEY", ""),
  stateFile: env("STATE_FILE", path.join(ROOT, "data", "state.json")),
  logFile: env("LOG_FILE", path.join(ROOT, "data", "agent.log")),
  proveTimeoutMs: Number(env("PROVE_TIMEOUT_MS", "40000")),
  zkverifyExplorerApi: env("ZKVERIFY_EXPLORER_API", ""),
  onchainInconclusive: env("ONCHAIN_INCONCLUSIVE", "pass"),
  requireHmac: env("REQUIRE_HMAC", "true") === "true",
  wasmPath: path.join(ROOT, "circuits", "gatekeeper.wasm"),
  zkeyPath: path.join(ROOT, "circuits", "gatekeeper_final.zkey"),
  vkeyPath: path.join(ROOT, "circuits", "gatekeeper.vkey.json"),
};

// BN128 (BN254) field prime — the circuit's field. Any field element must be < this.
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

// Published gatekeeper verification-key hash (mainnet, already registered).
// From /api/circuit-info. Used as the `vk` value in Kurier submit-proof
// (vkRegistered: true). Do NOT re-register this key.
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const KURIER_API_BASE = "https://api.kurier.xyz/api/v1";

// The 60s platform deadline, for reference in logs. The proving budget
// (PROVE_TIMEOUT_MS) is deliberately smaller so we can still respond.
export const PLATFORM_DEADLINE_MS = 60000;
