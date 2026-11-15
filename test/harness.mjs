// Local test harness — replays sample envelopes against a live server
// instance and checks the responses end to end.
//
// Run:  npm test
//   (starts the server on a test port with a dummy HMAC secret, sends the
//   cases below, verifies each response shape + the Groth16 proof with
//   snarkjs, then exits 0 on PASS / 1 on FAIL.)
//
// Cases:
//   1. preflight            -> {ok:true, protocolVersion:"v1"}, signed
//   2. valid APPROVE task   -> APPROVE / VALID_CONDITION + valid proof (13 signals)
//   3. VK mismatch          -> REJECT / VK_SUBSTITUTION + valid proof
//   4. threshold mismatch   -> REJECT / THRESHOLD_MISMATCH + valid proof
//   5. idempotency          -> resending case 2's task_id returns the stored
//                              response (same proof), NOT a PROOF_REUSED
//   6. replay (new task_id, same proof_tx as case 2) -> REJECT / PROOF_REUSED, no proof
//   7. bad HMAC             -> 401
//   8. health               -> GET /health 200
//
// NOTE: each decided task triggers a real snarkjs fullProve. On a throttled
// host that can take minutes per proof — the harness waits patiently (the
// platform deadline is 60s, so a slow host is a deployment problem, not a
// test problem). Set HARNESS_PROVE_TIMEOUT_MS to raise the server's proving
// budget for the test (default 300000 = 5 min per proof).
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PORT = 18777;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "harness-dummy-secret-do-not-use-in-production";
const VK = JSON.parse(fs.readFileSync(path.join(ROOT, "circuits", "gatekeeper.vkey.json"), "utf8"));

const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const VK_A = "0x" + "ab".repeat(32); // full 256-bit hash
const VK_B = "0x" + "cd".repeat(32); // a different full 256-bit hash
const TX_1 = "0x" + "12".repeat(32);
const TX_2 = "0x" + "34".repeat(32);
const TX_3 = "0x" + "56".repeat(32);

function task(taskId, overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: TX_1,
      ...overrides,
    },
  };
}

function sign(rawBody) {
  return crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");
}

async function post(pathname, obj, { goodSig = true } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  const sig = goodSig ? sign(raw) : "deadbeef";
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, json, text, respSig: res.headers.get("x-agent-games-signature"), rawBody: text };
}

function verifyRespSig(rawBody, sig) {
  if (!sig) return false;
  const expected = sign(Buffer.from(rawBody, "utf8"));
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
}

async function verifyProof(json) {
  if (!json.proof || !Array.isArray(json.public_signals) || json.public_signals.length !== 13) return false;
  return snarkjs.groth16.verify(VK, json.public_signals, json.proof);
}

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

async function waitForHealth(timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const res = await fetch(BASE + "/health");
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

async function main() {
  // Fresh state for the harness (isolated from any real run).
  const stateFile = path.join(ROOT, "data", "harness-state.json");
  const logFile = path.join(ROOT, "data", "harness.log");
  try { fs.unlinkSync(stateFile); } catch { /* first run */ }

  const env = {
    ...process.env,
    PORT: String(PORT),
    HOST: "127.0.0.1",
    AGENT_GAMES_HMAC_SECRET: SECRET,
    KURIER_API_KEY: "",
    STATE_FILE: stateFile,
    LOG_FILE: logFile,
    PROVE_TIMEOUT_MS: process.env.HARNESS_PROVE_TIMEOUT_MS || "300000",
    ZKVERIFY_EXPLORER_API: "",
    ONCHAIN_INCONCLUSIVE: "pass",
  };
  const server = spawn("node", ["server.mjs"], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  let serverOut = "";
  server.stdout.on("data", (d) => { serverOut += d; });
  server.stderr.on("data", (d) => { serverOut += d; });

  try {
    check("server starts + /health", await waitForHealth());

    // 1 — preflight
    {
      const r = await post("/agent", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
      check("preflight -> {ok:true, protocolVersion:v1}", r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === "v1", `status=${r.status}`);
      check("preflight response is signed", verifyRespSig(r.rawBody, r.respSig));
    }

    // 2 — valid APPROVE (all checks pass)
    let approveProof = null;
    {
      const t0 = Date.now();
      const r = await post("/agent", task("gk_24_9d1"));
      const dt = Date.now() - t0;
      check("APPROVE task -> 200", r.status === 200, `status=${r.status}`);
      check("APPROVE decision + VALID_CONDITION", r.json && r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION", JSON.stringify(r.json && { d: r.json.decision, rc: r.json.reason_code }));
      check("APPROVE response is signed", verifyRespSig(r.rawBody, r.respSig));
      check("APPROVE proof_tx echoed", r.json && r.json.proof_tx === TX_1);
      const proofOk = await verifyProof(r.json || {});
      check("APPROVE Groth16 proof verifies locally", proofOk, `prove+respond took ${dt}ms`);
      approveProof = r.json && r.json.proof;
    }

    // 3 — VK mismatch -> REJECT + valid proof
    {
      const r = await post("/agent", task("gk_25_9d2", { proof_vk: VK_B, proof_tx: TX_2 }));
      check("VK mismatch -> REJECT / VK_SUBSTITUTION", r.json && r.json.decision === "REJECT" && r.json.reason_code === "VK_SUBSTITUTION", JSON.stringify(r.json && { d: r.json.decision, rc: r.json.reason_code }));
      check("VK mismatch proof verifies locally", await verifyProof(r.json || {}));
    }

    // 4 — threshold mismatch -> REJECT + valid proof
    {
      const r = await post("/agent", task("gk_26_9d3", { public_balance: "500", proof_tx: TX_3 }));
      check("threshold mismatch -> REJECT / THRESHOLD_MISMATCH", r.json && r.json.decision === "REJECT" && r.json.reason_code === "THRESHOLD_MISMATCH", JSON.stringify(r.json && { d: r.json.decision, rc: r.json.reason_code }));
      check("threshold proof verifies locally", await verifyProof(r.json || {}));
    }

    // 5 — idempotency: resend case 2's task_id, expect the STORED response
    {
      const r = await post("/agent", task("gk_24_9d1"));
      const sameProof = r.json && approveProof && JSON.stringify(r.json.proof) === JSON.stringify(approveProof);
      check("idempotent replay returns stored response (same proof)", r.json && r.json.decision === "APPROVE" && sameProof, JSON.stringify(r.json && { d: r.json.decision, rc: r.json.reason_code }));
    }

    // 6 — replay: new task_id, same proof_tx as case 2 -> PROOF_REUSED, no proof
    {
      const r = await post("/agent", task("gk_27_9d4", { proof_tx: TX_1 }));
      check("reused proof_tx -> REJECT / PROOF_REUSED, no proof", r.json && r.json.decision === "REJECT" && r.json.reason_code === "PROOF_REUSED" && r.json.proof === null && Array.isArray(r.json.public_signals) && r.json.public_signals.length === 0, JSON.stringify(r.json && { d: r.json.decision, rc: r.json.reason_code }));
    }

    // 7 — bad HMAC -> 401
    {
      const r = await post("/agent", task("gk_28_9d5"), { goodSig: false });
      check("bad HMAC -> 401", r.status === 401, `status=${r.status}`);
    }

    // 8 — health endpoint
    {
      const res = await fetch(BASE + "/health");
      const j = await res.json().catch(() => null);
      check("GET /health -> 200 + ok", res.ok && j && j.ok === true, `status=${res.status}`);
    }
  } finally {
    server.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    if (serverOut) console.log("\n--- server output (tail) ---\n" + serverOut.split("\n").slice(-15).join("\n"));
  }

  console.log(failures === 0 ? "\nALL HARNESS CHECKS PASSED" : `\n${failures} HARNESS CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("HARNESS CRASHED:", err);
  process.exit(1);
});
