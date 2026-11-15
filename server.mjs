// Proof Gatekeeper agent — HTTP service.
//
// POST /agent  — the platform's task endpoint (also accepts POST / as a
//                fallback, in case the registered URL has no path).
// GET  /health — health check (also GET / returns the same status JSON).
//
// Request flow (POST):
//   raw body -> HMAC verify (fail closed, 401) -> JSON parse
//   -> preflight? respond {ok:true, protocolVersion:"v1"} (signed)
//   -> task? idempotency check -> validate -> 7 deterministic checks
//        -> Groth16 proof (bounded by PROVE_TIMEOUT_MS) -> signed response
//        -> Kurier submit+poll happens AFTER responding (async, non-blocking)
// Fail closed throughout: any error/uncertainty -> REJECT, never approve
// by default. A correct decision returned without a proof still scores
// (+12 − 2); a timeout scores −2 and loses the decision.
//
// Run:  node server.mjs   (env vars in config.mjs / .env.example)
import http from "node:http";
import { config } from "./src/config.mjs";
import { signBody, verifySignature, SIGNATURE_HEADER } from "./src/hmac.mjs";
import { validateTask, decide, REASON } from "./src/decision.mjs";
import { generateProof } from "./src/prover.mjs";
import { StateStore } from "./src/store.mjs";
import { submitAndTrack } from "./src/kurier.mjs";
import { makeLogger } from "./src/logger.mjs";

const logger = makeLogger(config.logFile);
const store = new StateStore(config.stateFile);

const MAX_BODY_BYTES = 1024 * 1024; // 1 MB — task envelopes are a few KB

// ---------- helpers ----------

function hmacOpts() {
  return {
    algorithm: config.hmacAlgorithm,
    encoding: config.hmacEncoding,
    prefix: config.hmacPrefix,
    secretEncoding: config.hmacSecretEncoding,
  };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Send a JSON response, signed when a secret is configured.
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers = { "content-type": "application/json" };
  if (config.hmacSecret) {
    headers[SIGNATURE_HEADER] = signBody(config.hmacSecret, body, hmacOpts());
  }
  res.writeHead(status, headers);
  res.end(body);
}

// Verify the inbound signature. Returns true when the request may proceed.
// When no secret is configured, verification is skipped with a loud warning
// (testing only — never run live without AGENT_GAMES_HMAC_SECRET).
function checkInboundSignature(req, rawBody) {
  if (!config.hmacSecret) {
    logger.log({ event: "hmac_skipped", warning: "AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC verification is OFF (testing only)" });
    return true;
  }
  if (!config.requireHmac) {
    logger.log({ event: "hmac_skipped", warning: "REQUIRE_HMAC=false — inbound HMAC verification is OFF (testing only)" });
    return true;
  }
  const header = req.headers[SIGNATURE_HEADER.toLowerCase()];
  if (!header) return false;
  return verifySignature(config.hmacSecret, rawBody, header, hmacOpts());
}

// ---------- task handling ----------

async function handleTask(task) {
  const taskId = typeof task.task_id === "string" ? task.task_id : "";

  // Idempotency: a retried task_id returns the stored response — never
  // re-decide, re-prove, or double-count its proof_tx.
  if (taskId) {
    const stored = store.getStoredResponse(taskId);
    if (stored) {
      logger.log({ event: "idempotent_replay", taskId });
      return { response: stored, replayed: true };
    }
  }

  // Validate the envelope shape.
  const invalid = validateTask(task);
  if (invalid) {
    const response = {
      decision: "REJECT",
      reason_code: REASON.INVALID_TASK,
      proof_tx: task.input && task.input.proof_tx ? String(task.input.proof_tx) : null,
      proof: null,
      public_signals: [],
    };
    if (taskId) store.storeResponse(taskId, response);
    logger.log({ event: "invalid_task", taskId, error: invalid });
    return { response, replayed: false, decision: "REJECT", reason_code: REASON.INVALID_TASK };
  }

  // The 7 deterministic checks.
  const { decision, reason_code, onchain } = await decide(task, {
    hasSeenProofTx: (tx) => store.hasSeenProofTx(tx),
    explorerApiBase: config.zkverifyExplorerApi,
    onchainInconclusive: config.onchainInconclusive,
  });

  // PROOF_REUSED carries no proof (the proof_tx was already used) and is
  // excluded from the reliability-bonus denominator — return decision only.
  if (reason_code === REASON.REUSED) {
    const response = {
      decision,
      reason_code,
      proof_tx: String(task.input.proof_tx),
      proof: null,
      public_signals: [],
    };
    store.storeResponse(taskId, response);
    logger.log({ event: "decision", taskId, decision, reason_code, proof: false, onchain: onchain ? onchain.status : null });
    return { response, replayed: false, decision, reason_code };
  }

  // Generate the Groth16 proof for the decided decision, bounded by the
  // proving budget. On timeout/failure we still return the decision
  // without a proof (better than a platform timeout).
  const proofResult = await generateProof(task, decision, {
    wasmPath: config.wasmPath,
    zkeyPath: config.zkeyPath,
    vkeyPath: config.vkeyPath,
  }, config.proveTimeoutMs);

  const response = {
    decision,
    reason_code,
    proof_tx: String(task.input.proof_tx),
    proof: proofResult.ok ? proofResult.proof : null,
    public_signals: proofResult.ok ? proofResult.publicSignals : [],
  };

  store.storeResponse(taskId, response);
  // The proof_tx has now been presented in a decided task — mark it seen
  // so a later task reusing it is caught by check 3.
  store.markProofTxSeen(String(task.input.proof_tx), taskId);

  logger.log({
    event: "decision",
    taskId,
    decision,
    reason_code,
    proof: proofResult.ok,
    proofVerifiedLocally: proofResult.ok ? proofResult.verified : null,
    proveMs: proofResult.proveMs,
    proofError: proofResult.ok ? null : proofResult.error,
    onchain: onchain ? onchain.status : null,
    onchainDetail: onchain ? onchain.detail : null,
  });

  return {
    response,
    replayed: false,
    decision,
    reason_code,
    proof: proofResult.ok ? proofResult.proof : null,
    publicSignals: proofResult.ok ? proofResult.publicSignals : null,
    taskId,
  };
}

// Kurier submission runs AFTER the platform response has been sent.
// Fire-and-forget; the outcome is only logged.
function trackWithKurier(result) {
  if (!config.kurierApiKey) {
    logger.log({ event: "kurier_skipped", taskId: result.taskId, warning: "KURIER_API_KEY is not set — proof is not anchored on-chain via Kurier" });
    return;
  }
  if (!result.proof) return; // nothing to anchor (no proof generated)
  submitAndTrack(config.kurierApiKey, result.proof, result.publicSignals, (outcome) => {
    logger.log({ event: "kurier", taskId: result.taskId, ...outcome });
  }).catch(() => {});
}

// ---------- HTTP server ----------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  if (req.method === "GET" && (pathname === "/health" || pathname === "/")) {
    sendJson(res, 200, {
      ok: true,
      service: "zkverify-proof-gatekeeper-agent",
      version: "1.0.0",
      uptimeSec: Math.floor(process.uptime()),
      state: store.stats(),
      hmacConfigured: Boolean(config.hmacSecret),
      kurierConfigured: Boolean(config.kurierApiKey),
    });
    return;
  }

  if (req.method !== "POST" || (pathname !== "/agent" && pathname !== "/")) {
    sendJson(res, 404, { ok: false, error: "not found" });
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    sendJson(res, 413, { ok: false, error: String((err && err.message) || err) });
    return;
  }

  if (!checkInboundSignature(req, rawBody)) {
    logger.log({ event: "hmac_rejected", path: pathname });
    sendJson(res, 401, { ok: false, error: "invalid signature" });
    return;
  }

  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    sendJson(res, 400, { ok: false, error: "invalid JSON" });
    return;
  }

  // Preflight handshake (signed).
  if (body && body.type === "agent-games.preflight.v1") {
    logger.log({ event: "preflight", agent_id: body.agent_id || null, nonce: body.nonce || null });
    sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    return;
  }

  // Proof Gatekeeper task.
  if (body && body.type === "agent-games.proof-gatekeeper.v1") {
    try {
      const result = await handleTask(body);
      sendJson(res, 200, result.response);
      // Anchor the proof on-chain via Kurier AFTER responding.
      if (!result.replayed) trackWithKurier(result);
    } catch (err) {
      // Never crash on a task, and never leave the platform hanging: fail
      // closed with a REJECT. (A 500 here would read as a timeout = −2 and
      // lose the decision; a REJECT at least scores the decision.)
      const taskId = typeof body.task_id === "string" ? body.task_id : "";
      logger.log({ event: "handler_error", taskId, error: String((err && err.message) || err) });
      sendJson(res, 200, {
        decision: "REJECT",
        reason_code: REASON.INVALID_TASK,
        proof_tx: body.input && body.input.proof_tx ? String(body.input.proof_tx) : null,
        proof: null,
        public_signals: [],
      });
    }
    return;
  }

  sendJson(res, 400, { ok: false, error: `unsupported type "${body && body.type}"` });
});

server.listen(config.port, config.host, () => {
  console.log(`[startup] proof-gatekeeper agent listening on http://${config.host}:${config.port}`);
  console.log(`[startup] POST /agent (tasks), GET /health (status)`);
  console.log(`[startup] HMAC configured: ${Boolean(config.hmacSecret)} (algorithm=${config.hmacAlgorithm}, encoding=${config.hmacEncoding}, prefix="${config.hmacPrefix}")`);
  console.log(`[startup] Kurier configured: ${Boolean(config.kurierApiKey)}`);
  console.log(`[startup] Proving budget: ${config.proveTimeoutMs}ms (platform deadline 60s)`);
  console.log(`[startup] Check-7 explorer: ${config.zkverifyExplorerApi || "(not configured — lookup skipped, inconclusive defaults to '" + config.onchainInconclusive + "')"}`);
  console.log(`[startup] State: ${JSON.stringify(store.stats())}`);
  if (!config.hmacSecret) {
    console.log("[startup] WARNING: AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC verification is OFF. Set it before going live.");
  }
});
