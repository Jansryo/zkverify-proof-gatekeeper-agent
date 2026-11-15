// Groth16 proving with snarkjs (local, no network).
// Uses the downloaded gatekeeper.wasm + gatekeeper_final.zkey.
//
// The circuit enforces correctness: a valid proof can only be produced for
// the CORRECT decision (a wrong APPROVE fails proof generation — verified in
// the research). So the proof is generated for the decision we already made
// in decision.mjs; if generation fails, the decision is still returned
// (without a proof) rather than timing out — a correct decision without a
// proof scores +12 − 2, a timeout scores −2 and loses the decision.
//
// Proving budget: fullProve is raced against PROVE_TIMEOUT_MS. On this
// throttled dev VM fullProve took ~180s for this small circuit; on a normal
// host it should be seconds — but MEASURE it on the deployment host. If the
// budget is exceeded we return the decision without a proof (never blow the
// platform's 60s deadline waiting for a proof).
import * as snarkjs from "snarkjs";
import crypto from "node:crypto";
import fs from "node:fs";
import { encodeTaskId, encodeVkHash, encodeAddress } from "./encoding.mjs";

let cachedVk = null;

export function loadVerificationKey(vkeyPath) {
  if (!cachedVk) {
    cachedVk = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
  }
  return cachedVk;
}

// Build the 13 circuit inputs from a task envelope + the decided decision.
// decision: "APPROVE" -> "1", "REJECT" -> "0" (verified in the research).
// salt: fresh cryptographically random 128-bit per task (private input;
// it only seeds publicSignals[0] = Poseidon(salt, taskId)).
export function buildCircuitInput(task, decision) {
  const input = task.input;
  return {
    taskId: encodeTaskId(task.task_id),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: encodeAddress(input.recipient),
    conditionRecipient: encodeAddress(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    registeredVkHash: encodeVkHash(input.registered_vk),
    proofVkHash: encodeVkHash(input.proof_vk),
    // The salt must be a DECIMAL string (a field element). A hex string
    // fails inside snarkjs ("Cannot convert ... to a BigInt") because it
    // contains a–f. Generate 128 random bits and express them in decimal.
    salt: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(10),
  };
}

// Generate a proof, bounded by timeoutMs. Returns:
//   { ok: true, proof, publicSignals, proveMs, verified: true|false }
//   { ok: false, error, proveMs }  — on timeout or generation failure.
// The caller decides what to return to the platform in the failure case
// (decision without a proof). `verified` is a local snarkjs self-check.
export async function generateProof(task, decision, paths, timeoutMs) {
  const started = Date.now();
  const circuitInput = buildCircuitInput(task, decision);
  const provePromise = (async () => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      paths.wasmPath,
      paths.zkeyPath
    );
    const vk = loadVerificationKey(paths.vkeyPath);
    const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
    return { proof, publicSignals, verified };
  })();
  let timeoutId;
  const timeoutPromise = new Promise((resolve) => {
    timeoutId = setTimeout(
      () => resolve({ timedOut: true }),
      Math.max(1000, timeoutMs)
    );
  });
  try {
    const result = await Promise.race([provePromise, timeoutPromise]);
    const proveMs = Date.now() - started;
    if (result.timedOut) {
      // The proof may still resolve later in the background; harmless.
      provePromise.catch(() => {});
      return { ok: false, error: `proving exceeded ${timeoutMs}ms budget`, proveMs };
    }
    return { ok: true, proof: result.proof, publicSignals: result.publicSignals, proveMs, verified: result.verified };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err), proveMs: Date.now() - started };
  } finally {
    clearTimeout(timeoutId);
  }
}
