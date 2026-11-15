// Kurier submission (zkVerify mainnet, REST, free API key).
// From SPEC.md §7 and the official submit-proof snippet.
//
// IMPORTANT TIMING: the response to the platform must carry the LOCAL
// Groth16 proof (that is what the platform re-verifies). Kurier submission
// happens AFTER the response is sent, asynchronously — never block the 60s
// response deadline waiting for Kurier to reach Finalized. If Kurier fails,
// the local proof in the response still stands.
//
// Flow: submit-proof -> { jobId, optimisticVerify } -> poll job-status
// every 5s until "Finalized" (or "Failed"). The final job object carries
// txHash + blockHash — the on-chain proof reference.
// If KURIER_API_KEY is unset, submission is skipped (logged) — the service
// still works, it just does not anchor proofs on-chain via Kurier.
import { KURIER_API_BASE, GATEKEEPER_VK_HASH } from "./config.mjs";

const POLL_INTERVAL_MS = 5000;
const POLL_MAX_ATTEMPTS = 24; // ~2 minutes of polling, then give up (logged)

// Submit a proof. Returns { jobId } on success, { error } on failure.
export async function submitProof(apiKey, proof, publicSignals) {
  const url = `${KURIER_API_BASE}/submit-proof/${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: {
        proof,
        publicSignals,
        vk: GATEKEEPER_VK_HASH, // the vk HASH string, NOT the vk JSON
      },
    }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    return { error: `Kurier submit HTTP ${res.status}: ${JSON.stringify(body)}` };
  }
  if (!body || !body.jobId) {
    return { error: `Kurier submit returned no jobId: ${JSON.stringify(body)}` };
  }
  return { jobId: body.jobId, optimisticVerify: body.optimisticVerify || null };
}

// Poll one job until Finalized/Failed or the attempt budget is exhausted.
// Returns { status, txHash, blockHash } or { status: "poll_timeout", ... }.
export async function pollJob(apiKey, jobId) {
  const url = `${KURIER_API_BASE}/job-status/${apiKey}/${jobId}`;
  for (let attempt = 1; attempt <= POLL_MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(url);
      const body = await res.json().catch(() => null);
      const status = body && (body.status || body.jobStatus);
      if (status === "Finalized") {
        return { status: "Finalized", txHash: body.txHash || null, blockHash: body.blockHash || null };
      }
      if (status === "Failed") {
        return { status: "Failed", txHash: null, blockHash: null, detail: JSON.stringify(body) };
      }
      // Queued | Valid | Submitted | IncludedInBlock | unknown — keep polling.
    } catch (err) {
      // Transient network error — keep polling until the budget is spent.
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
  return { status: "poll_timeout", txHash: null, blockHash: null };
}

// Fire-and-forget wrapper: submit, then poll, then hand the outcome to
// `onDone` (which logs it). Never throws — all failures are reported
// through onDone. Call this AFTER the platform response has been sent.
export async function submitAndTrack(apiKey, proof, publicSignals, onDone) {
  const done = (result) => {
    try { onDone(result); } catch { /* logging must never crash the agent */ }
  };
  try {
    const submitted = await submitProof(apiKey, proof, publicSignals);
    if (submitted.error) {
      done({ phase: "submit_failed", error: submitted.error });
      return;
    }
    const final = await pollJob(apiKey, submitted.jobId);
    done({
      phase: "done",
      jobId: submitted.jobId,
      optimisticVerify: submitted.optimisticVerify,
      finalStatus: final.status,
      txHash: final.txHash,
      blockHash: final.blockHash,
      detail: final.detail || null,
    });
  } catch (err) {
    done({ phase: "error", error: String((err && err.message) || err) });
  }
}
