// Check 7 — "proof on-chain": confirm proof_tx is a real, finalised
// verification transaction on the zkVerify chain.
//
// ⚠️ SPEC GAP 6 (spec §9): the exact chain-query method is NOT documented on
// the public pages, and the mainnet explorer URL was not confirmed in the
// research (only the testnet Subscan explorer, zkverify-testnet.subscan.io).
// Do NOT guess a mainnet URL — set ZKVERIFY_EXPLORER_API once it is confirmed
// from the dashboard/docs (expected: a Subscan-compatible API base URL).
//
// Behaviour:
//   - Explorer configured + lookup says the tx EXISTS        -> { status: "found" }
//   - Explorer configured + lookup says it does NOT exist    -> { status: "not_found" }
//   - Explorer not configured, or the lookup is inconclusive
//     (network error, timeout, unexpected response)          -> { status: "inconclusive" }
//
// How "inconclusive" is treated is decided by the caller via the
// ONCHAIN_INCONCLUSIVE env var ("pass" | "reject"). The default is "pass":
// the lookup method is unconfirmed, so a broken/unknown lookup must NOT
// reject every valid task (the platform is expected to only dispatch tasks
// whose proofs exist). Once the lookup method is confirmed in Practice Mode,
// set ONCHAIN_INCONCLUSIVE=reject to follow the spec's strict fail-closed
// rule. This module only reports the lookup outcome — it never decides alone.
//
// Lookup implementation (active only when ZKVERIFY_EXPLORER_API is set):
// Subscan-compatible POST {base}/api/scan/extrinsic { hash }.
// The response shape varies by chain; we treat a 200 with a non-empty
// `data` object as "found", an explicit empty/null data as "not_found",
// and anything else (non-200, network error, timeout) as "inconclusive".
// If the confirmed explorer turns out to use a different API, swap ONLY
// this file's queryExtrinsic() implementation.

const LOOKUP_TIMEOUT_MS = 8000; // never let a chain lookup eat the 60s budget

export async function lookupProofTx(proofTx, explorerApiBase) {
  if (!explorerApiBase) {
    return { status: "inconclusive", detail: "no explorer configured (ZKVERIFY_EXPLORER_API unset)" };
  }
  const url = String(explorerApiBase).replace(/\/+$/, "") + "/api/scan/extrinsic";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash: proofTx }),
      signal: controller.signal,
    });
    if (!res.ok) {
      return { status: "inconclusive", detail: `explorer HTTP ${res.status}` };
    }
    const body = await res.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return { status: "inconclusive", detail: "explorer returned non-JSON" };
    }
    // Subscan convention: { code: 0, data: {...} } on success; data null/empty = not found.
    if (body.code !== undefined && body.code !== 0) {
      return { status: "inconclusive", detail: `explorer code ${body.code}` };
    }
    const data = body.data;
    if (data && typeof data === "object" && Object.keys(data).length > 0) {
      return { status: "found", detail: "extrinsic present on-chain" };
    }
    if (data === null || data === undefined || (typeof data === "object" && Object.keys(data).length === 0)) {
      return { status: "not_found", detail: "explorer returned no extrinsic for this hash" };
    }
    return { status: "inconclusive", detail: "unexpected explorer response shape" };
  } catch (err) {
    const msg = err && err.name === "AbortError" ? "lookup timed out" : String((err && err.message) || err);
    return { status: "inconclusive", detail: msg };
  } finally {
    clearTimeout(timer);
  }
}
