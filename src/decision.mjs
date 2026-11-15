// Deterministic decision logic — the 7 checks from SPEC.md §6.1.
// APPROVE only when EVERY check passes. Otherwise REJECT with the
// reason_code of the first failing check. Checks run in the order below;
// each task carries at most one trap, so the order does not change the
// outcome, but the first failure is what gets reported.
//
// This module is PURE and deterministic: it never calls a model, never
// makes a network request except through the injected onchain lookup, and
// never approves on uncertainty (fail closed).
//
// Reason codes (from the platform):
//   VALID_CONDITION    all checks pass -> APPROVE
//   VK_SUBSTITUTION    proof_vk != registered_vk
//   THRESHOLD_MISMATCH public_balance < minimum
//   PROOF_REUSED       proof_tx already seen
//   EXPIRED_CONDITION  current_block > expiry_block
//   RECIPIENT_MISMATCH recipient != condition_recipient
//   AMOUNT_OVERFLOW    amount > max_transfer
//   PROOF_NOT_CONFIRMED (ours — no published code for check 7; see onchain.mjs)
//   INVALID_TASK       malformed envelope (fail closed)
import { normaliseHex } from "./encoding.mjs";
import { lookupProofTx } from "./onchain.mjs";

export const REASON = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
  NOT_CONFIRMED: "PROOF_NOT_CONFIRMED",
  INVALID_TASK: "INVALID_TASK",
};

// Validate the envelope shape. Returns null when valid, else a reason string.
// Amounts/balances arrive as DECIMAL STRINGS, blocks as NUMBERS (spec §2) —
// accept both string and number forms here and normalise downstream.
export function validateTask(task) {
  if (!task || typeof task !== "object") return "task is not an object";
  if (task.type !== "agent-games.proof-gatekeeper.v1") return `unexpected type "${task.type}"`;
  if (typeof task.task_id !== "string" || task.task_id.length === 0) return "missing task_id";
  const input = task.input;
  if (!input || typeof input !== "object") return "missing input";
  const required = [
    "registered_vk", "proof_vk", "minimum", "public_balance",
    "expiry_block", "current_block", "recipient", "condition_recipient",
    "amount", "max_transfer", "proof_tx",
  ];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      return `missing input.${f}`;
    }
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    if (!/^\d+$/.test(String(input[f]))) return `input.${f} is not a non-negative integer ("${input[f]}")`;
  }
  for (const f of ["expiry_block", "current_block"]) {
    if (!/^\d+$/.test(String(input[f]))) return `input.${f} is not a non-negative integer ("${input[f]}")`;
  }
  return null;
}

// Run the 7 checks. `deps` supplies the external state:
//   hasSeenProofTx(proofTx) -> boolean
//   explorerApiBase          -> string ("" = lookup skipped)
//   onchainInconclusive      -> "pass" | "reject"
// Returns { decision: "APPROVE"|"REJECT", reason_code, onchain }.
// `onchain` is the raw check-7 lookup outcome (for logging).
export async function decide(task, deps) {
  const input = task.input;

  // 1 — VK match (string equality on the normalised hex hashes).
  if (normaliseHex(input.proof_vk) !== normaliseHex(input.registered_vk)) {
    return { decision: "REJECT", reason_code: REASON.VK, onchain: null };
  }

  // 2 — Threshold: public_balance >= minimum.
  if (BigInt(String(input.public_balance)) < BigInt(String(input.minimum))) {
    return { decision: "REJECT", reason_code: REASON.THRESHOLD, onchain: null };
  }

  // 3 — Replay: proof_tx must not have been seen before.
  if (deps.hasSeenProofTx(input.proof_tx)) {
    return { decision: "REJECT", reason_code: REASON.REUSED, onchain: null };
  }

  // 4 — Expiry: current_block <= expiry_block.
  if (BigInt(String(input.current_block)) > BigInt(String(input.expiry_block))) {
    return { decision: "REJECT", reason_code: REASON.EXPIRED, onchain: null };
  }

  // 5 — Recipient: recipient == condition_recipient.
  if (normaliseHex(input.recipient) !== normaliseHex(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: REASON.RECIPIENT, onchain: null };
  }

  // 6 — Amount: amount <= max_transfer.
  if (BigInt(String(input.amount)) > BigInt(String(input.max_transfer))) {
    return { decision: "REJECT", reason_code: REASON.AMOUNT, onchain: null };
  }

  // 7 — Proof on-chain: proof_tx must be a real finalised verification.
  const onchain = await lookupProofTx(input.proof_tx, deps.explorerApiBase || "");
  if (onchain.status === "not_found") {
    return { decision: "REJECT", reason_code: REASON.NOT_CONFIRMED, onchain };
  }
  if (onchain.status === "inconclusive" && deps.onchainInconclusive === "reject") {
    return { decision: "REJECT", reason_code: REASON.NOT_CONFIRMED, onchain };
  }
  // "found", or "inconclusive" with ONCHAIN_INCONCLUSIVE=pass (the default
  // while the lookup method is unconfirmed — see onchain.mjs).
  return { decision: "APPROVE", reason_code: REASON.VALID, onchain };
}
