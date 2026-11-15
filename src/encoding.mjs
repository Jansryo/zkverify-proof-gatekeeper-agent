// Field-element encodings for the circuit inputs.
//
// ⚠️ TWO OF THESE ARE UNCONFIRMED (spec §9 gaps 1–2) and must be verified
// against a Practice Mode task before the first scored round. They are kept
// as small, isolated functions here precisely so they can be swapped without
// touching the decision or proving logic. Do NOT inline them elsewhere.
//
//   encodeTaskId  — task_id is a string like "gk_24_9d1"; the circuit needs
//                   a field element. Working hypothesis: the numeric task
//                   number (the segment after "gk_").
//   encodeVkHash  — registered_vk / proof_vk are 256-bit hex hashes, larger
//                   than the BN128 field prime (~254 bits), so they cannot be
//                   used raw. Working hypothesis: BigInt(hash) mod FIELD_PRIME.
//
//   encodeAddress — a 160-bit EVM address fits the field, no reduction needed.
//                   This one is NOT a gap (verified in the research).
import { FIELD_PRIME } from "./config.mjs";

// "gk_24_9d1" -> "24". Prefers the segment after "gk_"; falls back to the
// first digit run in the string. Throws if no digits are present.
// CONFIRM IN PRACTICE MODE: the real encoding could be a hash of the string.
export function encodeTaskId(taskId) {
  const s = String(taskId);
  const parts = s.split("_");
  for (const p of parts) {
    if (/^\d+$/.test(p)) return p;
  }
  const m = s.match(/\d+/);
  if (m) return m[0];
  throw new Error(`encodeTaskId: no numeric part in task_id "${s}"`);
}

// 256-bit hex hash -> field element via BigInt(hash) mod FIELD_PRIME.
// Accepts "0x…" or bare hex. Returns a decimal string.
// CONFIRM IN PRACTICE MODE: the platform's exact reduction/truncation is
// not documented; mod FIELD_PRIME is the working hypothesis.
export function encodeVkHash(hexHash) {
  const s = String(hexHash).trim();
  const cleaned = s.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
    throw new Error(`encodeVkHash: not a hex hash "${s}"`);
  }
  const value = BigInt("0x" + cleaned) % FIELD_PRIME;
  return value.toString(10);
}

// 160-bit EVM address -> decimal string. Fits the field; no reduction.
// Accepts "0x…" or bare hex. Throws on a non-hex or over-long value.
export function encodeAddress(hexAddress) {
  const s = String(hexAddress).trim();
  const cleaned = s.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length > 40) {
    throw new Error(`encodeAddress: not a 160-bit hex address "${s}"`);
  }
  return BigInt("0x" + cleaned).toString(10);
}

// Normalise a hex string for comparison (lowercase, keep the 0x prefix).
export function normaliseHex(s) {
  return String(s).trim().toLowerCase();
}
