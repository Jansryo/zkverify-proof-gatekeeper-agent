// HMAC signing / verification for the Agent Games protocol.
// Header: x-agent-games-signature, over the RAW request/response body bytes.
// Algorithm + header encoding are NOT named on the public pages — the
// defaults below (HMAC-SHA256, hex, no prefix) are the standard construction
// for this pattern and are consistent with the 32-byte secret. CONFIRM via
// the signed preflight: if the platform rejects a signed preflight response,
// the hash/encoding is wrong — adjust HMAC_ALGORITHM / HMAC_ENCODING /
// HMAC_PREFIX in the environment (see config.mjs) and retry.
import crypto from "node:crypto";

function secretKey(secret, encoding) {
  if (encoding === "hex") {
    const cleaned = secret.replace(/^0x/, "");
    if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
      return Buffer.from(cleaned, "hex");
    }
    // Not valid hex — fall back to treating the string as UTF-8.
    return Buffer.from(secret, "utf8");
  }
  return Buffer.from(secret, "utf8");
}

// Sign raw body bytes. Returns the header value to send.
export function signBody(secret, rawBody, opts = {}) {
  const algorithm = opts.algorithm || "sha256";
  const encoding = opts.encoding || "hex";
  const prefix = opts.prefix || "";
  const secretEncoding = opts.secretEncoding || "utf8";
  const h = crypto.createHmac(algorithm, secretKey(secret, secretEncoding));
  h.update(rawBody);
  return prefix + h.digest(encoding);
}

// Verify a received header value against the raw body.
// Uses a timing-safe comparison. Returns false on any mismatch
// (including a length mismatch — never throws on attacker input).
export function verifySignature(secret, rawBody, headerValue, opts = {}) {
  if (!secret || !headerValue) return false;
  const expected = signBody(secret, rawBody, opts);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(headerValue), "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// The header name used on every inbound request and outbound response.
export const SIGNATURE_HEADER = "x-agent-games-signature";
