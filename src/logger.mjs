// Append-only JSONL log (one JSON object per line) + console mirror.
// Every task decision, proof outcome, and Kurier result is logged.
// NEVER log a secret: this module only ever receives already-redacted
// fields. Callers must never pass AGENT_GAMES_HMAC_SECRET or KURIER_API_KEY.
import fs from "node:fs";
import path from "node:path";

export function makeLogger(logFile) {
  let warned = false;
  function ensureDir() {
    try {
      fs.mkdirSync(path.dirname(logFile), { recursive: true });
    } catch { /* best effort */ }
  }
  function write(entry) {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    try {
      ensureDir();
      fs.appendFileSync(logFile, line, "utf8");
    } catch (err) {
      if (!warned) {
        warned = true;
        console.error(`[logger] WARNING: cannot write to ${logFile}: ${err.message}`);
      }
    }
    // Console mirror (without the ts duplication — console adds its own).
    console.log(`[${entry.event || "log"}]`, JSON.stringify(entry));
  }
  return { log: write };
}
