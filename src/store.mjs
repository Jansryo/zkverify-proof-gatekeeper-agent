// Persistent state: the proof_tx seen-set (replay protection, check 3)
// and the task_id -> response map (idempotency, spec §8).
//
// A single JSON file, written atomically (temp file + rename) after every
// mutation so a crash mid-write never corrupts the store. The file must
// survive restarts — on Fly.io this means a mounted volume (see fly.toml);
// without a volume the state resets on each deploy, which is safe but loses
// replay protection across deploys (the platform's retry window is short,
// so the practical risk is low — still, mount a volume).
//
// Shape:
//   { version: 1,
//     seenProofTx: { [proofTx]: { taskId, decidedAt } },
//     responses:   { [taskId]:   { response, decidedAt } } }
import fs from "node:fs";
import path from "node:path";

export class StateStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.state = { version: 1, seenProofTx: {}, responses: {} };
    this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") {
          this.state.seenProofTx = parsed.seenProofTx || {};
          this.state.responses = parsed.responses || {};
        }
      }
    } catch (err) {
      // Corrupt state file: start fresh rather than crash. Log loudly.
      console.error(`[store] WARNING: could not load state from ${this.filePath} (${err.message}); starting with empty state.`);
      this.state = { version: 1, seenProofTx: {}, responses: {} };
    }
  }

  _save() {
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });
      const tmp = this.filePath + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify(this.state), "utf8");
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error(`[store] ERROR: could not persist state to ${this.filePath}: ${err.message}`);
    }
  }

  hasSeenProofTx(proofTx) {
    return Object.prototype.hasOwnProperty.call(this.state.seenProofTx, proofTx);
  }

  // Record a proof_tx as used. Called once a task has been decided and its
  // response is about to be returned (never for PROOF_REUSED tasks — the tx
  // is already in the set — and never before the decision is final).
  markProofTxSeen(proofTx, taskId) {
    this.state.seenProofTx[proofTx] = { taskId, decidedAt: new Date().toISOString() };
    this._save();
  }

  getStoredResponse(taskId) {
    const entry = this.state.responses[taskId];
    return entry ? entry.response : null;
  }

  storeResponse(taskId, response) {
    this.state.responses[taskId] = { response, decidedAt: new Date().toISOString() };
    this._save();
  }

  stats() {
    return {
      seenProofTx: Object.keys(this.state.seenProofTx).length,
      storedResponses: Object.keys(this.state.responses).length,
    };
  }
}
