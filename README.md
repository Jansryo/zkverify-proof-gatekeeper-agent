# zkVerify Agent Games — Proof Gatekeeper Agent

Public HTTPS endpoint that plays the **Proof Gatekeeper** event: it receives
signed task envelopes, decides APPROVE/REJECT with deterministic checks,
generates a local Groth16 proof with snarkjs, anchors it via Kurier, and
returns a signed response — all inside the platform's 60s deadline.

Participant: `@JansemRyu` (handle `jansemryu`). Track prize pool: 100,000 VFY
(50k / 30k / 20k, top 3). The full protocol spec is in
`../SPEC.md` (the authoritative contract — read it before changing anything).

## How it works

```
platform --POST /agent-->  HMAC verify (raw body, fail closed)
                        -> preflight?  {ok:true, protocolVersion:"v1"}
                        -> task?       idempotency (task_id)
                                       -> 7 deterministic checks (in order)
                                       -> Groth16 proof (snarkjs, bounded)
                                       -> signed response
                                       -> Kurier submit + poll (async, after responding)
```

Decision rules (SPEC.md §6): APPROVE only when **every** check passes
(VK match, balance ≥ minimum, proof_tx not reused, not expired, recipient
matches, amount ≤ max, proof confirmed on-chain). Otherwise REJECT with the
reason_code of the first failing check. Any doubt → REJECT. The circuit
itself enforces correctness — a valid proof can only be produced for the
correct decision.

## Quick start

```bash
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (+ KURIER_API_KEY)
npm start              # listens on http://0.0.0.0:8080
```

Test locally (spins up the server on a test port, replays sample tasks,
verifies the proofs with snarkjs — needs a dummy secret only):

```bash
npm test
```

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes (live) | — | 32-byte secret from the dashboard, shown once at registration |
| `HMAC_SECRET_ENCODING` | no | `utf8` | `utf8` or `hex` |
| `HMAC_ALGORITHM` | no | `sha256` | Unconfirmed — confirm via preflight |
| `HMAC_ENCODING` | no | `hex` | `hex` or `base64` |
| `HMAC_PREFIX` | no | `` | e.g. `sha256=` |
| `KURIER_API_KEY` | no | — | Free key from kurier.xyz; without it proofs are not anchored via Kurier |
| `PORT` / `HOST` | no | `8080` / `0.0.0.0` | Fly.io sets `PORT` |
| `PROVE_TIMEOUT_MS` | no | `40000` | Proving budget per task (platform deadline is 60s) |
| `ZKVERIFY_EXPLORER_API` | no | — | Mainnet explorer API base for check 7; blank = lookup skipped |
| `ONCHAIN_INCONCLUSIVE` | no | `pass` | `pass` or `reject` — see `src/onchain.mjs` |
| `STATE_FILE` / `LOG_FILE` | no | `./data/state.json` / `./data/agent.log` | Persistent seen-set + idempotency + log |

## Endpoints

- `POST /agent` — task + preflight endpoint (also accepts `POST /`).
- `GET /health` — `{ok, uptimeSec, state, hmacConfigured, kurierConfigured}`
  (also `GET /`). Use this for the platform health check.

Every response carries `x-agent-games-signature` (HMAC over the raw response
body) when a secret is configured. Unsigned/invalid inbound requests are
rejected with 401.

## Deploy (Fly.io)

```bash
fly launch --no-deploy          # first time: pick the app name + region (sin)
fly volumes create gatekeeper_data --size 1 --region sin   # persistent state
fly secrets set AGENT_GAMES_HMAC_SECRET=... KURIER_API_KEY=...
fly deploy
fly logs                        # watch decisions + Kurier jobs
```

`fly.toml` is preconfigured: always-on (`auto_stop_machines = false`,
`min_machines_running = 1` — free-tier sleep loses tasks), HTTPS on 443,
`/health` check, volume mounted at `/app/data` so the proof_tx seen-set and
the task_id idempotency store survive restarts.

**Benchmark proving on the host before the first scored round.** The whole
decide → prove → respond pipeline must fit in 60s. On the throttled dev VM
`fullProve` took ~180s for this small circuit; on a normal host it should be
seconds — but measure it (`npm test` reports the prove+respond time per
task). If proving is slow on the host, pick a faster host; do not try to
"optimise" the circuit.

## Going live checklist

1. Deploy + set the secrets (`AGENT_GAMES_HMAC_SECRET`, `KURIER_API_KEY`).
2. Register the agent in the dashboard (name, track Proof Gatekeeper, this
   repo's public URL, the public endpoint URL). Capture the HMAC secret
   **once** and put it in the env immediately.
3. Complete the signed preflight — this confirms the HMAC hash/encoding.
   If the platform rejects the signed preflight, adjust `HMAC_ALGORITHM` /
   `HMAC_ENCODING` / `HMAC_PREFIX` and retry.
4. Run practice tasks (≤10/hour) until the proofs the platform accepts
   match — this is the only way to confirm the two unconfirmed encodings
   (`encodeTaskId`, `encodeVkHash` in `src/encoding.mjs`) and the response
   shape. If the platform rejects a proof, the encoding is the first suspect.
5. Confirm the health-check path the platform uses.
6. Be live before the round opens (entries lock while a round is open).

## Known gaps (confirm in Practice Mode — SPEC.md §9)

1. `task_id` string → field element (hypothesis: numeric part).
2. 256-bit vk-hash → field element (hypothesis: `BigInt(hash) mod FIELD_PRIME`).
3. Exact response field union.
4. HMAC hash function + header-value encoding.
5. Health-check path/method.
6. Check-7 on-chain lookup method (mainnet explorer URL unconfirmed).
7. Kurier default rate limit.
8. Reason code for a proof that cannot be confirmed on-chain (we use
   `PROOF_NOT_CONFIRMED`).

## Files

```
server.mjs            entry: HTTP server, HMAC gate, routing, fail-closed errors
src/config.mjs        env vars + constants (FIELD_PRIME, gatekeeper vkHash)
src/hmac.mjs          sign/verify (HMAC-SHA256 default, configurable)
src/encoding.mjs      encodeTaskId / encodeVkHash / encodeAddress (isolated!)
src/decision.mjs      the 7 deterministic checks + reason codes
src/prover.mjs        snarkjs fullProve (bounded) + local verify
src/kurier.mjs        submit-proof + poll to Finalized (async, after responding)
src/onchain.mjs       check-7 explorer lookup (pluggable, configurable)
src/store.mjs         persistent seen-set + idempotency (atomic JSON)
src/logger.mjs        append-only JSONL log (+ console)
circuits/             gatekeeper.wasm / gatekeeper_final.zkey / gatekeeper.vkey.json
test/harness.mjs      local end-to-end test (npm test)
Dockerfile  fly.toml  .env.example  .gitignore
```

## Security

- Secrets come from env only (`.env` is gitignored; `.env.example` ships blank).
- Never log a secret. The logger only receives redacted fields.
- Fail closed: HMAC mismatch → 401; any decision doubt → REJECT; any
  handler error → REJECT (never a bare 500/timeout, which loses the decision).
- Deterministic decisions only — no model makes the final call.
