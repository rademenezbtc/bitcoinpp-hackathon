# Marmot Vault — signing coordinator

Remote FROST signing for a Sparrow watch-only taproot wallet (physical
Frostsnap 2-of-2 on Signet), including sends to silent-payment addresses
(BIP 352), coordinated over an end-to-end encrypted Marmot group. No
coordination server: relays only see MLS ciphertext.

The silent-payment flow follows [Frostsnap PR #640](https://github.com/frostsnap/frostsnap/pull/640).

The physical-device implementation is in [the local Frostsnap bridge handoff](frostsnap/README.md).
It includes the Rust bridge, firmware updater, process adapter and hardware test
results. `bun run vault` (below) wires its opaque payloads into Marmot; `demo`
continues to use software stand-ins.

## Hardware run: Frostsnap SP bridge over Marmot

Each Mac runs **one** `marmot-vault` process. It launches that Mac's own
`frostsnap_sp_bridge` (own state dir, pinned SP firmware digest) and carries
the bridge's opaque payloads through the encrypted Marmot group. Wallet
databases and bridge state never leave the Mac. Protocol: `frostsnap-sp-bridge/1`.

```
A (coordinator + share 1)            B (share 2)
prepare ──► fs.proposal ───────────► ecdh (device approval) ─► offer
ecdh ─► offer ─► fs.offer ◄───────── fs.offer
   ── 2/2 offers: MILESTONE-1 GATE (type `sign`) ──
fs.sign_request (same offers) ─────► sign (verify proofs, derive SP output, device approval)
sign ─► shares ─► fs.shares ◄─────── shares
combine ─► signed tx (not broadcast) ─► fs.complete
```

### 1. Install (each Mac)

```bash
git clone git@github.com:rademenezbtc/bitcoinpp-hackathon.git && cd bitcoinpp-hackathon
bun install && bun test
```

### 2. Initialise (each Mac; Frostsnap app closed, device plugged in)

```bash
# Signer B
bun run vault init --name B --device <B_DEVICE_ID> \
  --bridge ~/Downloads/Frostsnap-SP-Bridge-mac-arm64/frostsnap_sp_bridge \
  --state ~/frostsnap-sp-bridge-state

# Signer A (coordinator)
bun run vault init --name A --role coordinator --device <A_DEVICE_ID> \
  --bridge <path>/frostsnap_sp_bridge --state ~/frostsnap-sp-bridge-state
```

`init` creates a Marmot identity in `~/.marmot-vault/<name>/`, asks the bridge
(offline) for the Signet wallet, pins key id + access structure, finds this
Mac's share index from `--device`, and prints the **npub** to share.

### 3. Pair (exchange npubs out of band)

```bash
# on A
bun run vault member --name A <B_NPUB> 2
# on B
bun run vault member --name B <A_NPUB> 1
bun run vault coordinator --name B <A_NPUB>
```

### 4. Run (B first, then A)

```bash
bun run vault run --name B      # waits for A's invite (accepts only A)
bun run vault run --name A      # creates the group and invites B
```

### Live dashboard

`vault run` serves a dashboard at **http://127.0.0.1:8787** (`--port N` to change,
`--no-dashboard` to disable; it listens on localhost only). It shows the payment,
the ceremony steps, both devices' progress, the "both devices derived the identical
transaction" check, the signed txid with **Broadcast to Signet** / mempool.space,
and a live **"What the relays see"** feed of every Nostr event this Mac sent or
received, with a counter that flags any plaintext (recipient address, ceremony JSON,
wallet ids) found in it. On the coordinator it also has Propose / Request signatures /
Cancel buttons. No external fonts or scripts, so it works on venue Wi-Fi.

Rehearse it without hardware (`MOCK_APPROVE_MS` simulates the time to press the device):
```bash
bun run relay 7777
MOCK_DEVICE=devB MOCK_SHARE=2 MOCK_APPROVE_MS=6000 bun run vault run --name B --port 8788
MOCK_DEVICE=devA MOCK_APPROVE_MS=2500 bun run vault run --name A
```
(with mock-bridge configs from `vault init --bridge scripts/mock-bridge.sh … --home /tmp/rehearsal`).

### 5. Milestone 1 (on A)

```bash
propose proposal.json           # proposal.json: see below
# both devices: approve ECDH  → A prints "2 hardware-approved ECDH offers collected"
sign                            # only when ready to go further: devices verify + derive output, then approve
```

```json
{
  "inputs": [{ "txid": "<funding txid>", "vout": 0, "internal": false, "index": 0 }],
  "recipients": [{ "address": "tsp1…", "amount_sat": 1000 }],
  "change": { "index": 0, "amount_sat": 8700 }
}
```
The previous transaction is fetched from mempool.space/signet when only `txid` is
given. Inputs must be confirmed, default-account P2TR wallet UTXOs; `index` is the
address index. The signed transaction is printed, **not broadcast**.

REPL: `status`, `invite [npub]`, `propose <file>`, `sign`, `retry`, `cancel`, `quit`.

### Relays

Default: `relay.damus.io`, `nos.lol`, `relay.primal.net` (edit `relays` in
`~/.marmot-vault/<name>/config.json`). If public relays misbehave on venue Wi-Fi,
run one on A and point both configs at it (relay still sees only ciphertext):
```bash
bun run relay 7777              # on A → ws://<A's LAN IP>:7777 in both configs
```

### Rehearse without hardware

`scripts/mock-bridge.sh` mirrors the real bridge's wire shapes (events, statuses,
results from `frostsnap/sp_bridge/src/{main,lib}.rs`); set `MOCK_DEVICE`/`MOCK_SHARE`
and use it as `--bridge` with `bun run relay` to run A and B locally.
`test/app.test.ts` covers the flow, the milestone gate, sender binding, wallet
pinning, a swapped-offer attack, mismatched derivations and a device rejection.
`test/node.test.ts` guards against a marmot-ts 0.9 message-loss race (sends
overlapping ingests), which `VaultNode` avoids by queueing all MLS operations.

### What this app enforces (bridge README requirements)

- Marmot sender (MLS-authenticated; marmot-ts rejects rumor/sender mismatch) is bound to a configured share index.
- Wallet key id, access structure and protocol are pinned; proposals for anything else are refused.
- Invites accepted only from the configured coordinator; joining grants no signing authority.
- Fresh 32-byte session id per attempt, never reused; one open session per bridge; messages de-duplicated.
- Subset frozen at the first sign request; each signer checks every offer in it equals the one that signer actually sent.
- After `sign`, each signer publishes a hash of its bridge's `completed_task`; signature
  shares are released only when every signer derived the identical transaction.
- Proposals are refused if the local bridge's core revision differs from the pinned one,
  or if the device isn't connected with the expected SP firmware.
- Cancellation (`cancel`, device rejection, 20-min timeout) reaches every bridge.

## Reference implementation (TypeScript SP math)

```bash
bun install
bun test            # BIP352 + BIP374 official vectors, 2-of-2 ceremony checks
bun run demo        # coordinator + 2 devices over an in-memory relay
```

The demo uses software stand-ins for the devices. SP math is real; FROST
nonces and signature shares are opaque placeholders (`frost` fields), which
the Frostsnap bridge fills in.

## Ceremony (PR #640 shape)

| # | Message | From | Contents |
|---|---|---|---|
| 1 | `sp.ecdh_request` | coordinator | Sparrow PSBT, inputs, recipients (list), `inputHash`, `scanKeys` (≈ `RequestSpEcdh`) |
| 2 | `sp.offer` | device | per scan key: `x_j·B_scan` + full BIP374 DLEQ proof vs its share image, message = `input_hash`; opaque FROST offer (≈ `SpOffer`) |
| 3 | `sp.sign_request` | coordinator | subset, **proof bundle** (account polynomial, input hash, subset's shares), completed task with SP scripts (≈ `RoundConfirmed.sp` + `RequestSpSign`) |
| 4 | `sign.shares` | device | opaque FROST signature shares |
| 5 | `session.complete` / `session.abort` | either | txid / reason + culprit |

**Device checks** (mirrors #640):
- before an ECDH share: input hash and scan keys match its own derivation; inputs are vault keys.
- before signing: polynomial is its access structure; every proof verifies against the
  rebuilt share image; ≥ threshold distinct share indices per scan key; re-derived SP
  scripts equal the task's, else refuse; refuse SP outputs without proofs, or proofs for a plain send.

**Coordinator math** (`src/sp.ts`, `src/ceremony.ts`):
`x·B = Σ λ_j·share_j` → `C = (Σg_i)·x·B + (Σt_i)·B` over input tweak contexts
`a_i = g_i·x + t_i` → `S = input_hash·C` → `P_k = B_spend + hash(S‖k)·G`.
`k` follows transaction output order (Sparrow's), recipients sharing a scan key
count up together.

## Layout

| File | What |
|---|---|
| `src/cli.ts` | `bun run vault` — init / member / coordinator / run (one process per Mac) |
| `src/vault-app.ts` | Bridge-backed session logic: proposal → offers → gate → sign → shares → combine |
| `src/fs-schema.ts` | Marmot messages carrying opaque `frostsnap-sp-bridge/1` payloads |
| `src/frostsnap-bridge.ts` | Re-export of `frostsnap/sp_bridge/client.ts` (local bridge process adapter) |
| `src/net-pool.ts` | marmot-ts network over real relays (applesauce-relay, NIP-42 auth) |
| `src/file-store.ts` | On-disk MLS group state so restarts resume the group |
| `src/dashboard/` | Live ceremony dashboard (`server.ts` SSE + self-contained `index.html`) |
| `src/tap.ts` | Records every event crossing the wire, for the relay view |
| `scripts/` | `local-relay.ts` (LAN relay), `mock-bridge.ts`/`.sh` (hardware stand-in) |
| `src/schema.ts` | Reference ceremony messages (TypeScript SP math path, not used with hardware) |
| `src/sp.ts` | BIP374 DLEQ, BIP352 input hash / outputs / addresses, share images, Lagrange |
| `src/ceremony.ts` | Coordinator (build requests, verify + combine) and device checks |
| `src/node.ts` | Marmot participant (marmot-ts): key packages, invite/join, send/receive |
| `src/mem-relay.ts` | In-memory relay implementing marmot-ts `NostrNetworkInterface` |
| `src/fixture.ts` | Trusted-dealer 2-of-2 + vault inputs (demo/test only) |
| `test/` | Official BIP352/374 vectors + ceremony tests |

## Open points with the Frostsnap side

- Account polynomial encoding and which key level the share images are (account vs root).
- Per-input tweak contexts `(g, t)`: bridge exports them, or we port Frostsnap's derivation.
- Output order: Sparrow fixes it; the bridge must not reshuffle recipients.
- `outputs_fingerprint` tag/format, if devices want it in the request.
- Returning to Sparrow: no aggregate BIP375 DLEQ in this flow, so we hand back a
  finalized transaction (or broadcast on Signet) rather than a BIP375-complete PSBT.

## Next

- [ ] `src/psbt.ts` — read Sparrow PSBTv2: inputs, derivation paths → tweak contexts, SP outputs
- [ ] Real relays (swap `MemRelay` for a relay pool)
- [ ] Sparrow I/O: import exported PSBT, return finalized tx
- [ ] Guards: timeouts/abort, one session at a time
