# Marmot Vault — signing coordinator

Remote FROST signing for a Sparrow watch-only taproot wallet (physical
Frostsnap 2-of-2 on Signet), including sends to silent-payment addresses
(BIP 352), coordinated over an end-to-end encrypted Marmot group. No
coordination server: relays only see MLS ciphertext.

The silent-payment flow follows [Frostsnap PR #640](https://github.com/frostsnap/frostsnap/pull/640).

The physical-device implementation is in [the local Frostsnap bridge handoff](frostsnap/README.md).
It includes the Rust bridge, firmware updater, process adapter and hardware test
results. Wiring its opaque payloads into Marmot is still required; `demo` continues
to use software stand-ins.

## Run

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
| `src/schema.ts` | Ceremony message types — the contract with the Frostsnap bridge |
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
