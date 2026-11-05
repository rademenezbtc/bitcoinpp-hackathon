# Marmot Vault — signing coordinator

Remote FROST signing for a Sparrow watch-only taproot wallet, including sends to
silent-payment addresses (BIP 352/375), coordinated over an end-to-end
encrypted Marmot group. No coordination server: relays only see MLS ciphertext.

## Run

```bash
bun install
bun run demo        # coordinator + 3 devices (2-of-3) over an in-memory relay
```

Expected output: the group forms, the ceremony runs
`spend.proposal → round1 → signing.package → round2 → session.complete`,
and the relay log shows only kinds 30443 (key packages), 1059 (welcomes)
and 445 (group ciphertext) — no ceremony JSON.

## Layout

| File | What |
|---|---|
| `src/schema.ts` | Ceremony message types (shared contract with the device team) |
| `src/node.ts` | Marmot participant: key packages, invite/join, send/receive ceremony msgs |
| `src/mem-relay.ts` | In-memory relay implementing marmot-ts `NostrNetworkInterface` |
| `src/demo.ts` | End-to-end choreography with placeholder crypto |

## Ceremony

1. **spend.proposal** — coordinator posts Sparrow's PSBT (PSBTv2, SP outputs have
   `PSBT_OUT_SP_V0_INFO`, no script yet).
2. **round1** — each device: FROST nonce commitments per input, plus per scan key
   `x_i·B_scan` and DLEQ commitments `k_i·G`, `k_i·B_scan`.
3. **signing.package** — coordinator fixes the signer set (first *t* responders),
   computes `C = Σλ_i·x_i·B_scan + T·B_scan`, derives SP output scripts,
   sighashes and the DLEQ challenge `e`.
4. **round2** — each device recomputes outputs/sighash itself, then returns
   FROST signature shares and `s_i = k_i + e·λ_i·x_i`.
5. **session.complete** — coordinator aggregates, writes
   `PSBT_GLOBAL_SP_ECDH_SHARE`, `PSBT_GLOBAL_SP_DLEQ`, `PSBT_OUT_SCRIPT`,
   `PSBT_IN_TAP_KEY_SIG`; Sparrow loads it and broadcasts.

## Next

- [ ] `src/psbt.ts` — read/write Sparrow PSBTv2 incl. BIP 375 fields
- [ ] `src/sp.ts` — input_hash, output derivation (test against BIP 352 vectors)
- [ ] `src/dleq.ts` — BIP 374 verify + threshold proof assembly
- [ ] `src/frost.ts` — must match the devices' FROST implementation
- [ ] Real relays (swap `MemRelay` for a relay pool) + Nigiri regtest
- [ ] Sparrow I/O: watch a folder for exported PSBTs, write signed PSBT back
- [ ] Guards: ignore late round1, timeouts/restart with new signer set, one session at a time
