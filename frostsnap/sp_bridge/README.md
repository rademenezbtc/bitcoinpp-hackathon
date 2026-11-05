# Frostsnap SP device bridge (development, Signet only)

Local Rust process for each signer, built on Frostsnap PR #640 at
`538b0ec0832de92de98b1f58c556a0ea559ab9f4`. It wraps upstream USB, threshold ECDH,
proof verification, nonce reservations and FROST signing. Private signing shares
remain on the devices. No Marmot network listener, automatic approval or broadcast.

## Build and initialize

```sh
cargo build -p frostsnap_sp_bridge
cargo test -p frostsnap_sp_bridge
```

Close the Frostsnap app before starting a hardware bridge. Each Mac uses its OWN
app database, after pairing that Mac with the wallet. Initialize once:

```sh
target/debug/frostsnap_sp_bridge \
  --state /absolute/private/bridge-state \
  --import-app-db "$HOME/Library/Application Support/com.frostsnap/frostsnap.sqlite" \
  --desktop-dev-key --offline
```

Send `wallets` below, then close stdin. The import opens the source read-only,
imports Signet key metadata and encrypted root-public-key material, and excludes
all nonce/reservation state. It does NOT copy hardware private shares. New nonce
streams are requested from hardware. Do not clone an initialized bridge-state
directory to another Mac or run two copies of it. Use one state directory per
local signer and the same directory on every restart. A process lock prevents
concurrent use of a directory; journal updates are committed before USB sends or
responses. The directory must have permissions 0700.

The upstream desktop app currently uses a temporary all-zero wrapping key
(`DesktopSecureKeyProvider`). `--desktop-dev-key` explicitly selects that existing
development behavior. This is not a production keystore implementation. Local
bridge state includes wallet-unlocking material and must never be sent to Marmot.

Run hardware mode with the exact reviewed SP firmware body digest:

```sh
target/debug/frostsnap_sp_bridge --state /absolute/private/bridge-state \
  --desktop-dev-key --expected-firmware BODY_SHA256
```

Only devices reporting that digest receive nonce/signing requests. Keep stdin
open throughout the session. `--offline` supports wallet inspection and transaction
preparation, without opening USB. The firmware digest is an integration check,
not remote attestation.

## Local API and coordinator contract

One JSON object per line, maximum 2 MiB. Request IDs correlate responses; asynchronous
device notifications have `event`. `client.ts` provides a Node/Bun process adapter.

```json
{"protocol":"frostsnap-sp-bridge/1","id":"list","command":{"method":"wallets"}}
```

Successful response: `{"id":"list","result":...}`. Failure:
`{"id":"list","error":"..."}`. Startup announces protocol and core revision.

| Command | Arguments / result |
| --- | --- |
| `wallets` | Signet wallet IDs, access structure IDs, thresholds, hardware IDs, share indices, account verification shares |
| `prepare` | `key_id`, `inputs`, `recipients`, optional `change`; returns `task` and `fee_sat` |
| `ecdh` | `session_id`, `key_id`, `access_structure_id`, `device_id`, `task`; requests physical ECDH approval |
| `offer` | `session_id`; after `ecdh_ready`, returns `{binonces,ecdh}` with full DLEQ proofs |
| `sign` | `session_id`, `offers`; validates threshold proofs, derives scripts, requests physical transaction approval |
| `shares` | `session_id`; after `signature_ready`, returns `{shares}` |
| `combine` | `session_id`, `offers`, `shares` (array of payload strings); verifies shares, returns signed transaction hex and txid |
| `cancel` | `session_id`; terminal for that ID. A new proposal requires a fresh ID |

`session_id` is a randomly generated **32-byte hex value**, identical across both
signers. Use a fresh one for each attempt. Only one incomplete session per local
bridge. Retrying an identical `ecdh` returns its status; it does not re-prompt the
device. If a request was lost before device approval, cancel and start a new session.
Reserved offers and completed shares can be queried again after process restart.
The upstream nonce state binds signing to the selected task and subset.

`prepare` accepts real previous transactions (not invented UTXOs):

```json
{
  "method":"prepare",
  "key_id":"FROM_WALLETS",
  "inputs":[{"transaction":"FULL_PREVIOUS_TX_HEX","vout":0,"internal":false,"index":0}],
  "recipients":[{"address":"tsp1...","amount_sat":1000}],
  "change":{"index":0,"amount_sat":8900}
}
```

The bridge checks the input script against the local wallet derivation and checks
amount arithmetic, duplicate inputs and address network. It does not query chain
state: the transaction builder must check confirmation/spendability. Fees and
recipients must still be reviewed on device. Only default-account P2TR key-path
inputs, SP recipients and ordinary wallet change are supported initially.

The Marmot coordinator transports `task`, `binonces`, `ecdh`, `shares` as **opaque
bincode-hex payloads**, pinned to this core revision. They are not PSBT or raw scalar
hex. Do not reinterpret them as the coordinator skeleton's `R1/R2/e/s` proof protocol.
No TypeScript curve arithmetic is necessary: a local bridge can run `prepare` and
`combine` for the coordinator. Each other signer independently derives and verifies
the completed transaction. PSBTv2/BIP375 translation is a separate adapter; do not
write the per-share proof bundle directly into a BIP375 global DLEQ field.

Suggested Marmot flow:

1. Builder calls `prepare`; sends the task and public wallet identifiers as proposal.
2. Each local signer accepts the proposal and calls `ecdh` for its own device.
3. After approval, calls `offer` and sends that result to the Marmot coordinator.
4. Coordinator selects the threshold subset and distributes the SAME offers to both.
5. Each local signer calls `sign`, reviews hardware, then publishes `shares`.
6. One bridge calls `combine`; coordinator receives signed transaction hex.

The Marmot application MUST bind authenticated senders to configured share indices,
pin the wallet/access structure and protocol revision, freeze the proposal/subset,
deduplicate messages, and handle cancellation/timeouts. Invite acceptance does not
grant Bitcoin signing authority. The bridge API itself is a trusted local IPC surface.

## Firmware

Use `sp_firmware IMAGE EXPECTED_BODY_SHA256 DEVICE_ID [DEVICE_ID...]` with the matching
development-signed image. It verifies the Secure Boot signature against the upstream
development key, checks the body digest, rejects unselected devices, uses the upstream
on-device confirmation protocol, and checks the reported digest after reboot. It does
not erase wallet data or rewrite bootloaders/eFuses. Close all other USB wallet clients.

Firmware provenance for this build is recorded in `firmware-provenance.json`.
The deterministic CI source merge has identical core, comms, device, Cargo manifest
and lockfile contents to the pinned PR head. The upstream normal CI failed; this
image comes from the separate successful deterministic build, not an invented local
build result. Physical wallet-state compatibility and ECDH must be tested before use.

## Scope / known limits

- Test funds only. PR #640 and its remote-signing base are experimental; this is not
  a cryptographic review. The base contains a documented deterministic-signing
  randomization workaround; the bridge does not claim to fix it.
- No chain service, coin selection, Marmot implementation, PSBT adapter or broadcast.
- App imports support the pinned desktop schema and fail on unknown key records.
- Receiving/scanning is outside this sender bridge. Batches retain recipient order
  and upstream scan-key grouping/counters.
- Local tests exercise the real Rust device/core state machines in simulation.
  Hardware signing and firmware installation remain separate acceptance checks.
