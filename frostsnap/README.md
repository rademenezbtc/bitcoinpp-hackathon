# Local Frostsnap bridge handoff

This directory contains the actual Rust USB bridge, development firmware updater,
Node 24/Bun adapter, tests, and firmware/hardware provenance. It is pinned to
[PR #640](https://github.com/frostsnap/frostsnap/pull/640) revision
`538b0ec0832de92de98b1f58c556a0ea559ab9f4`.

## Build on each Mac

Install Rust 1.95.0, Git and Xcode command-line tools, then run:

```sh
sh frostsnap/build.sh
```

The script checks out the pinned source, adds the bridge as a workspace member,
exposes the upstream firmware verifier, and builds/tests the bridge. It refuses
to overwrite an existing build checkout. Rebuild subsequent edits by copying
`frostsnap/sp_bridge` into `.frostsnap-build/tools/sp_bridge` and running Cargo there.
Build on the target Mac architecture; the previously shared ZIP is Apple Silicon.

See [local setup and command reference](sp_bridge/README.md) for importing the
restored wallet, firmware installation and the JSONL API. The firmware is not
embedded in this repository. The reviewed deterministic CI artifact and both
unsigned/signed checksums are in [provenance](sp_bridge/firmware-provenance.json).
The previously shared ZIP includes the development-signed image. Do not use an
arbitrary current PR build with the pinned bridge.

Each Mac must import its OWN restored app database. Never exchange app databases
or initialized bridge-state directories. Private signing shares stay on devices.

## Connection to Marmot: remaining integration

```text
device A --USB-- bridge A --JSONL-- app A
                                   |
                         encrypted Marmot group
                                   |
device B --USB-- bridge B --JSONL-- app B
```

`src/frostsnap-bridge.ts` exports the local process adapter. Start one instance
on each Mac, using absolute paths:

```ts
import { FrostsnapBridge } from "./src/frostsnap-bridge.ts";

const bridge = new FrostsnapBridge("/absolute/path/frostsnap_sp_bridge", [
  "--state", "/absolute/private/signer-state",
  "--desktop-dev-key",
  "--expected-firmware",
  "512ec13bf0c839d6d5c97f425d8db7f3caa2eb1f479cafac93dcdb01a484e2ef",
]);
bridge.on("notification", event => console.log(event));
const wallets = await bridge.request({ method: "wallets" });
```

This commit does **not** connect the existing demo to hardware or implement real
relays/invitation persistence. The current `schema.ts` v2 uses decoded ECDH shares
and PSBT tasks; it is not directly interchangeable with the bridge API. Do not
cast the opaque payloads into those fields or call the demo placeholder signing
functions with physical devices.

The coordinator integration must carry these exact bridge payloads:

| Stage | Bridge operation | Marmot payload |
| --- | --- | --- |
| Propose | `prepare` with real previous transactions, paths, recipients and change | returned opaque `task`, wallet/access IDs, fresh 32-byte lowercase-hex session ID |
| ECDH | each signer calls `ecdh`, then `offer` after `ecdh_ready` | `{binonces, ecdh}` from each signer, both opaque bincode-hex |
| Sign | each signer calls `sign` with identical selected offers | exact selected offer array, bound to the same session/proposal |
| Shares | each signer calls `shares` after `signature_ready` | opaque `shares` string |
| Complete | a bridge calls `combine` with offers and shares | signed transaction hex and txid; no automatic broadcast |

Use protocol `frostsnap-sp-bridge/1` and pin the Rust revision above on both Macs.
The Rust core verifies proofs, derives SP outputs and combines signatures; no
TypeScript curve conversion is needed for this path. A PSBT-to-bridge adapter is
still needed for Sparrow inputs. The payload is not an aggregate BIP375 DLEQ proof.

Bind authenticated Marmot identities to the configured wallet/share indices.
Freeze the proposal and selected subset, reject duplicates/conflicting retries,
and handle cancellation/timeouts. Treat incoming proposals as requests for local
approval, not permission to broadcast. Keep the bridge process and its stdin open
throughout the ceremony.

## Validation and known issue

- Rust bridge tests pass for one receiver and a batch with the same scan key,
  proof tampering/duplicate signers, import/replay isolation, and stdio errors.
- Node adapter test passes with a real bridge process. From repository root:
  `FROSTSNAP_BRIDGE_BIN=/absolute/path/frostsnap_sp_bridge node --test frostsnap/sp_bridge/client.test.ts`.
- Signer A booted the pinned SP firmware and returned a verified hardware ECDH proof.
- First hardware run showed a serial-decoding panic at `esp32_run.rs:440`
  (`ReceiveSerial` variant 33, allowed 0..12). A staged repeat stayed normal through
  ECDH, cancellation and USB close. The intermittent crash is **not fixed**.
- Signer B has not yet been physically validated by this bridge. No transaction
  has been signed or broadcast with the two physical devices. Signet development only.
