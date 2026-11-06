# Two-Mac Signet hardware test

On 2026-11-06 (Asia/Seoul), two physical Frostsnap devices completed a
2-of-2 silent-payment send using the local bridges and Marmot coordinator.
The wallet was created with both devices together, then restored into separate
local apps. Each Mac used its own bridge state and one device.

- Core: Frostsnap PR #640, `538b0ec0832de92de98b1f58c556a0ea559ab9f4`.
- Firmware body digest: `512ec13bf0c839d6d5c97f425d8db7f3caa2eb1f479cafac93dcdb01a484e2ef`.
- Both hardware ECDH approvals arrived over Marmot.
- Both signers reported completed-task hash
  `efde2dae5c4f31bf9e453ca17fdcefa186c73ca64a5a2921e07a92481ac7ea33`.
- Payment: 1,000 sats to one silent-payment receiver; 8,700 sats ordinary
  wallet change; 300 sats fee; 10,000 sats input.
- [Transaction](https://blockstream.info/signet/tx/dec10c6da4742ec13f2419c3f1abcb0ee2d2a6c3a378128929ade0549544898d)
  confirmed in Signet block **329605**.
- BlindBit Desktop v0.1.0-alpha.1, using `signet.oracle.setor.dev` with TLS,
  scanned through block 329605 and displayed output 0 as **1,000 sats, unspent**.
  Its balance header still displayed zero despite the UTXO row.

## Integration findings

The Rust bridge rejects unknown input fields. The coordinator must retain `txid`
for its display/fetch logic but pass only `transaction`, `vout`, `internal` and
`index` to `prepare`. The initial attempt failed on the extra `txid`; removing it
allowed this run. The coordinator now strips that metadata at the bridge boundary.

BlindBit resumed an old whole-chain scan even after a recent-height rescan request.
For this new test receiver, the app was closed, its wallet file backed up locally,
and its saved scan cursor set to 329599 before reopening the same Signet data
directory. It then scanned the payment's block. No recovery words, private keys,
wallet files or initialized bridge state are included here.

This establishes one end-to-end 2-of-2 send to one receiver. It does not establish
physical 2-of-3, multiple-recipient hardware coverage, Sparrow integration,
mainnet readiness, or resolution of the earlier serial-decoding crash.
