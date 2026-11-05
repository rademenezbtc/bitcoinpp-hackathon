// Ceremony messages exchanged inside the Marmot group — aligned with
// Frostsnap PR #640 (BIP352 sending for FROST remote signing).
//
// Each message is an unsigned Nostr rumor of CEREMONY_KIND whose content is
// the JSON below. MLS authenticates the sender, so payloads carry no signatures.
//
// Flow (2-of-2, one SP recipient, Signet to start):
//   coordinator → sp.ecdh_request   (≈ RequestSpEcdh)
//   device      → sp.offer          (≈ SigningMessage::SpOffer: ECDH share + full DLEQ per scan key)
//   coordinator → sp.sign_request   (≈ RoundConfirmed.sp + RequestSpSign: subset, proof bundle, completed task)
//   device      → sign.shares
//   coordinator → session.complete | session.abort
//
// Encoding: points 33-byte compressed hex, scalars 32-byte hex,
// DLEQ proofs 64-byte hex (BIP374 e‖s), PSBTs base64.
// `frost` fields are opaque to the coordinator: the Frostsnap bridge owns the
// nonce/offer and signature-share encodings and passes them through untouched.

/** Hackathon-local rumor kind for vault ceremony messages (never published raw). */
export const CEREMONY_KIND = 9750;
export const SCHEMA_VERSION = 2;

export type Hex = string;
export type Network = "signet" | "bitcoin" | "testnet" | "regtest";

export interface Participant {
  /** FROST share index (1..n) */
  shareIndex: number;
  /** Nostr pubkey of the device's (or its bridge's) Marmot identity */
  nostrPubkey: Hex;
}

/** One transaction input as BIP352 sees it. */
export interface SpInput {
  txid: Hex; // display (big-endian) hex
  vout: number;
  /** BIP352 input public key (taproot: output key lifted to even Y) */
  pubkey: Hex;
}

/** A payment. A list from day one so batch payments drop in later. */
export interface Recipient {
  outputIndex: number; // position in the transaction (fixes the k counter order)
  address: string; // tsp1… / sp1… for silent payments, else a normal address
  amountSat: number;
}

/** Device's ECDH contribution for one scan key. */
export interface EcdhShare {
  shareIndex: number;
  scanKey: Hex; // B_scan
  share: Hex; // x_j · B_scan  (NOT Lagrange-weighted)
  /** BIP374 proof that `share` uses the secret behind the device's share image,
   *  with message = input_hash (32 bytes) so it can't be replayed into another tx. */
  proof: Hex;
}

export interface SpScript {
  outputIndex: number;
  script: Hex; // 5120<xonly>
}

export type CeremonyMsg =
  | {
      type: "vault.setup";
      v: typeof SCHEMA_VERSION;
      vaultId: string;
      network: Network;
      threshold: number;
      /** Public polynomial (coefficient commitments) of the account key; share images derive from it. */
      accountPolynomial: Hex[];
      participants: Participant[];
      /** Sparrow watch-only descriptor, for reference */
      descriptor?: string;
    }
  | {
      type: "sp.ecdh_request";
      v: typeof SCHEMA_VERSION;
      sessionId: string;
      network: Network;
      /** Unsigned PSBT from Sparrow (SP outputs have no script yet). */
      psbt: string;
      inputs: SpInput[];
      recipients: Recipient[];
      /** Coordinator's claims — devices recompute and refuse on mismatch. */
      inputHash: Hex;
      scanKeys: Hex[];
      /** Frostsnap `outputs_fingerprint` (tagged hash over index, value, address), if the bridge wants it. */
      outputsFingerprint?: Hex;
    }
  | {
      type: "sp.offer";
      v: typeof SCHEMA_VERSION;
      sessionId: string;
      shareIndex: number;
      /** Exactly one per scan key in the request. */
      ecdh: EcdhShare[];
      /** Opaque FROST offer (nonce commitments etc.) from the Frostsnap bridge. */
      frost?: string;
    }
  | {
      type: "sp.sign_request";
      v: typeof SCHEMA_VERSION;
      sessionId: string;
      /** Chosen signer subset (share indices). */
      subset: number[];
      /** Everything a device needs to re-verify before signing. */
      bundle: {
        accountPolynomial: Hex[];
        inputHash: Hex;
        shares: EcdhShare[]; // the subset's shares, all scan keys
      };
      /** The task completed from the shares. */
      task: {
        network: Network;
        psbt: string; // PSBT with PSBT_OUT_SCRIPT filled for SP outputs
        inputs: SpInput[];
        recipients: Recipient[];
        spScripts: SpScript[];
      };
      /** Opaque per-signer FROST data from the bridge (e.g. the subset's offers). */
      frost?: Record<number, string>;
    }
  | {
      type: "sign.shares";
      v: typeof SCHEMA_VERSION;
      sessionId: string;
      shareIndex: number;
      /** Opaque FROST signature shares, one per input, from the bridge. */
      frost: string;
    }
  | { type: "session.complete"; v: typeof SCHEMA_VERSION; sessionId: string; txid: Hex; txHex?: Hex; psbt?: string }
  | { type: "session.abort"; v: typeof SCHEMA_VERSION; sessionId: string; reason: string; culprit?: number };

export type MsgType = CeremonyMsg["type"];

export function encode(msg: CeremonyMsg): string {
  return JSON.stringify(msg);
}

export function decode(content: string): CeremonyMsg | null {
  try {
    const m = JSON.parse(content);
    return typeof m?.type === "string" && m.v === SCHEMA_VERSION ? (m as CeremonyMsg) : null;
  } catch {
    return null;
  }
}
