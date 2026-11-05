// Ceremony messages exchanged inside the Marmot group.
// Each one is an unsigned Nostr rumor of CEREMONY_KIND whose content is the
// JSON below. MLS authenticates the sender, so payloads carry no signatures.
//
// Hex everywhere: points are 33-byte compressed (66 hex chars),
// scalars 32 bytes (64 hex chars). PSBTs are base64 (PSBTv2 from Sparrow).

/** Hackathon-local rumor kind for vault ceremony messages (never published raw). */
export const CEREMONY_KIND = 9750;

export type Hex = string;

export interface Participant {
  /** FROST identifier (1..n) */
  id: number;
  /** Nostr pubkey of the device's Marmot identity */
  nostrPubkey: Hex;
  /** FROST verifying share Y_i = x_i·G */
  verifyingShare: Hex;
}

export type CeremonyMsg =
  | {
      type: "vault.setup";
      vaultId: string;
      threshold: number;
      groupKey: Hex; // FROST group public key (untweaked)
      participants: Participant[];
    }
  | {
      type: "spend.proposal";
      sessionId: string;
      psbt: string; // base64, as exported by Sparrow
      memo?: string;
    }
  | {
      // Round 1, device → group
      type: "round1";
      sessionId: string;
      signerId: number;
      /** FROST nonce commitments, one pair per input */
      commitments: { hiding: Hex; binding: Hex }[];
      /** Per silent-payment scan key: x_i·B_scan plus DLEQ commitments */
      sp: { scanKey: Hex; share: Hex; R1: Hex; R2: Hex }[];
    }
  | {
      // Coordinator → group, after picking the signer set
      type: "signing.package";
      sessionId: string;
      signers: number[];
      /** PSBT with PSBT_OUT_SCRIPT filled for SP outputs */
      psbt: string;
      sighashes: Hex[];
      /** DLEQ challenge per scan key */
      dleq: { scanKey: Hex; e: Hex }[];
    }
  | {
      // Round 2, device → group
      type: "round2";
      sessionId: string;
      signerId: number;
      sigShares: Hex[]; // one per input
      dleq: { scanKey: Hex; s: Hex }[];
    }
  | { type: "session.complete"; sessionId: string; txid: string; psbt: string }
  | { type: "session.abort"; sessionId: string; reason: string; culprit?: number };

export type MsgType = CeremonyMsg["type"];

export function encode(msg: CeremonyMsg): string {
  return JSON.stringify(msg);
}

export function decode(content: string): CeremonyMsg | null {
  try {
    const m = JSON.parse(content);
    return typeof m?.type === "string" ? (m as CeremonyMsg) : null;
  } catch {
    return null;
  }
}
