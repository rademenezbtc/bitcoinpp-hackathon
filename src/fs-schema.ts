// Marmot messages for the Frostsnap SP bridge flow (protocol frostsnap-sp-bridge/1).
//
//   coordinator: bridge.prepare → fs.proposal
//   each signer: bridge.ecdh (hardware approval) → bridge.offer → fs.offer
//   coordinator: freeze subset → fs.sign_request (the SAME offers to everyone)   ← milestone-1 gate
//   each signer: bridge.sign (verifies proofs, derives scripts, hardware approval) → bridge.shares → fs.shares
//   coordinator: bridge.combine → fs.complete (signed tx hex + txid)
//
// task / binonces / ecdh / shares are OPAQUE bincode-hex payloads from the
// bridge, pinned to its core revision. Never reinterpret them here.
// MLS authenticates the sender; marmot-ts rejects a rumor whose pubkey differs
// from the MLS sender, and the app binds that pubkey to a configured share index.

export const FS_KIND = 9751;
export const BRIDGE_PROTOCOL = "frostsnap-sp-bridge/1";

export interface BridgeOffer { binonces: string; ecdh: string }

export interface Pin {
  protocol: typeof BRIDGE_PROTOCOL;
  /** Bridge core revision announced at startup, if known (all parties must match). */
  coreRevision?: string;
  keyId: string;
  accessStructureId: string;
}

export type FsMsg =
  | {
      t: "fs.proposal";
      sessionId: string; // 32-byte hex, fresh per attempt
      pin: Pin;
      task: string; // opaque, from bridge.prepare
      feeSat?: number;
      /** Human-readable copy of what was passed to prepare — for logs/UI only; devices show the truth. */
      summary: { recipients: { address: string; amount_sat: number }[]; change?: { index: number; amount_sat: number }; inputs: { txid: string; vout: number }[] };
    }
  | { t: "fs.offer"; sessionId: string; shareIndex: number; offer: BridgeOffer }
  | { t: "fs.sign_request"; sessionId: string; subset: number[]; offers: { shareIndex: number; offer: BridgeOffer }[] }
  /** sha256 of the bridge's `completed_task` (SP scripts filled in) after `sign` — all signers must match before shares are released. */
  | { t: "fs.derived"; sessionId: string; shareIndex: number; completedTaskHash: string }
  | { t: "fs.shares"; sessionId: string; shareIndex: number; shares: unknown }
  | { t: "fs.complete"; sessionId: string; txid: string; txHex: string }
  | { t: "fs.cancel"; sessionId: string; reason: string; by?: number }
  | { t: "fs.status"; sessionId?: string; shareIndex: number; note: string };

export const encodeFs = (m: FsMsg) => JSON.stringify(m);
export function decodeFs(s: string): FsMsg | null {
  try {
    const m = JSON.parse(s);
    return typeof m?.t === "string" && m.t.startsWith("fs.") ? m : null;
  } catch {
    return null;
  }
}

export const isSessionId = (s: unknown): s is string => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
export const newSessionId = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
