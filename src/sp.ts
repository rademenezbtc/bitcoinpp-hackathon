// Silent-payment sending math for a FROST vault (Frostsnap PR #640 flow).
//
//   device j:     share_j = x_j·B_scan  + BIP374 DLEQ proof vs X_j = x_j·G, msg = input_hash
//   coordinator:  verify each proof, X·B = Σ λ_j·share_j   (x = account secret)
//                 C = Σ_inputs (g_i·x + t_i)·B = (Σg_i)·X·B + (Σg_i... t_i)·B
//                 S = input_hash·C,  t_k = H(S‖k),  P_k = B_spend + t_k·G
//   device:       re-verifies the bundle and re-derives every script before signing.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, concatBytes } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";
import type { EcdhShare } from "./schema.ts";

export const Point = secp256k1.Point;
export type Pt = InstanceType<typeof Point>;
export const N = Point.Fn.ORDER;
export const G = Point.BASE;

// ---------------------------------------------------------------- helpers
export const mod = (a: bigint) => ((a % N) + N) % N;
const be32 = (x: bigint) => hexToBytes(x.toString(16).padStart(64, "0"));
const toInt = (b: Uint8Array) => BigInt("0x" + (bytesToHex(b) || "0"));
export const ptHex = (p: Pt) => bytesToHex(p.toBytes(true));
export const pt = (hex: string) => Point.fromHex(hex);
const cbytes = (p: Pt) => p.toBytes(true);

function invert(a: bigint): bigint {
  // Fermat: a^(n-2) mod n
  let r = 1n, b = mod(a), e = N - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % N; b = (b * b) % N; e >>= 1n; }
  return r;
}

const tagCache = new Map<string, Uint8Array>();
export function taggedHash(tag: string, ...msgs: Uint8Array[]) {
  let t = tagCache.get(tag);
  if (!t) { t = sha256(new TextEncoder().encode(tag)); tagCache.set(tag, t); }
  return sha256(concatBytes(t, t, ...msgs));
}

// ---------------------------------------------------------------- BIP 374 DLEQ
function dleqChallenge(A: Pt, B: Pt, C: Pt, R1: Pt, R2: Pt, m: Uint8Array | undefined, Gp: Pt) {
  const mb = m ?? new Uint8Array();
  return mod(toInt(taggedHash("BIP0374/challenge",
    cbytes(A), cbytes(B), cbytes(C), cbytes(Gp), cbytes(R1), cbytes(R2), mb)));
}

/** BIP374 GenerateProof. Returns 64-byte proof (e‖s). Caller supplies 32 bytes of aux randomness. */
export function dleqProve(a: bigint, B: Pt, r: Uint8Array, m?: Uint8Array, Gp: Pt = G): Uint8Array {
  if (a <= 0n || a >= N) throw new Error("dleq: bad secret");
  const A = Gp.multiply(a), C = B.multiply(a);
  const aux = taggedHash("BIP0374/aux", r);
  const t = be32(a).map((v, i) => v ^ aux[i]);
  const rand = taggedHash("BIP0374/nonce", t, cbytes(A), cbytes(C), m ?? new Uint8Array());
  const k = mod(toInt(rand));
  if (k === 0n) throw new Error("dleq: k = 0");
  const R1 = Gp.multiply(k), R2 = B.multiply(k);
  const e = dleqChallenge(A, B, C, R1, R2, m, Gp);
  const s = mod(k + e * a);
  const proof = concatBytes(be32(e), be32(s));
  if (!dleqVerify(A, B, C, proof, m, Gp)) throw new Error("dleq: self-check failed");
  return proof;
}

/** BIP374 VerifyProof. */
export function dleqVerify(A: Pt, B: Pt, C: Pt, proof: Uint8Array, m?: Uint8Array, Gp: Pt = G): boolean {
  if (proof.length !== 64) return false;
  const e = toInt(proof.slice(0, 32)), s = toInt(proof.slice(32));
  if (s >= N) return false;
  if (e >= N) return false; // challenge is reduced mod n, so it could never match
  try {
    const negE = mod(-e);
    const R1 = Gp.multiplyUnsafe(s).add(A.multiplyUnsafe(negE));
    const R2 = B.multiplyUnsafe(s).add(C.multiplyUnsafe(negE));
    if (R1.equals(Point.ZERO) || R2.equals(Point.ZERO)) return false;
    return dleqChallenge(A, B, C, R1, R2, m, Gp) === e;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- FROST helpers
/** Share image X_j = Σ_k j^k · P_k from the public polynomial (coefficient commitments). */
export function shareImage(polynomial: Pt[], index: number): Pt {
  let acc = Point.ZERO, xp = 1n;
  const x = BigInt(index);
  for (const P of polynomial) { acc = acc.add(P.multiply(xp)); xp = mod(xp * x); }
  return acc;
}

/** Lagrange coefficient at 0 for `index` within signer set `indices`. */
export function lagrange(index: number, indices: number[]): bigint {
  let num = 1n, den = 1n;
  const i = BigInt(index);
  for (const jn of indices) {
    if (jn === index) continue;
    const j = BigInt(jn);
    num = mod(num * j);
    den = mod(den * (j - i));
  }
  return mod(num * invert(den));
}

// ---------------------------------------------------------------- BIP 352
export interface Outpoint { txid: string; vout: number } // txid in display (big-endian) hex

export function serOutpoint(o: Outpoint) {
  const txidLE = hexToBytes(o.txid).reverse();
  const v = new Uint8Array(4);
  new DataView(v.buffer).setUint32(0, o.vout, true);
  return concatBytes(txidLE, v);
}

/** input_hash = hash_BIP0352/Inputs(outpoint_L ‖ A). outpoints: ALL tx inputs. */
export function inputHash(outpoints: Outpoint[], inputPubkeys: Pt[]): bigint {
  const ser = outpoints.map(serOutpoint).sort((a, b) => {
    for (let i = 0; i < 36; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  });
  const A = inputPubkeys.reduce((s, p) => s.add(p), Point.ZERO);
  return mod(toInt(taggedHash("BIP0352/Inputs", ser[0], cbytes(A))));
}

export interface SpAddress { scan: Pt; spend: Pt; network: "main" | "test" }

/** Decode sp1… / tsp1… (v0). */
export function decodeSpAddress(addr: string): SpAddress {
  const { prefix, words } = bech32m.decode(addr as `${string}1${string}`, 1023);
  const network = prefix === "sp" ? "main" : prefix === "tsp" ? "test" : null;
  if (!network) throw new Error(`not a silent payment address: ${prefix}`);
  if (words[0] !== 0) throw new Error(`unsupported SP version ${words[0]}`);
  const data = bech32m.fromWords(words.slice(1));
  if (data.length !== 66) throw new Error("bad SP address length");
  return { scan: pt(bytesToHex(data.slice(0, 33))), spend: pt(bytesToHex(data.slice(33))), network };
}

/** Encode a v0 silent-payment address (sp1… mainnet, tsp1… test networks). */
export function encodeSpAddress(scan: Pt, spend: Pt, network: "main" | "test" = "test"): string {
  const data = concatBytes(scan.toBytes(true), spend.toBytes(true));
  return bech32m.encode(network === "main" ? "sp" : "tsp", [0, ...bech32m.toWords(data)], 1023);
}

/**
 * Input-key context relative to the account key x: the input's BIP352 secret is
 * a_i = g·x + t (mod n), with g = ±1 folding BIP32/taproot parity and the BIP352
 * odd-Y negation, and t the accumulated public tweak. (Frostsnap: gacc/tacc/gv.)
 */
export interface TweakCtx { g: 1n | -1n; t: bigint }

/** C = a·B_scan for a = Σ (g_i·x + t_i), given X·B = x·B_scan. */
export function inputEcdh(xB: Pt, B: Pt, ctxs: TweakCtx[]): Pt {
  const gSum = mod(ctxs.reduce((s, c) => s + c.g, 0n));
  const tSum = mod(ctxs.reduce((s, c) => s + c.t, 0n));
  let C = Point.ZERO;
  if (gSum) C = C.add(xB.multiply(gSum));
  if (tSum) C = C.add(B.multiply(tSum));
  return C;
}


/** Device side: x_j·B_scan with a full DLEQ proof bound to input_hash. */
export function makeEcdhShare(shareIndex: number, xj: bigint, scanKey: string, ih: bigint): EcdhShare {
  const B = pt(scanKey);
  const proof = dleqProve(xj, B, crypto.getRandomValues(new Uint8Array(32)), be32(ih));
  return { shareIndex, scanKey, share: ptHex(B.multiply(xj)), proof: bytesToHex(proof) };
}

/** Verify one share against the share image derived from the polynomial. */
export function verifyEcdhShare(s: EcdhShare, polynomial: Pt[], ih: bigint): boolean {
  return dleqVerify(shareImage(polynomial, s.shareIndex), pt(s.scanKey), pt(s.share), hexToBytes(s.proof), be32(ih));
}

/** Combine a threshold of verified shares for one scan key: X·B = Σ λ_j·share_j. */
export function combineEcdhShares(shares: EcdhShare[], threshold: number): Pt {
  const idx = [...new Set(shares.map((s) => s.shareIndex))];
  if (idx.length < threshold) throw new Error(`need ${threshold} distinct shares, got ${idx.length}`);
  const use = idx.slice(0, threshold);
  return use.reduce((acc, j) => {
    const s = shares.find((x) => x.shareIndex === j)!;
    return acc.add(pt(s.share).multiply(lagrange(j, use)));
  }, Point.ZERO);
}

/** BIP352 per-scan-key recipient limit. */
export const K_MAX = 2323;

export interface SpRecipient { address: string; amountSat: number; outputIndex: number }

/**
 * Derive P2TR scripts for SP recipients. Recipients sharing a scan key get k = 0,1,…
 * in the order given (= transaction output order).
 */
export function deriveSpOutputs(
  recipients: { scan: Pt; spend: Pt; outputIndex: number }[],
  ecdhByScan: Map<string, Pt>, // a·B_scan per scan key (before input_hash)
  ih: bigint,
): { outputIndex: number; xonly: string; script: string }[] {
  const perScan = new Map<string, number>();
  for (const r of recipients) perScan.set(ptHex(r.scan), (perScan.get(ptHex(r.scan)) ?? 0) + 1);
  for (const [key, n] of perScan) if (n > K_MAX) throw new Error(`> K_max recipients for ${key.slice(0, 10)}`);
  const k = new Map<string, number>();
  return recipients.map((r) => {
    const key = ptHex(r.scan);
    const C = ecdhByScan.get(key);
    if (!C) throw new Error(`no ECDH for scan key ${key.slice(0, 10)}`);
    const S = C.multiply(ih);
    const kk = k.get(key) ?? 0;
    k.set(key, kk + 1);
    const ser = new Uint8Array(4);
    new DataView(ser.buffer).setUint32(0, kk, false);
    const tk = mod(toInt(taggedHash("BIP0352/SharedSecret", cbytes(S), ser)));
    if (tk === 0n) throw new Error("t_k = 0");
    const P = r.spend.add(G.multiply(tk));
    const xonly = bytesToHex(P.toBytes(true).slice(1));
    return { outputIndex: r.outputIndex, xonly, script: "5120" + xonly };
  });
}

export { be32, toInt };
