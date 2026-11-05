// Software stand-ins for the Frostsnap devices: a trusted-dealer t-of-n account
// key and vault inputs derived from it. Demo/test only — real shares live on devices.
import { bytesToHex } from "@noble/hashes/utils.js";
import { G, N, mod, ptHex, type Pt, type TweakCtx } from "./sp.ts";
import { inputPubkey } from "./ceremony.ts";
import type { SpInput } from "./schema.ts";

export const randScalar = () => BigInt("0x" + bytesToHex(crypto.getRandomValues(new Uint8Array(32)))) % N || 1n;

/** f(z) = x + c1·z + … ; shares f(1..n); polynomial = coefficient commitments. */
export function dealer(threshold: number, n: number) {
  const coeffs = Array.from({ length: threshold }, randScalar);
  const f = (z: bigint) => coeffs.reduceRight((acc, c) => mod(acc * z + c), 0n);
  return {
    secret: coeffs[0],
    polynomial: coeffs.map((c) => G.multiply(c)) as Pt[],
    shares: Array.from({ length: n }, (_, i) => ({ shareIndex: i + 1, x: f(BigInt(i + 1)) })),
  };
}

/** Vault inputs: secret a_i = g·x + t with g chosen so A_i has even Y (BIP352 taproot rule). */
export function vaultInputs(X: Pt, count: number) {
  const ctxs: TweakCtx[] = [];
  const inputs: SpInput[] = [];
  for (let i = 0; i < count; i++) {
    let c: TweakCtx = { g: 1n, t: randScalar() };
    if (!inputPubkey(X, c).hasEvenY()) c = { g: -1n, t: mod(-c.t) };
    ctxs.push(c);
    inputs.push({ txid: bytesToHex(crypto.getRandomValues(new Uint8Array(32))), vout: i, pubkey: ptHex(inputPubkey(X, c)) });
  }
  return { inputs, ctxs };
}
