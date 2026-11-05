import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  G, N, Point, mod, pt, ptHex, be32,
  dleqProve, dleqVerify, inputHash, decodeSpAddress, deriveSpOutputs,
  shareImage, lagrange, makeEcdhShare, verifyEcdhShare, combineEcdhShares, inputEcdh,
  type TweakCtx,
} from "../src/sp.ts";

const dir = new URL("./vectors/", import.meta.url);
const csv = (f: string) => {
  const [head, ...rows] = readFileSync(new URL(f, dir), "utf8").trim().split("\n");
  const keys = head.split(",");
  return rows.map((r) => Object.fromEntries(r.split(",").map((v, i) => [keys[i], v])));
};
const parsePt = (h: string) => { try { return pt(h); } catch { return null; } };
const msg = (h: string) => (h ? hexToBytes(h) : undefined);
const rand = () => BigInt("0x" + bytesToHex(crypto.getRandomValues(new Uint8Array(32)))) % N || 1n;

describe("BIP374 DLEQ", () => {
  test("generate vectors", () => {
    for (const v of csv("test_vectors_generate_proof.csv")) {
      const Gp = parsePt(v.point_G), B = parsePt(v.point_B);
      let got = "INVALID";
      try {
        if (!Gp || !B) throw 0;
        got = bytesToHex(dleqProve(BigInt("0x" + v.scalar_a), B, hexToBytes(v.auxrand_r), msg(v.message), Gp));
      } catch {}
      expect(`${v.index}:${got}`).toBe(`${v.index}:${v.result_proof}`);
    }
  });
  test("verify vectors", () => {
    for (const v of csv("test_vectors_verify_proof.csv")) {
      const [Gp, A, B, C] = [v.point_G, v.point_A, v.point_B, v.point_C].map(parsePt);
      const ok = !!(Gp && A && B && C) && dleqVerify(A, B, C, hexToBytes(v.proof), msg(v.message), Gp);
      expect(`${v.index}:${ok}`).toBe(`${v.index}:${v.result_success === "TRUE"}`);
    }
  });
});

// vectors may compress repeated recipients with a "count" field
const expand = (rs: any[]) => rs.flatMap((r) => Array(r.count ?? 1).fill(r));
const sp = JSON.parse(readFileSync(new URL("send_and_receive_test_vectors.json", dir), "utf8"));

describe("BIP352 sending", () => {
  const cases = sp.flatMap((t: any) => t.sending.map((s: any) => ({ comment: t.comment, ...s })))
    .filter((c: any) => c.expected.input_private_key_sum && c.given.recipients.length);

  test(`${cases.length} vectors: input_hash, shared secrets, outputs`, () => {
    for (const c of cases) {
      const mustFail = JSON.stringify(c.expected.outputs) === "[[]]";
      if (mustFail) {
        expect(() => {
          const ih = inputHash(c.given.vin.map((v: any) => ({ txid: v.txid, vout: v.vout })), c.expected.input_pub_keys.map(pt));
          const a = BigInt("0x" + c.expected.input_private_key_sum);
          const recips = expand(c.given.recipients).map((r: any, i: number) => ({ scan: pt(r.scan_pub_key), spend: pt(r.spend_pub_key), outputIndex: i }));
          const ecdh = new Map(recips.map((r: any) => [ptHex(r.scan), r.scan.multiply(a)]));
          deriveSpOutputs(recips, ecdh as any, ih);
        }).toThrow();
        continue;
      }
      const outpoints = c.given.vin.map((v: any) => ({ txid: v.txid, vout: v.vout }));
      const ih = inputHash(outpoints, c.expected.input_pub_keys.map(pt));
      const a = BigInt("0x" + c.expected.input_private_key_sum);
      const recips = expand(c.given.recipients).map((r: any, i: number) => ({
        scan: pt(r.scan_pub_key), spend: pt(r.spend_pub_key), outputIndex: i,
      }));
      const ecdh = new Map<string, any>();
      for (const r of recips) ecdh.set(ptHex(r.scan), r.scan.multiply(a));
      // shared secrets = input_hash·a·B_scan, one per distinct scan key
      const secrets = [...ecdh.values()].map((C) => ptHex(C.multiply(ih))).sort();
      expect(secrets).toEqual([...new Set<string>(c.expected.shared_secrets)].sort());
      const outs = deriveSpOutputs(recips, ecdh, ih).map((o) => o.xonly).sort();
      const ok = c.expected.outputs.some((set: string[]) => JSON.stringify([...set].sort()) === JSON.stringify(outs));
      expect(`${c.comment}: ${ok}`).toBe(`${c.comment}: true`);
    }
  });

  test("address decoding matches vector keys", () => {
    for (const c of cases) for (const r of c.given.recipients) {
      const d = decodeSpAddress(r.address);
      expect(ptHex(d.scan)).toBe(r.scan_pub_key);
      expect(ptHex(d.spend)).toBe(r.spend_pub_key);
    }
  });
});

describe("2-of-2 FROST flow (PR #640 shape)", () => {
  // Trusted-dealer 2-of-2: f(z) = x + c·z; shares f(1), f(2); polynomial = [x·G, c·G]
  const x = rand(), c1 = rand();
  const f = (z: bigint) => mod(x + c1 * z);
  const poly = [G.multiply(x), G.multiply(c1)];

  test("share images and Lagrange recombine the account key", () => {
    expect(shareImage(poly, 1).equals(G.multiply(f(1n)))).toBe(true);
    expect(lagrange(1, [1, 2])).toBe(2n);
    expect(lagrange(2, [1, 2])).toBe(mod(-1n));
  });

  test("shares + proofs combine to x·B_scan, bound to input_hash", () => {
    const B = G.multiply(rand());
    const ih = rand();
    const shares = [1, 2].map((j) => makeEcdhShare(j, f(BigInt(j)), ptHex(B), ih));
    for (const s of shares) expect(verifyEcdhShare(s, poly, ih)).toBe(true);
    expect(combineEcdhShares(shares, 2).equals(B.multiply(x))).toBe(true);
    // replay into another tx (different input_hash) fails
    expect(verifyEcdhShare(shares[0], poly, mod(ih + 1n))).toBe(false);
    // a share claiming the wrong index fails
    expect(verifyEcdhShare({ ...shares[0], shareIndex: 2 }, poly, ih)).toBe(false);
    // tampered share fails
    expect(verifyEcdhShare({ ...shares[0], share: ptHex(B.multiply(7n)) }, poly, ih)).toBe(false);
    expect(() => combineEcdhShares([shares[0]], 2)).toThrow();
  });

  test("tweak contexts: multi-input ECDH equals direct a·B", () => {
    const B = G.multiply(rand());
    const ctxs: TweakCtx[] = [{ g: 1n, t: rand() }, { g: -1n, t: rand() }, { g: 1n, t: rand() }];
    const a = mod(ctxs.reduce((s, c) => s + c.g * x + c.t, 0n));
    expect(inputEcdh(B.multiply(x), B, ctxs).equals(B.multiply(a))).toBe(true);
  });
});
