import { describe, expect, test } from "bun:test";
import { G, mod, ptHex, pt, toInt, encodeSpAddress, makeEcdhShare, deriveSpOutputs } from "../src/sp.ts";
import { buildEcdhRequest, buildSignRequest, checkEcdhRequest, checkSignRequest } from "../src/ceremony.ts";
import { dealer, vaultInputs, randScalar } from "../src/fixture.ts";
import type { CeremonyMsg, Recipient } from "../src/schema.ts";

type Offer = Extract<CeremonyMsg, { type: "sp.offer" }>;

function setup(nInputs = 2) {
  const vault = dealer(2, 2);
  const X = vault.polynomial[0];
  const { inputs, ctxs } = vaultInputs(X, nInputs);
  const scan = G.multiply(randScalar()), spend = G.multiply(randScalar());
  const recipients: Recipient[] = [
    { outputIndex: 0, address: encodeSpAddress(scan, spend, "test"), amountSat: 50_000 },
    { outputIndex: 1, address: "tb1pchangechangechangechangechangechangechangechangechangeq", amountSat: 12_345 },
  ];
  const req = buildEcdhRequest({ sessionId: "s1", network: "signet", psbt: "cHNidP8=", inputs, recipients });
  const offers: Offer[] = vault.shares.map(({ shareIndex, x }) => {
    const h = checkEcdhRequest(req, X, ctxs);
    return { type: "sp.offer", v: 2, sessionId: "s1", shareIndex, ecdh: req.scanKeys.map((k) => makeEcdhShare(shareIndex, x, k, h)) };
  });
  return { vault, X, inputs, ctxs, scan, spend, recipients, req, offers };
}

describe("PR #640 ceremony, 2-of-2, one SP recipient", () => {
  test("threshold result equals single-signer BIP352 computation", () => {
    const { vault, ctxs, scan, spend, req, offers } = setup();
    const sr = buildSignRequest(req, offers, vault.polynomial, 2, ctxs);
    // reference: the whole input secret in one place
    const a = mod(ctxs.reduce((s, c) => s + c.g * vault.secret + c.t, 0n));
    const h = toInt(Buffer.from(req.inputHash, "hex"));
    const ref = deriveSpOutputs([{ scan, spend, outputIndex: 0 }], new Map([[ptHex(scan), scan.multiply(a)]]), h);
    expect(sr.task.spScripts).toEqual([{ outputIndex: 0, script: ref[0].script }]);
    expect(sr.subset).toEqual([1, 2]);
    expect(checkSignRequest(sr, vault.polynomial, 2, ctxs)).toBe(true);
  });

  test("coordinator rejects a bad proof and names the culprit", () => {
    const { vault, ctxs, req, offers } = setup();
    offers[1].ecdh[0].share = ptHex(pt(offers[1].ecdh[0].share).add(G));
    expect(() => buildSignRequest(req, offers, vault.polynomial, 2, ctxs)).toThrow(/share 2: bad DLEQ/);
  });

  test("device refuses a swapped SP script", () => {
    const { vault, ctxs, req, offers } = setup();
    const sr = buildSignRequest(req, offers, vault.polynomial, 2, ctxs);
    sr.task.spScripts[0].script = "5120" + "ab".repeat(32);
    expect(() => checkSignRequest(sr, vault.polynomial, 2, ctxs)).toThrow(/script mismatch/);
  });

  test("device refuses missing proofs, foreign polynomial, wrong input hash", () => {
    const { vault, ctxs, req, offers } = setup();
    const sr = buildSignRequest(req, offers, vault.polynomial, 2, ctxs);
    expect(() => checkSignRequest({ ...sr, bundle: { ...sr.bundle, shares: [] } }, vault.polynomial, 2, ctxs)).toThrow(/no proofs/);
    expect(() => checkSignRequest(sr, dealer(2, 2).polynomial, 2, ctxs)).toThrow(/access structure/);
    expect(() => checkEcdhRequest({ ...req, inputHash: "00".repeat(32) }, vault.polynomial[0], ctxs)).toThrow(/input_hash/);
  });

  test("a share replayed from another transaction fails", () => {
    const a = setup(), b = setup();
    // b's device share used in a's session: different input_hash and key → rejected
    const mixed = [a.offers[0], { ...b.offers[1], ecdh: b.offers[1].ecdh.map((e) => ({ ...e, scanKey: a.req.scanKeys[0] })) }];
    expect(() => buildSignRequest(a.req, mixed, a.vault.polynomial, 2, a.ctxs)).toThrow(/share 2/);
  });
});
