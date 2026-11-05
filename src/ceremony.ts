// Coordinator and device logic for the PR #640 silent-payment flow.
// Pure functions over schema messages: no transport, no I/O — easy to test,
// and a reference for the Frostsnap bridge/firmware checks.
import {
  G, Point, mod, pt, ptHex, toInt, type Pt, type TweakCtx,
  inputHash, decodeSpAddress, verifyEcdhShare, combineEcdhShares, inputEcdh, deriveSpOutputs,
} from "./sp.ts";
import type { CeremonyMsg, EcdhShare, Network, Recipient, SpInput, SpScript } from "./schema.ts";

type EcdhRequest = Extract<CeremonyMsg, { type: "sp.ecdh_request" }>;
type Offer = Extract<CeremonyMsg, { type: "sp.offer" }>;
type SignRequest = Extract<CeremonyMsg, { type: "sp.sign_request" }>;

const SP_HRP: Record<Network, string> = { bitcoin: "sp1", signet: "tsp1", testnet: "tsp1", regtest: "tsp1" };
export const isSpAddress = (a: string) => /^t?sp1/.test(a);

function spRecipients(recipients: Recipient[], network: Network) {
  return recipients
    .filter((r) => isSpAddress(r.address))
    .map((r) => {
      if (!r.address.startsWith(SP_HRP[network])) throw new Error(`${r.address.slice(0, 8)}… is not a ${network} SP address`);
      return { ...decodeSpAddress(r.address), outputIndex: r.outputIndex };
    })
    .sort((a, b) => a.outputIndex - b.outputIndex); // k counter follows tx output order
}

const ih = (inputs: SpInput[]) => inputHash(inputs.map(({ txid, vout }) => ({ txid, vout })), inputs.map((i) => pt(i.pubkey)));
const hex32 = (x: bigint) => x.toString(16).padStart(64, "0");
const uniq = <T,>(xs: T[]) => [...new Set(xs)];

/** Input key implied by a tweak context: A_i = g·X + t·G (must equal the PSBT input key). */
export const inputPubkey = (X: Pt, c: TweakCtx) => X.multiply(mod(c.g)).add(c.t ? G.multiply(c.t) : Point.ZERO);

function checkInputsMatchCtxs(inputs: SpInput[], X: Pt, ctxs: TweakCtx[]) {
  if (ctxs.length !== inputs.length) throw new Error("tweak contexts ≠ inputs");
  inputs.forEach((inp, i) => {
    if (ptHex(inputPubkey(X, ctxs[i])) !== inp.pubkey) throw new Error(`input ${i} is not a vault key`);
  });
}

// ----------------------------------------------------------- coordinator
export function buildEcdhRequest(a: {
  sessionId: string; network: Network; psbt: string; inputs: SpInput[]; recipients: Recipient[];
}): EcdhRequest {
  const sp = spRecipients(a.recipients, a.network);
  return {
    type: "sp.ecdh_request", v: 2, ...a,
    inputHash: hex32(ih(a.inputs)),
    scanKeys: uniq(sp.map((r) => ptHex(r.scan))),
  };
}

/**
 * Verify offers, pick the subset, combine ECDH per scan key, apply input tweak
 * contexts and derive the SP output scripts. Throws with the culprit's index.
 */
export function buildSignRequest(
  req: EcdhRequest, offers: Offer[], polynomial: Pt[], threshold: number, ctxs: TweakCtx[],
): SignRequest {
  const h = toInt(Buffer.from(req.inputHash, "hex"));
  const X = polynomial[0];
  checkInputsMatchCtxs(req.inputs, X, ctxs);

  const valid: Offer[] = [];
  for (const o of offers) {
    const keys = o.ecdh.map((e) => e.scanKey).sort().join();
    if (keys !== [...req.scanKeys].sort().join()) throw culprit(o.shareIndex, "wrong scan keys");
    for (const e of o.ecdh) {
      if (e.shareIndex !== o.shareIndex) throw culprit(o.shareIndex, "share index mismatch");
      if (!verifyEcdhShare(e, polynomial, h)) throw culprit(o.shareIndex, "bad DLEQ proof");
    }
    valid.push(o);
  }
  const subset = uniq(valid.map((o) => o.shareIndex)).sort((a, b) => a - b).slice(0, threshold);
  if (subset.length < threshold) throw new Error(`need ${threshold} offers, have ${subset.length}`);
  const shares = valid.filter((o) => subset.includes(o.shareIndex)).flatMap((o) => o.ecdh);

  const spScripts = deriveScripts(req.recipients, req.network, shares, req.scanKeys, threshold, ctxs, h);
  return {
    type: "sp.sign_request", v: 2, sessionId: req.sessionId, subset,
    bundle: { accountPolynomial: polynomial.map(ptHex), inputHash: req.inputHash, shares },
    task: { network: req.network, psbt: req.psbt /* TODO: write PSBT_OUT_SCRIPT */, inputs: req.inputs, recipients: req.recipients, spScripts },
    frost: Object.fromEntries(valid.filter((o) => subset.includes(o.shareIndex) && o.frost).map((o) => [o.shareIndex, o.frost!])),
  };
}

function deriveScripts(
  recipients: Recipient[], network: Network, shares: EcdhShare[], scanKeys: string[],
  threshold: number, ctxs: TweakCtx[], h: bigint,
): SpScript[] {
  const ecdh = new Map<string, Pt>();
  for (const key of scanKeys) {
    const xB = combineEcdhShares(shares.filter((s) => s.scanKey === key), threshold);
    ecdh.set(key, inputEcdh(xB, pt(key), ctxs));
  }
  return deriveSpOutputs(spRecipients(recipients, network), ecdh, h).map(({ outputIndex, script }) => ({ outputIndex, script }));
}

const culprit = (i: number, why: string) => Object.assign(new Error(`share ${i}: ${why}`), { culprit: i });

// ----------------------------------------------------------- device checks
/** Before making a share: input hash and scan keys must match what we derive ourselves. */
export function checkEcdhRequest(req: EcdhRequest, X: Pt, ctxs: TweakCtx[]) {
  checkInputsMatchCtxs(req.inputs, X, ctxs);
  const own = hex32(ih(req.inputs));
  if (own !== req.inputHash) throw new Error("input_hash mismatch");
  const scan = uniq(spRecipients(req.recipients, req.network).map((r) => ptHex(r.scan)));
  if (scan.sort().join() !== [...req.scanKeys].sort().join()) throw new Error("scan keys mismatch");
  return toInt(Buffer.from(own, "hex"));
}

/** Before signing: rebuild share images, check every proof, threshold per scan key, re-derive scripts. */
export function checkSignRequest(sr: SignRequest, myPolynomial: Pt[], threshold: number, ctxs: TweakCtx[]) {
  const poly = sr.bundle.accountPolynomial;
  if (poly.length !== myPolynomial.length || poly.some((p, i) => p !== ptHex(myPolynomial[i])))
    throw new Error("polynomial is not our access structure");
  const { inputs, recipients, spScripts } = sr.task;
  checkInputsMatchCtxs(inputs, myPolynomial[0], ctxs);
  const own = hex32(ih(inputs));
  if (own !== sr.bundle.inputHash) throw new Error("input_hash mismatch");
  const h = toInt(Buffer.from(own, "hex"));

  const network = sr.task.network;
  const sp = spRecipients(recipients, network);
  if (sp.length && !sr.bundle.shares.length) throw new Error("SP outputs but no proofs");
  if (!sp.length && sr.bundle.shares.length) throw new Error("proofs for a plain send");

  for (const s of sr.bundle.shares) if (!verifyEcdhShare(s, myPolynomial, h)) throw new Error(`bad proof from share ${s.shareIndex}`);
  const scanKeys = uniq(sp.map((r) => ptHex(r.scan)));
  for (const key of scanKeys) {
    const n = uniq(sr.bundle.shares.filter((s) => s.scanKey === key).map((s) => s.shareIndex)).length;
    if (n < threshold) throw new Error(`only ${n} shares for a scan key`);
  }
  const mine = deriveScripts(recipients, network, sr.bundle.shares, scanKeys, threshold, ctxs, h);
  if (JSON.stringify(mine) !== JSON.stringify([...spScripts].sort((a, b) => a.outputIndex - b.outputIndex)))
    throw new Error("SP script mismatch — refusing to sign");
  return true;
}

export { hex32 };
