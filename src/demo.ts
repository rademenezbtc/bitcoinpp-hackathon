// End-to-end PR #640 flow over Marmot: coordinator + 2 software "Frostsnap"
// devices (2-of-2), one Signet silent-payment recipient, in-memory relay.
// SP math is real (BIP352/374); FROST nonces and signature shares are opaque
// placeholders — the Frostsnap bridge supplies those.
import { MemRelay } from "./mem-relay.ts";
import { VaultNode } from "./node.ts";
import { G, encodeSpAddress, makeEcdhShare } from "./sp.ts";
import { buildEcdhRequest, buildSignRequest, checkEcdhRequest, checkSignRequest } from "./ceremony.ts";
import { dealer, vaultInputs, randScalar } from "./fixture.ts";
import type { CeremonyMsg, Recipient } from "./schema.ts";

const RELAYS = ["wss://mem.relay"];
const THRESHOLD = 2, N_DEVICES = 2;
const relay = new MemRelay();
const net = relay.network(RELAYS[0]);
const until = (ok: () => boolean, ms = 15000) =>
  new Promise<void>((res, rej) => {
    const t0 = Date.now();
    const tick = () => (ok() ? res() : Date.now() - t0 > ms ? rej(new Error("timeout")) : setTimeout(tick, 20));
    tick();
  });
const log = (who: string, m: CeremonyMsg, extra = "") => console.log(`  ${who.padEnd(12)} got ${m.type}${extra}`);

// --- Keys (stand-in for the physical Frostsnap 2-of-2) ---------------------
const vault = dealer(THRESHOLD, N_DEVICES);
const X = vault.polynomial[0];
const { inputs, ctxs } = vaultInputs(X, 2); // two vault UTXOs being spent
const recipient = encodeSpAddress(G.multiply(randScalar()), G.multiply(randScalar()), "test");
const recipients: Recipient[] = [
  { outputIndex: 0, address: recipient, amountSat: 50_000 },
  { outputIndex: 1, address: "tb1p…vault-change", amountSat: 12_345 },
];

// --- Marmot group -----------------------------------------------------------
const coord = await new VaultNode("coordinator", net, RELAYS).start();
const devices = await Promise.all(
  vault.shares.map((s) => new VaultNode(`device-${s.shareIndex}`, net, RELAYS).start()),
);
await coord.createGroup("Marmot Vault");
for (const d of devices) await coord.invite(d.pubkey);
await until(() => devices.every((d) => d.groupId === coord.groupId));
console.log(`group ready: coordinator + ${devices.length} devices, ${THRESHOLD}-of-${N_DEVICES}, signet`);
console.log(`paying ${recipient.slice(0, 20)}…${recipient.slice(-6)}\n`);

// --- Devices ----------------------------------------------------------------
devices.forEach((d, i) => {
  const { shareIndex, x } = vault.shares[i];
  d.on("message", async ({ msg }) => {
    try {
      if (msg.type === "sp.ecdh_request") {
        const h = checkEcdhRequest(msg, X, ctxs); // refuse before making any share
        log(d.name, msg, " → checks ok, user confirms on device");
        await d.send({
          type: "sp.offer", v: 2, sessionId: msg.sessionId, shareIndex,
          ecdh: msg.scanKeys.map((k) => makeEcdhShare(shareIndex, x, k, h)),
          frost: `<frostsnap offer ${shareIndex}>`,
        });
      }
      if (msg.type === "sp.sign_request" && msg.subset.includes(shareIndex)) {
        checkSignRequest(msg, vault.polynomial, THRESHOLD, ctxs);
        log(d.name, msg, " → proofs ok, scripts re-derived, signing");
        await d.send({ type: "sign.shares", v: 2, sessionId: msg.sessionId, shareIndex, frost: `<frostsnap sig shares ${shareIndex}>` });
      }
    } catch (e: any) {
      console.log(`  ${d.name} REFUSED: ${e.message}`);
      await d.send({ type: "session.abort", v: 2, sessionId: (msg as any).sessionId, reason: e.message, culprit: shareIndex });
    }
  });
});

// --- Coordinator ------------------------------------------------------------
const sessionId = crypto.randomUUID();
const req = buildEcdhRequest({ sessionId, network: "signet", psbt: "<sparrow psbt>", inputs, recipients });
const offers: Extract<CeremonyMsg, { type: "sp.offer" }>[] = [];
const sigs = new Set<number>();
let signReq: Extract<CeremonyMsg, { type: "sp.sign_request" }> | undefined;
let done = false;

coord.on("message", async ({ msg }) => {
  if (msg.type === "sp.offer" && msg.sessionId === sessionId && !signReq) {
    log(coord.name, msg, ` from share ${msg.shareIndex}`);
    offers.push(msg);
    if (offers.length >= THRESHOLD) {
      signReq = buildSignRequest(req, offers, vault.polynomial, THRESHOLD, ctxs);
      console.log(`  ${"coordinator".padEnd(12)} proofs verified, ECDH combined → output 0 script ${signReq.task.spScripts[0].script.slice(0, 20)}…`);
      await coord.send(signReq);
    }
  }
  if (msg.type === "sign.shares" && msg.sessionId === sessionId && !done) {
    log(coord.name, msg, ` from share ${msg.shareIndex}`);
    sigs.add(msg.shareIndex);
    if (sigs.size >= THRESHOLD) {
      done = true; // here: bridge aggregates FROST sig, coordinator finalizes tx
      await coord.send({ type: "session.complete", v: 2, sessionId, txid: "<txid>" });
    }
  }
  if (msg.type === "session.abort") { console.log("  aborted:", msg.reason); process.exit(1); }
});

await coord.send(req);
await until(() => done);
await new Promise((r) => setTimeout(r, 300));

// --- What the relay saw -----------------------------------------------------
const kinds = relay.log.reduce<Record<number, number>>((a, e) => ((a[e.kind] = (a[e.kind] ?? 0) + 1), a), {});
console.log("\nrelay saw (kind → count):", JSON.stringify(kinds));
const leaked = relay.log.some((e) => /sp\.offer|tsp1|ecdh/.test(e.content));
console.log("ceremony data or SP address visible to relay?", leaked);
process.exit(0);
