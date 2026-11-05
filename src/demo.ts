// End-to-end message flow: coordinator + 3 FROST devices (2-of-3) over an
// in-memory relay. Crypto values are placeholders for now — this proves the
// Marmot plumbing and the ceremony choreography.
import { MemRelay } from "./mem-relay.ts";
import { VaultNode } from "./node.ts";
import type { CeremonyMsg } from "./schema.ts";

const RELAYS = ["wss://mem.relay"];
const relay = new MemRelay();
const net = relay.network(RELAYS[0]);

const fake = (tag: string) => tag.padEnd(64, "0");
const until = (ok: () => boolean, ms = 15000) =>
  new Promise<void>((res, rej) => {
    const t0 = Date.now();
    const tick = () => (ok() ? res() : Date.now() - t0 > ms ? rej(new Error("timeout")) : setTimeout(tick, 20));
    tick();
  });

const coord = await new VaultNode("coordinator", net, RELAYS).start();
const devices = await Promise.all(
  [1, 2, 3].map((i) => new VaultNode(`device-${i}`, net, RELAYS).start()),
);
const THRESHOLD = 2;
const log = (who: string, m: CeremonyMsg) => console.log(`  ${who.padEnd(12)} ${m.type}`);

// --- Group setup -----------------------------------------------------------
await coord.createGroup("Marmot Vault");
for (const d of devices) await coord.invite(d.pubkey);
await until(() => devices.every((d) => d.groupId === coord.groupId));
console.log(`group ${coord.groupId!.slice(0, 12)}… has coordinator + ${devices.length} devices`);

// --- Device behaviour (placeholder crypto) ---------------------------------
for (const [idx, d] of devices.entries()) {
  const id = idx + 1;
  d.on("message", async ({ msg }) => {
    if (msg.type === "spend.proposal" && id <= THRESHOLD + 1) {
      log(d.name, msg);
      await d.send({
        type: "round1",
        sessionId: msg.sessionId,
        signerId: id,
        commitments: [{ hiding: fake("h" + id), binding: fake("b" + id) }],
        sp: [{ scanKey: fake("scan"), share: fake("sh" + id), R1: fake("r1"), R2: fake("r2") }],
      });
    }
    if (msg.type === "signing.package" && msg.signers.includes(id)) {
      log(d.name, msg);
      // A real device recomputes sighash + SP outputs from all round1 shares here.
      await d.send({
        type: "round2",
        sessionId: msg.sessionId,
        signerId: id,
        sigShares: [fake("z" + id)],
        dleq: [{ scanKey: fake("scan"), s: fake("s" + id) }],
      });
    }
  });
}

// --- Coordinator session ---------------------------------------------------
const sessionId = crypto.randomUUID();
const round1 = new Map<number, CeremonyMsg>();
const round2 = new Map<number, CeremonyMsg>();
let done = false;

coord.on("message", async ({ msg }) => {
  if (msg.type === "round1" && msg.sessionId === sessionId) {
    log(coord.name, msg);
    round1.set(msg.signerId, msg);
    if (round1.size === THRESHOLD) {
      const signers = [...round1.keys()].sort();
      // Here: combine λ_i·share_i → C, derive SP output scripts, sighashes, DLEQ challenge e.
      await coord.send({
        type: "signing.package",
        sessionId,
        signers,
        psbt: "cHNidP8B…",
        sighashes: [fake("sighash")],
        dleq: [{ scanKey: fake("scan"), e: fake("e") }],
      });
    }
  }
  if (msg.type === "round2" && msg.sessionId === sessionId && !done) {
    log(coord.name, msg);
    round2.set(msg.signerId, msg);
    if (round2.size === THRESHOLD) {
      done = true;
      // Here: aggregate FROST sig + DLEQ proof, write PSBT fields, hand back to Sparrow.
      await coord.send({ type: "session.complete", sessionId, txid: fake("txid"), psbt: "cHNidP8B…signed" });
    }
  }
});

console.log("ceremony:");
await coord.send({ type: "spend.proposal", sessionId, psbt: "cHNidP8B…from-sparrow", memo: "demo spend" });
await until(() => done);
await new Promise((r) => setTimeout(r, 300));

// --- What the relay saw ----------------------------------------------------
const kinds = relay.log.reduce<Record<number, number>>((a, e) => ((a[e.kind] = (a[e.kind] ?? 0) + 1), a), {});
console.log("\nrelay saw (kind → count):", kinds);
const sample = relay.log.filter((e) => e.kind === 445).at(-1)!;
console.log("sample kind 445 content (ciphertext):", sample.content.slice(0, 60) + "…");
const leaked = relay.log.some((e) => e.content.includes("spend.proposal") || e.content.includes("round1"));
console.log("ceremony JSON visible to relay?", leaked);
process.exit(0);
