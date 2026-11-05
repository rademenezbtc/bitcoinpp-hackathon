// A (coordinator + signer 1) and B (signer 2), each with its own mock bridge
// process, over an in-memory relay.
import { afterEach, describe, expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { getPublicKey } from "nostr-tools";
import { MemRelay } from "../src/mem-relay.ts";
import { VaultNode } from "../src/node.ts";
import { VaultApp, type AppConfig } from "../src/vault-app.ts";
import { FrostsnapBridge } from "../src/frostsnap-bridge.ts";
import { FS_KIND, encodeFs, newSessionId } from "../src/fs-schema.ts";

const MOCK = fileURLToPath(new URL("../scripts/mock-bridge.ts", import.meta.url));
const RELAYS = ["wss://mem.relay"];
const until = (ok: () => boolean, ms = 20000) =>
  new Promise<void>((res, rej) => {
    const t0 = Date.now();
    const tick = () => (ok() ? res() : Date.now() - t0 > ms ? rej(new Error("timeout")) : setTimeout(tick, 25));
    tick();
  });

const bridges: FrostsnapBridge[] = [];
afterEach(() => { bridges.splice(0).forEach((b) => b.close()); });

async function setup(opts: { gate?: boolean; rejectSignB?: boolean; tamperB?: boolean } = {}) {
  const relay = new MemRelay();
  const net = relay.network(RELAYS[0]);
  const skA = crypto.getRandomValues(new Uint8Array(32)), skB = crypto.getRandomValues(new Uint8Array(32));
  const pkA = getPublicKey(skA), pkB = getPublicKey(skB);
  const base = {
    network: "signet" as const, relays: RELAYS, threshold: 2, coordinator: pkA,
    pin: { keyId: "key-mock", accessStructureId: "as-mock" }, members: { [pkA]: 1, [pkB]: 2 },
    gateBeforeSign: opts.gate ?? true,
  };
  const cfgA: AppConfig = { ...base, name: "A", role: "coordinator", shareIndex: 1, deviceId: "devA" };
  const cfgB: AppConfig = { ...base, name: "B", role: "signer", shareIndex: 2, deviceId: "devB" };
  const logs: string[] = [];
  const mk = (cfg: AppConfig, sk: Uint8Array, extra: string[] = []) => {
    const node = new VaultNode(cfg.name, net, RELAYS, { secretKey: sk, acceptInvitesFrom: [pkA], log: (s) => logs.push(`${cfg.name} ${s}`) });
    const bridge = new FrostsnapBridge("bun", [MOCK, "--device", cfg.deviceId!, "--share", String(cfg.shareIndex), ...extra]);
    bridges.push(bridge);
    return new VaultApp(cfg, node, bridge, (s) => logs.push(`${cfg.name} ${s}`));
  };
  const A = mk(cfgA, skA), B = mk(cfgB, skB, [...(opts.rejectSignB ? ["--reject-sign"] : []), ...(opts.tamperB ? ["--tamper-task"] : [])]);
  await until(() => A.deviceReady && B.deviceReady);
  await A.node.start(); await B.node.start();
  await A.node.createGroup("vault");
  await A.node.invite(pkB);
  await until(() => B.node.groupId === A.node.groupId);
  return { A, B, relay, logs, pkA, pkB };
}

const proposal = {
  inputs: [{ txid: "11".repeat(32), transaction: "02000000", vout: 0, internal: false, index: 0 }],
  recipients: [{ address: "tsp1qexample", amount_sat: 1000 }],
  change: { index: 0, amount_sat: 8700 },
};

describe("bridge-backed ceremony A+B", () => {
  test("milestone 1: identical proposal → both offers → stops at the sign gate", async () => {
    const { A, B, logs } = await setup({ gate: true });
    const id = await A.propose(proposal);
    await until(() => A.coord!.offers.size === 2);
    await new Promise((r) => setTimeout(r, 300));
    expect(A.signer!.proposal.task).toBe(B.signer!.proposal.task); // identical proposal
    expect(B.signer!.id).toBe(id);
    expect(A.coord!.subset).toBeUndefined(); // gate held
    expect(B.signer!.signing).toBeFalsy();
    expect(logs.some((l) => l.includes("MILESTONE 1 GATE"))).toBe(true);
  }, 30000);

  test("full run: sign → shares → combine → signed tx", async () => {
    const { A, B, logs } = await setup({ gate: true });
    await A.propose(proposal);
    await until(() => A.coord!.offers.size === 2);
    await A.requestSignatures();
    await until(() => !!A.coord!.completed).catch((e) => { console.log(logs.join("\n")); throw e; });
    await until(() => !!B.signer!.done);
    expect(A.coord!.subset).toEqual([1, 2]);
    expect(B.signer!.sharesSent).toBe(true);
    expect(new Set([...A.signer!.derived.values(), ...B.signer!.derived.values()]).size).toBe(1);
  }, 30000);

  test("B refuses a sign request whose offer for A was swapped", async () => {
    const { A, B, logs } = await setup({ gate: true });
    await A.propose(proposal);
    await until(() => A.coord!.offers.size === 2);
    const c = A.coord!;
    c.offers.set(1, { binonces: "00", ecdh: "00" }); // malicious coordinator edits A's offer
    await A.requestSignatures();
    await until(() => logs.some((l) => l.startsWith("B ✗ offer for share 1 differs")));
    await until(() => !!B.signer!.done);
    expect(B.signer!.sharesSent).toBeFalsy();
  }, 30000);

  test("proposals from a non-coordinator and replays are ignored", async () => {
    const { A, B, logs } = await setup();
    // B (not coordinator) tries to propose to the group
    await B.node.sendRumor(FS_KIND, encodeFs({ t: "fs.proposal", sessionId: newSessionId(), task: "aa", pin: { protocol: "frostsnap-sp-bridge/1", keyId: "key-mock", accessStructureId: "as-mock" }, summary: { recipients: [], inputs: [] } }));
    await until(() => logs.some((l) => l.startsWith("A ✗ proposal from non-coordinator")));
    expect(A.signer).toBeUndefined();
    // wrong wallet pin is refused
    await A.node.sendRumor(FS_KIND, encodeFs({ t: "fs.proposal", sessionId: newSessionId(), task: "aa", pin: { protocol: "frostsnap-sp-bridge/1", keyId: "other", accessStructureId: "as-mock" }, summary: { recipients: [], inputs: [] } }));
    await until(() => logs.some((l) => l.startsWith("B ✗ proposal for a different key id")));
    expect(B.signer).toBeUndefined();
  }, 30000);

  test("signers that derive different transactions never release shares", async () => {
    const { A, B, logs } = await setup({ gate: false, tamperB: true });
    await A.propose(proposal);
    await until(() => logs.some((l) => l.includes("derived DIFFERENT transactions")));
    await until(() => !!A.coord!.completed && !!B.signer!.done);
    expect(A.signer!.sharesSent).toBeFalsy();
    expect(B.signer!.sharesSent).toBeFalsy();
    expect(A.coord!.shares.size).toBe(0);
  }, 30000);

  test("a device rejecting the sign cancels cleanly", async () => {
    const { A, B, logs } = await setup({ gate: false, rejectSignB: true });
    await A.propose(proposal);
    await until(() => logs.some((l) => l.startsWith("B ✗ user rejected on device")));
    await until(() => logs.some((l) => l.startsWith("A share 2: ✗ user rejected on device"))); // coordinator is told
    expect(A.coord!.completed).toBeFalsy();
    await A.cancel("rejected on B");
    await until(() => !!A.coord!.completed && !!B.signer!.done);
  }, 30000);
});
