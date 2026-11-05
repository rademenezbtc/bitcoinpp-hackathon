// Regression: marmot-ts 0.9 loses messages when sends overlap ingests on the
// same group ("Desired gen in the past"). VaultNode serialises them.
import { expect, test } from "bun:test";
import { MemRelay } from "../src/mem-relay.ts";
import { VaultNode } from "../src/node.ts";

test("no message loss when replies are sent while messages are arriving", async () => {
  const relay = new MemRelay();
  const net = relay.network("wss://mem.relay");
  const R = ["wss://mem.relay"];
  const quiet = { log: () => {} };
  const A = await new VaultNode("A", net, R, quiet).start();
  const B = await new VaultNode("B", net, R, quiet).start();
  await A.createGroup("g");
  await A.invite(B.pubkey);
  while (B.groupId !== A.groupId) await new Promise((r) => setTimeout(r, 20));
  const gotA: string[] = [], gotB: string[] = [];
  A.on("rumor", (r) => { if (!r.local) gotA.push(r.content); });
  B.on("rumor", (r) => {
    if (r.local) return;
    gotB.push(r.content);
    setTimeout(() => B.sendRumor(1, `re-${r.content}`), Math.random() * 30);
  });
  for (let i = 0; i < 6; i++) { A.sendRumor(1, `a${i}`); await new Promise((r) => setTimeout(r, 5)); }
  const t0 = Date.now();
  while (gotA.length < 6 && Date.now() - t0 < 10000) await new Promise((r) => setTimeout(r, 25));
  expect(gotB.sort()).toEqual(["a0", "a1", "a2", "a3", "a4", "a5"]);
  expect(gotA.sort()).toEqual(["re-a0", "re-a1", "re-a2", "re-a3", "re-a4", "re-a5"]);
}, 30000);
