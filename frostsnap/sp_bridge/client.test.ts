import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { FrostsnapBridge } from "./client.ts";

test("adapter correlates concurrent requests and reports bridge errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "frostsnap-client-"));
  const bridge = new FrostsnapBridge(process.env.FROSTSNAP_BRIDGE_BIN ?? resolve("target/debug/frostsnap_sp_bridge"), [
    "--state", join(directory, "state"), "--desktop-dev-key", "--offline",
  ]);
  try {
    assert.deepEqual(await Promise.all([
      bridge.request({ method: "wallets" }), bridge.request({ method: "wallets" }),
    ]), [[], []]);
    await assert.rejects(bridge.request({ method: "unknown" }), /unknown variant/);
    assert.deepEqual(await bridge.request({ method: "wallets" }), []);
  } finally {
    bridge.close();
    // Closing stdin terminates the process; allow it to release SQLite before cleanup.
    await new Promise(resolve => setTimeout(resolve, 100));
    await rm(directory, { recursive: true, force: true });
  }
});
