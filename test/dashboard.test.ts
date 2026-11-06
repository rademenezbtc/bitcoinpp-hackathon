import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// Exercise the shipped dashboard script with inert DOM/network adapters.
// No hardware, live coordinator, or broadcast endpoint is contacted.
test("batch review shows every address and amount; export preserves signed hex without broadcasting", () => {
  const html = readFileSync(new URL("../src/dashboard/index.html", import.meta.url), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1];
  const elements: Record<string, any> = {};
  let downloaded: Blob | undefined;
  let anchor: any;
  let calls = 0;
  const context: any = {
    console, Blob, setTimeout: (f: () => void) => f(),
    EventSource: class { addEventListener() {} },
    fetch: () => { calls++; throw new Error("unexpected network call"); },
    URL: { createObjectURL: (b: Blob) => { downloaded = b; return "blob:test"; }, revokeObjectURL() {} },
    document: {
      getElementById: (id: string) => elements[id] ??= { dataset: {}, innerHTML: "", textContent: "" },
      createElement: () => anchor = { click() {}, remove() {} },
      body: { appendChild() {}, classList: { toggle() {} } },
    },
  };
  runInNewContext(script + `
    S = { session: {
      id: "session", recipients: [{address: "tsp1first", amount_sat: 1000}, {address: "tsp1second<test>", amount_sat: 2000}],
      inputs: [{txid: "first", vout: 0}, {txid: "second", vout: 1}],
      feeSat: 300, change: {amount_sat: 6700}, complete: {txid: "abc", txHex: "010203"}
    }};
    renderPayment(); renderTx();
  `, context);
  expect(elements.payment.innerHTML).toContain("tsp1first");
  expect(elements.payment.innerHTML).toContain("tsp1second&lt;test&gt;");
  expect(elements.payment.innerHTML).toContain("1,000 sat");
  expect(elements.payment.innerHTML).toContain("2,000 sat");
  expect(elements.payment.innerHTML).toContain("second:1");
  elements.exportTx.onclick();
  expect(anchor.download).toBe("signet-abc.hex");
  expect(downloaded).toBeDefined();
  expect(calls).toBe(0);
  return downloaded!.text().then(text => expect(text).toBe("010203\n"));
});
