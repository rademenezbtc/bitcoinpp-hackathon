// Live ceremony dashboard, served by `vault run` on 127.0.0.1 only.
//   GET  /         the page (self-contained, works offline)
//   GET  /events   Server-Sent Events: snapshot | wire | log
//   POST /api/*    propose · sign · cancel · broadcast (header x-vault: 1 required)
import type { VaultApp } from "../vault-app.ts";
import type { WireEvent } from "../tap.ts";

export interface DashboardActions {
  propose?: (file: string) => Promise<unknown>;
  broadcast?: (txHex: string) => Promise<string>;
}

const enc = new TextEncoder();
const page = Bun.file(new URL("./index.html", import.meta.url));

export function startDashboard(app: VaultApp, opts: { port: number; actions?: DashboardActions; network?: string }) {
  const clients = new Set<ReadableStreamDefaultController>();
  const wire: any[] = [];
  const send = (c: ReadableStreamDefaultController, type: string, data: unknown) => {
    try { c.enqueue(enc.encode(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`)); } catch { clients.delete(c); }
  };
  const broadcast = (type: string, data: unknown) => { for (const c of clients) send(c, type, data); };

  // Words that must never appear in what relays see.
  const secrets = () => {
    const s = app.signer?.proposal;
    return [
      ...(s?.summary.recipients.map((r) => r.address) ?? []),
      "tsp1q", "sp1q", '"t":"fs.', "binonces", app.cfg.pin.keyId, app.cfg.pin.accessStructureId,
    ].filter((x) => x && x.length > 4);
  };

  const onWire = (w: WireEvent) => {
    const hit = secrets().some((x) => w.content.includes(x));
    const item = {
      dir: w.dir, at: w.at, id: w.id, kind: w.kind, pubkey: w.pubkey, bytes: w.bytes,
      tags: w.tags.map((t) => t[0]).filter((t) => t !== "d"),
      snippet: w.content.slice(0, 160), plaintext: hit,
    };
    wire.push(item);
    if (wire.length > 200) wire.shift();
    broadcast("wire", item);
  };

  let pending = false;
  app.onChange(() => {
    if (pending) return;
    pending = true;
    setTimeout(() => {
      pending = false;
      broadcast("snapshot", app.snapshot());
      broadcast("log", app.logLines.slice(-1)[0]);
    }, 40);
  });

  const json = (data: unknown, status = 200) => Response.json(data, { status });
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: opts.port,
    idleTimeout: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/") return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } });
      if (url.pathname === "/events") {
        let ctl: ReadableStreamDefaultController;
        const stream = new ReadableStream({
          start(c) {
            ctl = c;
            clients.add(c);
            send(c, "hello", { network: opts.network ?? "signet" });
            send(c, "snapshot", app.snapshot());
            for (const w of wire) send(c, "wire", w);
            for (const l of app.logLines.slice(-80)) send(c, "log", l);
          },
          cancel() { clients.delete(ctl); },
        });
        req.signal.addEventListener("abort", () => clients.delete(ctl));
        return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" } });
      }
      if (url.pathname.startsWith("/api/")) {
        if (req.method !== "POST" || req.headers.get("x-vault") !== "1") return json({ error: "forbidden" }, 403);
        const body: any = await req.json().catch(() => ({}));
        try {
          switch (url.pathname) {
            case "/api/propose":
              if (!opts.actions?.propose) throw new Error("only the coordinator proposes");
              await opts.actions.propose(String(body.file ?? "proposal.json"));
              return json({ ok: true });
            case "/api/sign":
              await app.requestSignatures();
              return json({ ok: true });
            case "/api/cancel":
              await app.cancel("cancelled from dashboard");
              return json({ ok: true });
            case "/api/broadcast": {
              const tx = app.snapshot().session?.complete?.txHex;
              if (!tx) throw new Error("no signed transaction yet");
              if (!opts.actions?.broadcast) throw new Error("broadcast not available");
              const txid = await opts.actions.broadcast(tx);
              app.log(`✓ broadcast to Signet: ${txid}`);
              return json({ ok: true, txid });
            }
          }
          return json({ error: "unknown action" }, 404);
        } catch (e: any) {
          app.log(`✗ ${e?.message ?? e}`);
          return json({ error: e?.message ?? String(e) }, 400);
        }
      }
      return new Response("not found", { status: 404 });
    },
  });
  // keep proxies/browsers from closing idle SSE connections
  setInterval(() => { for (const c of clients) try { c.enqueue(enc.encode(": ping\n\n")); } catch { clients.delete(c); } }, 15000);
  return { url: `http://127.0.0.1:${server.port}`, onWire, server };
}
