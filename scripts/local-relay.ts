#!/usr/bin/env bun
// Tiny in-memory Nostr relay (NIP-01 EVENT/REQ/CLOSE) for local rehearsals.
//   bun scripts/local-relay.ts [port]      → ws://localhost:7777
// Not for production: no persistence, no auth, no rate limits.
import { matchFilters } from "applesauce-core/helpers/filter";
import { verifyEvent } from "nostr-tools/pure";

const port = Number(process.argv[2] ?? 7777);
const events: any[] = [];
const subs = new Map<any, Map<string, any[]>>();

Bun.serve({
  port,
  hostname: "0.0.0.0",
  fetch(req, server) {
    if (server.upgrade(req)) return;
    return new Response("nostr relay");
  },
  websocket: {
    open(ws) { subs.set(ws, new Map()); },
    close(ws) { subs.delete(ws); },
    message(ws, raw) {
      let msg: any;
      try { msg = JSON.parse(String(raw)); } catch { return; }
      const [type, ...rest] = msg;
      if (type === "EVENT") {
        const ev = rest[0];
        if (!verifyEvent(ev)) return ws.send(JSON.stringify(["OK", ev?.id, false, "invalid: bad signature"]));
        if (!events.some((e) => e.id === ev.id)) {
          if ((ev.kind >= 10000 && ev.kind < 20000) || (ev.kind >= 30000 && ev.kind < 40000)) {
            const d = ev.tags.find((t: string[]) => t[0] === "d")?.[1] ?? "";
            for (let i = events.length - 1; i >= 0; i--) {
              const o = events[i];
              if (o.kind === ev.kind && o.pubkey === ev.pubkey && (o.tags.find((t: string[]) => t[0] === "d")?.[1] ?? "") === d) events.splice(i, 1);
            }
          }
          events.push(ev);
          for (const [sock, m] of subs) for (const [id, fs] of m) if (matchFilters(fs, ev)) sock.send(JSON.stringify(["EVENT", id, ev]));
        }
        ws.send(JSON.stringify(["OK", ev.id, true, ""]));
      } else if (type === "REQ") {
        const [id, ...filters] = rest;
        subs.get(ws)!.set(id, filters);
        let out = events.filter((e) => matchFilters(filters, e)).sort((a, b) => b.created_at - a.created_at);
        const limit = filters.length === 1 ? filters[0].limit : undefined;
        if (limit !== undefined) out = out.slice(0, limit);
        for (const e of out.reverse()) ws.send(JSON.stringify(["EVENT", id, e]));
        ws.send(JSON.stringify(["EOSE", id]));
      } else if (type === "CLOSE") {
        subs.get(ws)?.delete(rest[0]);
      }
    },
  },
});
console.log(`relay listening on ws://0.0.0.0:${port}`);
