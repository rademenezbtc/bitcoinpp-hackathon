// In-memory relay pool implementing marmot-ts's NostrNetworkInterface.
// Lets several Marmot clients run in one process for tests and demos,
// with no internet. Swap for a real relay pool (e.g. applesauce-relay) later.
import type { NostrEvent } from "applesauce-core/helpers/event";
import { matchFilters, type Filter } from "applesauce-core/helpers/filter";
import type {
  NostrNetworkInterface,
  PublishResponse,
  Subscribable,
} from "@internet-privacy/marmot-ts/client";

type Sub = { filters: Filter[]; next: (e: NostrEvent) => void };

export class MemRelay {
  events = new Map<string, NostrEvent>();
  subs = new Set<Sub>();
  /** Every event the relay ever saw — used by the "what the relay sees" view. */
  log: NostrEvent[] = [];

  publish(event: NostrEvent) {
    if (this.events.has(event.id)) return;
    // Replaceable / addressable handling (kind 10000-19999, 30000-39999)
    if (
      (event.kind >= 10000 && event.kind < 20000) ||
      (event.kind >= 30000 && event.kind < 40000)
    ) {
      const d = event.tags.find((t) => t[0] === "d")?.[1] ?? "";
      for (const [id, old] of this.events) {
        const oldD = old.tags.find((t) => t[0] === "d")?.[1] ?? "";
        if (old.kind === event.kind && old.pubkey === event.pubkey && oldD === d) {
          this.events.delete(id);
        }
      }
    }
    this.events.set(event.id, event);
    this.log.push(event);
    for (const s of this.subs) if (matchFilters(s.filters, event)) queueMicrotask(() => s.next(event));
  }

  query(filters: Filter[]) {
    let out = [...this.events.values()].filter((e) => matchFilters(filters, e));
    out.sort((a, b) => b.created_at - a.created_at);
    const limit = filters.length === 1 ? filters[0].limit : undefined;
    if (limit !== undefined) out = out.slice(0, limit);
    return out;
  }

  /** A NostrNetworkInterface view of this relay for one client. */
  network(url = "wss://mem.relay"): NostrNetworkInterface {
    const relay = this;
    const norm = (f: Filter | Filter[]) => (Array.isArray(f) ? f : [f]);
    return {
      async publish(relays: string[], event: NostrEvent) {
        relay.publish(event);
        const res: Record<string, PublishResponse> = {};
        for (const r of relays.length ? relays : [url]) res[r] = { from: r, ok: true };
        return res;
      },
      async request(_relays: string[], filters: Filter | Filter[]) {
        return relay.query(norm(filters));
      },
      subscription(_relays: string[], filters: Filter | Filter[]): Subscribable<NostrEvent> {
        return {
          subscribe(observer) {
            const fs = norm(filters);
            const sub: Sub = { filters: fs, next: (e) => observer.next?.(e) };
            relay.subs.add(sub);
            // replay stored events, like a relay answering REQ before EOSE
            for (const e of relay.query(fs.map((f) => ({ ...f, limit: undefined }))).reverse())
              queueMicrotask(() => sub.next(e));
            return { unsubscribe: () => relay.subs.delete(sub) };
          },
        };
      },
      async getUserInboxRelays() {
        return [url];
      },
    } as NostrNetworkInterface;
  }
}
