// marmot-ts NostrNetworkInterface over real relays (applesauce-relay RelayPool).
import { RelayPool } from "applesauce-relay";
import { lastValueFrom, toArray, timeout, catchError, of, retry, timer, config as rxConfig } from "rxjs";
import type { NostrEvent } from "applesauce-core/helpers/event";
import type { Filter } from "applesauce-core/helpers/filter";
import type { NostrNetworkInterface, PublishResponse, Subscribable } from "@internet-privacy/marmot-ts/client";

export function relayNetwork(relays: string[], signer: any, log = console.log): NostrNetworkInterface {
  // A relay outage must never crash the app (e.g. venue Wi-Fi drops): log instead of throwing.
  rxConfig.onUnhandledError = (e: any) => log(`relay error: ${e?.message ?? e}`);
  // NIP-42: some relays only serve gift wraps (1059) to authenticated users.
  const onAuthRequired = async ({ relay }: any) => {
    await relay.authenticate(signer);
  };
  const pool = new RelayPool({ onAuthRequired } as any);
  const arr = (f: Filter | Filter[]) => (Array.isArray(f) ? f : [f]);
  const use = (r: string[]) => (r.length ? r : relays);

  return {
    async publish(rs: string[], event: NostrEvent) {
      const out: Record<string, PublishResponse> = {};
      // The pool normalizes URLs (e.g. adds a trailing "/"); marmot-ts looks acks
      // up by the exact strings it asked for, so map responses back to those.
      const norm = (u: string) => u.trim().toLowerCase().replace(/\/+$/, "");
      try {
        const res = await pool.publish(use(rs), event as any, { onAuthRequired } as any);
        for (const u of use(rs)) {
          const r = res.find((x) => norm(x.from) === norm(u));
          out[u] = r ? { from: u, ok: r.ok, message: r.message } : { from: u, ok: false, message: "no response", uncertain: true };
        }
      } catch (e: any) {
        log(`publish failed: ${e?.message ?? e}`);
        for (const r of use(rs)) out[r] = { from: r, ok: false, message: String(e?.message ?? e), uncertain: true };
      }
      const ok = Object.values(out).filter((x) => x.ok).length;
      if (!ok) log(`⚠ kind ${event.kind} accepted by 0 relays: ${JSON.stringify(out)}`);
      return out;
    },
    async request(rs: string[], filters: Filter | Filter[]) {
      return lastValueFrom(
        pool.request(use(rs), arr(filters) as any, { onAuthRequired } as any).pipe(
          timeout(15_000),
          catchError(() => of()),
          toArray(),
        ),
      ) as Promise<NostrEvent[]>;
    },
    subscription(rs: string[], filters: Filter | Filter[]): Subscribable<NostrEvent> {
      // Keep subscriptions alive across outages: resubscribe every 5 s until relays are back.
      return pool.subscription(use(rs), arr(filters) as any, { onAuthRequired } as any).pipe(
        retry({ delay: (e: any) => { log(`relays unreachable (${e?.message ?? e}) — retrying in 5 s`); return timer(5000); } }),
      ) as any;
    },
    async getUserInboxRelays() {
      return relays;
    },
  } as NostrNetworkInterface;
}
