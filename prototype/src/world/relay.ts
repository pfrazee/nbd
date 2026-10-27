// The Relay-Witnessed Repos proposal (proposal-reliable-detection.md), world
// side: the reference relay, a single ordered log every subscriber reads, and
// the witnesses applications run to tail it. A witness reconstructs each
// account's public repo (in this simulation the whole public repo is the
// device and approval collections) at every published commit, or records a
// permanent gap, and reports its frontier age on its own clock.
//
// The relay is honest unless a scenario says otherwise: it verifies commit
// signatures on ingest, refuses revisions that go backward, and delivers the
// same events to every subscriber. It serves no repos (a non-archival relay),
// so `#sync` events are reconstructed by fetching from the PDS.

import { type Cbor, ref } from "../protocol/encoding";
import { verify } from "../protocol/crypto";
import { type Commit, type RecordPath, type Snapshot, commitUnsigned, snapshotData } from "../protocol/repo";
import type { Did } from "../protocol/types";
import type { CommitStatus, HistoryEntry, HistoryResponse, WitnessApi } from "../protocol/witness";

export type { CommitStatus, HistoryEntry, HistoryResponse, WitnessApi };

/** Hours of events the relay keeps for resumption by cursor. */
export const RELAY_REPLAY_WINDOW = 72;
/** Hours a witness retains reconstructed changes and gaps (proposed: 90 days). */
export const WITNESS_RETENTION = 90 * 24;

export type RelayOp = { path: RecordPath; prev: Cbor | null; value: Cbor | null };
/** A repository event as the relay publishes it. `prevData`: the previous
 * tree root (null for an account's first commit); `ops`: the operations,
 * with the previous value of each path, for inversion. */
export type RelayEvent = {
  seq: number; t: number; kind: "commit" | "sync"; did: Did; commit: Commit; prevData: string | null; ops: RelayOp[];
  /** The repo key the relay verified the commit against on ingest. */
  key: Uint8Array;
};
export type Emitted = Omit<RelayEvent, "seq" | "t" | "key">;

export class Relay {
  readonly events: RelayEvent[] = [];
  private inbox: Emitted[] = [];
  private lastRev = new Map<Did, number>();
  private nextSeq = 1;
  /** Honest per-subscriber delivery delay in hours: a slow consumer whose
   * events queue at the relay while pings still arrive (see the README's
   * findings). */
  readonly deliveryDelay = new Map<string, number>();
  /** A relay colluding with a PDS: events for `did` are hidden from the
   * named subscribers. Out of the proposal's reach. */
  readonly hideFrom = new Map<Did, Set<string>>();

  constructor(private readonly keyOf: (did: Did) => Uint8Array | null, private readonly clock: () => number) {}

  /** A PDS sends an event; the relay takes it in on its next ingest. */
  send(e: Emitted): void {
    this.inbox.push(e);
  }

  /** Verify and sequence pending events. Returns how many were published. */
  ingest(): number {
    let n = 0;
    for (const e of this.inbox.splice(0)) {
      const key = this.keyOf(e.did);
      if (!key || e.commit.did !== e.did || !verify(e.commit.sig, commitUnsigned(e.commit) as unknown[], key)) continue;
      if (e.commit.rev <= (this.lastRev.get(e.did) ?? 0)) continue; // revisions only move forward
      this.lastRev.set(e.did, e.commit.rev);
      this.events.push({ ...e, seq: this.nextSeq, t: this.clock(), key });
      // Sequence numbers may skip values; skips are not gaps.
      this.nextSeq += this.events.length % 4 === 3 ? 3 : 1;
      n++;
    }
    return n;
  }

  /** Events after `cursor` that `subscriber` has been delivered by now. */
  delivered(subscriber: string, cursor: number): RelayEvent[] {
    const by = this.clock() - (this.deliveryDelay.get(subscriber) ?? 0);
    return this.events.filter((e) => e.seq > cursor && e.t <= by && !this.hideFrom.get(e.did)?.has(subscriber));
  }

  /** Whether resuming after `cursor` is refused as outdated: some event
   * after it has aged out of the replay window. */
  outdated(cursor: number): boolean {
    const horizon = this.clock() - RELAY_REPLAY_WINDOW;
    return this.events.some((e) => e.seq > cursor && e.t < horizon);
  }

  /** The first retained event's sequence number minus one: where a refused
   * subscriber restarts. */
  restartCursor(): number {
    const horizon = this.clock() - RELAY_REPLAY_WINDOW;
    const first = this.events.find((e) => e.t >= horizon);
    return first ? first.seq - 1 : this.headSeq();
  }

  headSeq(): number {
    return this.events.length ? this.events[this.events.length - 1].seq : 0;
  }

  /** The latest published commit for an account (getLatestCommit). */
  latestCommit(did: Did): RelayEvent | null {
    for (let i = this.events.length - 1; i >= 0; i--) if (this.events[i].did === did) return this.events[i];
    return null;
  }
}

type Account = { state: Snapshot | null; history: HistoryEntry[] };

const PAGE = 50;

export class Witness implements WitnessApi {
  /** Hours added to world time to get this witness's clock. */
  clockOffset = 0;
  /** Subscription open. False is an outage; resuming after it may be refused. */
  connected = true;
  /** Clients can reach it. */
  reachable = true;
  /** Hours behind: it processes only events delivered at least this long
   * ago, so it is not live and its frontier age is at least this. */
  lag = 0;
  /** A dishonest witness, colluding with a PDS: it leaves these relay
   * sequence numbers out of an account's history, reporting neither the
   * commits nor gaps. Out of the proposal's reach. */
  readonly omits = new Map<Did, Set<number>>();
  cursor = 0;
  /** Witness-clock time it was last live. */
  private lastLive: number;
  private resume = false;
  readonly accounts = new Map<Did, Account>();
  readonly streamGaps: HistoryEntry[] = [];
  /** Processed events' (seq, witness time), for retention. */
  private processed: { seq: number; at: number }[] = [];
  /** Mutation hook point: later resynchronization never erases a gap. */
  private readonly eraseGapsOnResync = false;

  constructor(
    readonly id: string,
    readonly app: string,
    private readonly relay: Relay,
    private readonly fetchRepo: (witness: string, did: Did) => Snapshot | null,
    private readonly worldNow: () => number,
  ) {
    this.lastLive = this.now();
  }

  now(): number {
    return this.worldNow() + this.clockOffset;
  }

  setConnected(on: boolean): void {
    if (on && !this.connected) this.resume = true;
    this.connected = on;
  }

  frontierAge(): number {
    return Math.max(0, this.now() - this.lastLive);
  }

  private account(did: Did): Account {
    let a = this.accounts.get(did);
    if (!a) this.accounts.set(did, (a = { state: null, history: [] }));
    return a;
  }

  /** Process what the relay has delivered. Returns how many events. */
  pump(): number {
    if (!this.connected) return 0;
    if (this.resume) {
      this.resume = false;
      if (this.relay.outdated(this.cursor)) {
        // The relay refuses the resume: a stream gap for every account, then
        // each known account is resynchronized at its latest published commit.
        const to = this.relay.restartCursor();
        const gap: HistoryEntry = { seq: this.cursor + 1, at: this.now(), kind: "gap", rev: null, reason: "stream gap: the relay refused to resume", toSeq: to, stream: true };
        this.streamGaps.push(gap);
        this.cursor = to;
        for (const [did, a] of this.accounts) {
          a.state = null;
          const latest = this.relay.latestCommit(did);
          if (latest && latest.seq <= to) this.reconstructByFetch(did, latest, "resync", to);
        }
      }
    }
    const by = this.worldNow() - this.lag;
    let n = 0;
    for (const e of this.relay.delivered(this.id, this.cursor)) {
      if (e.t > by) break;
      this.process(e);
      this.cursor = e.seq;
      n++;
    }
    // Live: subscription open, frames arriving, everything delivered processed.
    this.lastLive = this.now() - this.lag;
    this.prune();
    return n;
  }

  private process(e: RelayEvent): void {
    this.processed.push({ seq: e.seq, at: this.now() });
    const a = this.account(e.did);
    if (e.kind === "commit") {
      const prev = a.state ? new Map(a.state.records) : e.prevData === null && !a.history.length ? new Map<RecordPath, Cbor>() : null;
      if (prev && (e.prevData === null ? prev.size === 0 : snapshotData(prev) === e.prevData)) {
        const next = applyOps(prev, e.ops);
        if (next && snapshotData(next) === e.commit.data && invert(next, e.ops, e.prevData)) {
          this.record(e.did, { seq: e.seq, at: this.now(), kind: "state", rev: e.commit.rev, snap: { commit: e.commit, records: next }, via: "commit" });
        } else this.gap(e.did, e, "operations fail inversion");
        return;
      }
      // No usable previous state: reconstruct at this commit's exact root.
      this.reconstructByFetch(e.did, e, "sync", e.seq);
      return;
    }
    this.reconstructByFetch(e.did, e, "sync", e.seq);
  }

  /** Fetch the repo and accept it only at `e`'s exact root. */
  private reconstructByFetch(did: Did, e: RelayEvent, via: "sync" | "resync", seq: number): void {
    const s = this.fetchRepo(this.id, did);
    if (s && s.commit.rev === e.commit.rev && s.commit.data === e.commit.data && snapshotData(s.records) === e.commit.data) {
      if (this.eraseGapsOnResync) {
        const a = this.account(did);
        a.history = a.history.filter((h) => h.kind !== "gap");
      }
      this.record(did, { seq, at: this.now(), kind: "state", rev: e.commit.rev, snap: { commit: e.commit, records: new Map(s.records) }, via });
    } else this.gap(did, e, s ? `the repo served was not at revision ${e.commit.rev}'s root` : "the repo was not served");
  }

  private record(did: Did, entry: Extract<HistoryEntry, { kind: "state" }>): void {
    const a = this.account(did);
    a.state = entry.snap;
    a.history.push(entry);
  }

  private gap(did: Did, e: RelayEvent, reason: string): void {
    const a = this.account(did);
    a.state = null;
    a.history.push({ seq: e.seq, at: this.now(), kind: "gap", rev: e.commit.rev, reason, toSeq: e.seq, stream: false });
  }

  /** Drop entries older than WITNESS_RETENTION. */
  private prune(): void {
    const horizon = this.now() - WITNESS_RETENTION;
    for (const a of this.accounts.values()) {
      // Keep the latest state as a starting point even if old.
      const last = a.history[a.history.length - 1];
      a.history = a.history.filter((h) => h.at >= horizon || h === last);
    }
  }

  /** The largest processed seq older than retention: history at or before
   * it is gone. */
  private horizonSeq(): number {
    const horizon = this.now() - WITNESS_RETENTION;
    let out = 0;
    for (const p of this.processed) if (p.at < horizon) out = p.seq;
    else break;
    return out;
  }

  history(_observer: string, did: Did, from: number | null, limit = PAGE): HistoryResponse {
    const a = this.account(did);
    const start = from ?? 0;
    const horizon = this.horizonSeq();
    const all = [...a.history, ...this.streamGaps]
      .filter((h) => h.seq > start || (h.kind === "gap" && h.toSeq > start && h.stream))
      .filter((h, i, xs) => xs.indexOf(h) === i && !this.omits.get(did)?.has(h.seq))
      .sort((x, y) => x.seq - y.seq);
    const entries = all.slice(0, limit);
    const more = all.length > limit;
    return {
      entries,
      more,
      frontierAge: this.frontierAge(),
      head: more ? entries[entries.length - 1].seq : this.cursor,
      truncatedTo: from !== null && from < horizon ? horizon : null,
    };
  }

  commitAt(_observer: string, did: Did, rev: number): CommitStatus {
    const a = this.account(did);
    for (let i = a.history.length - 1; i >= 0; i--) {
      const h = a.history[i];
      if (h.rev !== rev || this.omits.get(did)?.has(h.seq)) continue;
      return h.kind === "state" ? { status: "reconstructed", data: h.snap.commit.data, seq: h.seq } : { status: "gap", seq: h.seq };
    }
    return { status: "unknown" };
  }

  latest(_observer: string, did: Did): { seq: number; snap: Snapshot } | null {
    const a = this.accounts.get(did);
    const last = a?.history[a.history.length - 1];
    // The latest published commit must itself be reconstructed.
    if (!a || !last || last.kind !== "state" || !a.state) return null;
    const stream = this.streamGaps.some((g) => g.kind === "gap" && g.toSeq >= last.seq && g.seq > last.seq);
    if (stream) return null;
    return { seq: Math.max(last.seq, this.cursor), snap: last.snap };
  }

  /** Every device ID in any state this witness reconstructed for `did`
   * (ground truth for the goal check). */
  devicesSeen(did: Did): Set<string> {
    const out = new Set<string>();
    for (const h of this.accounts.get(did)?.history ?? [])
      if (h.kind === "state") for (const k of h.snap.records.keys()) if (k.includes(".device/")) out.add(k.split("/")[1]);
    return out;
  }
}

/** A "witness" run by a malicious PDS: it reports whatever the PDS serves
 * the asking client as published and current. Clients must not trust it
 * (proposal: Trusted witnesses); it exists so a mutation that does can be
 * caught. */
export class RogueWitness implements WitnessApi {
  constructor(readonly id: string, private readonly serve: (observer: string, did: Did) => Snapshot | null) {}

  history(observer: string, did: Did): HistoryResponse {
    const s = this.serve(observer, did);
    const seq = 1e9 + (s?.commit.rev ?? 0);
    return {
      entries: s ? [{ seq, at: 0, kind: "state", rev: s.commit.rev, snap: s, via: "sync" }] : [],
      more: false, frontierAge: 0, head: seq, truncatedTo: null,
    };
  }

  commitAt(observer: string, did: Did, rev: number): CommitStatus {
    const s = this.serve(observer, did);
    return s && s.commit.rev === rev ? { status: "reconstructed", data: s.commit.data, seq: 1e9 + rev } : { status: "unknown" };
  }

  latest(observer: string, did: Did): { seq: number; snap: Snapshot } | null {
    const s = this.serve(observer, did);
    return s ? { seq: 1e9 + s.commit.rev, snap: s } : null;
  }
}

/** Apply operations, checking each path's previous value. */
function applyOps(prev: Map<RecordPath, Cbor>, ops: RelayOp[]): Map<RecordPath, Cbor> | null {
  const next = new Map(prev);
  for (const op of ops) {
    const cur = next.get(op.path) ?? null;
    if ((cur === null) !== (op.prev === null) || (cur !== null && ref(cur) !== ref(op.prev!))) return null;
    if (op.value === null) next.delete(op.path);
    else next.set(op.path, op.value);
  }
  return next;
}

/** Inversion: the reversed operations must produce the previous root. */
function invert(next: Map<RecordPath, Cbor>, ops: RelayOp[], prevData: string | null): boolean {
  const back = new Map(next);
  for (const op of [...ops].reverse()) {
    if (op.prev === null) back.delete(op.path);
    else back.set(op.path, op.prev);
  }
  return prevData === null ? back.size === 0 : snapshotData(back) === prevData;
}
