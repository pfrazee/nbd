// The Relay-Witnessed Repos proposal (proposal-reliable-detection.md), world
// side: the reference relay, a single ordered log every subscriber reads, and
// the witnesses applications run to tail it. A witness reconstructs each
// account's public repo (in this simulation the whole public repo is the
// device and approval collections) at every published commit, or records a
// permanent gap, and reports its frontier age for each account: its own
// clock minus the relay time of the newest event it has processed in order.
//
// The relay is honest unless a scenario says otherwise: it verifies commit
// signatures on ingest, refuses revisions that go backward or lie more than
// REV_ALLOWANCE ahead of its clock, may drop commits (a rate limit), stamps each
// event with the time it first sequenced it and keeps that time for every
// subscriber and on every replay (proposal: Reference relay), and delivers the
// same events to every subscriber, though possibly late to a slow one. It serves no repos (a
// non-archival relay), so `#sync` events are reconstructed by fetching from
// the PDS.

import { type Cbor, ref } from "../protocol/encoding";
import { verify } from "../protocol/crypto";
import { type Commit, type RecordPath, type Snapshot, commitUnsigned, snapshotData } from "../protocol/repo";
import type { Did } from "../protocol/types";
import type { CommitStatus, FrontierFault, HistoryEntry, HistoryResponse, IntegrityReport, WitnessApi } from "../protocol/witness";
import { revAt } from "./pds";

export type { CommitStatus, HistoryEntry, HistoryResponse, WitnessApi };

/** Hours of events the relay keeps for resumption by cursor. */
export const RELAY_REPLAY_WINDOW = 72;
/** Hours a witness retains reconstructed changes and gaps (proposed: 90 days). */
export const WITNESS_RETENTION = 90 * 24;
/** Hours a witness and the relay's clocks may differ (proposed: 5 minutes). */
export const CLOCK_SKEW = 5 / 60;
/** Hours a commit may await a fetch before it is a gap (proposed: 1 hour). */
export const FETCH_TIMEOUT = 1;
/** Hours a commit's revision may lie ahead of the relay time on its event
 * (proposed: 5 minutes, the sync specification's drift window). */
export const REV_ALLOWANCE = 5 / 60;

/** Whether a commit's revision is more than REV_ALLOWANCE ahead of relay time `time`. */
export const beyondAllowance = (rev: number, time: number): boolean => rev > revAt(time + REV_ALLOWANCE);

export type RelayOp = { path: RecordPath; prev: Cbor | null; value: Cbor | null };
/** A repository event as the relay publishes it. `time`: when the relay
 * sequenced it (on the relay's clock), the same for every subscriber
 * whenever it is delivered (unless Relay.timeOnDelivery); `prevData`: the previous tree root (null for an
 * account's first commit); `since`: the revision of the commit before it,
 * as the PDS states it (not signed: a PDS can misstate it); `ops`: the
 * operations, with the previous value of each path, for inversion. */
export type RelayEvent = {
  seq: number; time: number; kind: "commit" | "sync"; did: Did; commit: Commit; prevData: string | null; since: number | null; ops: RelayOp[];
  /** The repo key the relay verified the commit against on ingest. */
  key: Uint8Array;
};
export type Emitted = Omit<RelayEvent, "seq" | "time" | "key">;

export class Relay {
  readonly events: RelayEvent[] = [];
  private inbox: Emitted[] = [];
  private lastRev = new Map<Did, number>();
  private nextSeq = 1;
  /** Honest per-subscriber delivery delay in hours: a slow consumer whose
   * events queue at the relay while pings still arrive (see the README's
   * findings). An event sequenced at `time` reaches it at `time + delay`. */
  readonly deliveryDelay = new Map<string, number>();
  /** A relay colluding with a PDS: events for `did` are hidden from the
   * named subscribers. Out of the proposal's reach. */
  readonly hideFrom = new Map<Did, Set<string>>();
  /** An honest relay dropping commits, as under a rate limit: how many of
   * each account's next events it discards on ingest. */
  readonly drops = new Map<Did, number>();
  /** Accounts whose revisions this relay doesn't check, neither that they
   * increase nor that they are within REV_ALLOWANCE of its clock: the sync
   * specification asks it to, but a relay may not. */
  readonly unchecked = new Set<Did>();
  /** Ground truth: every commit a PDS sent, as `did:rev`, whether or not
   * the relay published it. */
  readonly received = new Set<string>();
  /** Not the reference relay: it stamps each event with the time it sends
   * it to the subscriber, not the time it first sequenced it, so a replay
   * after a resume, or a slow subscriber's backlog, carries fresh times. The
   * sync specification lets an honest relay replace an upstream time; NBD
   * forbids its reference relay to (proposal: Reference relay), since a
   * witness's frontier is read off these times. */
  timeOnDelivery = false;
  /** When each subscriber last resumed from a cursor: the relay replays
   * what it missed from then. */
  private resumedAt = new Map<string, number>();

  constructor(private readonly keyOf: (did: Did) => Uint8Array | null, private readonly clock: () => number) {}

  /** A PDS sends an event; the relay takes it in on its next ingest. */
  send(e: Emitted): void {
    this.received.add(`${e.did}:${e.commit.rev}`);
    this.inbox.push(e);
  }

  /** Drop the next `n` events for `did` on ingest (an honest rate limit). */
  dropNext(did: Did, n = 1): void {
    this.drops.set(did, (this.drops.get(did) ?? 0) + n);
  }

  /** Verify and sequence pending events. Returns how many were published. */
  ingest(): number {
    let n = 0;
    for (const e of this.inbox.splice(0)) {
      const key = this.keyOf(e.did);
      if (!key || e.commit.did !== e.did || !verify(e.commit.sig, commitUnsigned(e.commit) as unknown[], key)) continue;
      const drop = this.drops.get(e.did) ?? 0;
      if (drop > 0) {
        this.drops.set(e.did, drop - 1);
        continue;
      }
      if (!this.unchecked.has(e.did)) {
        if (e.commit.rev <= (this.lastRev.get(e.did) ?? 0)) continue; // revisions only move forward
        if (beyondAllowance(e.commit.rev, this.clock())) continue; // nor into the future
      }
      this.lastRev.set(e.did, Math.max(e.commit.rev, this.lastRev.get(e.did) ?? 0));
      this.events.push({ ...e, seq: this.nextSeq, time: this.clock(), key });
      // Sequence numbers may skip values; skips are not gaps.
      this.nextSeq += this.events.length % 4 === 3 ? 3 : 1;
      n++;
    }
    return n;
  }

  delayOf(subscriber: string): number {
    return this.deliveryDelay.get(subscriber) ?? 0;
  }

  now(): number {
    return this.clock();
  }

  /** A subscriber resumes from its cursor (or restarts after a refusal):
   * what it missed is replayed from now. */
  resume(subscriber: string): void {
    this.resumedAt.set(subscriber, this.clock());
  }

  /** Whether events carry the time they are sent rather than the time they
   * were sequenced (Relay.timeOnDelivery). */
  private refreshes(): boolean {
    return this.timeOnDelivery;
  }

  /** The `time` on `e` as `subscriber` receives it, sent by relay time
   * `by`: the reference relay's is when it first sequenced the event. */
  private stamp(e: RelayEvent, subscriber: string, by: number): number {
    if (!this.refreshes()) return e.time;
    return Math.min(by, Math.max(e.time + this.delayOf(subscriber), this.resumedAt.get(subscriber) ?? -Infinity));
  }

  /** Events after `cursor` sent to `subscriber` by relay time `by` (an
   * event sequenced at `time` is sent at `time + delay`), with the time on
   * each as the subscriber receives it. */
  delivered(subscriber: string, cursor: number, by = this.clock()): RelayEvent[] {
    return this.events
      .filter((e) => e.seq > cursor && e.time + this.delayOf(subscriber) <= by && !this.hideFrom.get(e.did)?.has(subscriber))
      .map((e) => ({ ...e, time: this.stamp(e, subscriber, by) }));
  }

  /** The time on the newest event of the rest of the network sent to
   * `subscriber` by relay time `by`. The firehose carries the whole
   * network, and this simulation's accounts are a sliver of it: the rest,
   * never idle, is sent up to `by` too, sequenced `delay` earlier. */
  networkTime(subscriber: string, by: number): number {
    return this.refreshes() ? by : by - this.delayOf(subscriber);
  }

  /** Whether resuming after `cursor` is refused as outdated: some event
   * after it has aged out of the replay window. */
  outdated(cursor: number): boolean {
    const horizon = this.clock() - RELAY_REPLAY_WINDOW;
    return this.events.some((e) => e.seq > cursor && e.time < horizon);
  }

  /** The first retained event's sequence number minus one: where a refused
   * subscriber restarts. */
  restartCursor(): number {
    const horizon = this.clock() - RELAY_REPLAY_WINDOW;
    const first = this.events.find((e) => e.time >= horizon);
    return first ? first.seq - 1 : this.headSeq();
  }

  headSeq(): number {
    return this.events.length ? this.events[this.events.length - 1].seq : 0;
  }

  /** The latest published commit for an account at or before `seq`
   * (getLatestCommit), passing `ok` if given. */
  latestCommit(did: Did, seq = Infinity, ok: (e: RelayEvent) => boolean = () => true): RelayEvent | null {
    for (let i = this.events.length - 1; i >= 0; i--) if (this.events[i].did === did && this.events[i].seq <= seq && ok(this.events[i])) return this.events[i];
    return null;
  }
}

/** A commit awaiting a fetch, and the account's events that arrived behind
 * it, which wait their turn. */
type Pending = { e: RelayEvent; via: "sync" | "resync"; seq: number; since: number; queue: RelayEvent[] };

type Gap = Extract<HistoryEntry, { kind: "gap" }>;
type State = Extract<HistoryEntry, { kind: "state" }>;

type Account = {
  state: Snapshot | null; history: HistoryEntry[];
  pending: Pending | null;
  /** A gap opened by a commit beyond REV_ALLOWANCE, whose end is not known
   * yet: closed by the account's next reconstructed commit or gap, and not
   * served until then. */
  open: Gap | null;
  /** The newest revision this witness recorded, and the newest it pruned. */
  lastRev: number; prunedThrough: number;
  /** Integrity alarms this witness raised for the account, reported with
   * every answer whatever the cursor asked from. */
  integrity: IntegrityReport[];
};

const PAGE = 50;

export class Witness implements WitnessApi {
  /** Hours added to world time to get this witness's clock. */
  clockOffset = 0;
  /** Subscription open. False is an outage; resuming after it may be refused. */
  connected = true;
  /** Clients can reach it. */
  reachable = true;
  /** Hours behind: it processes only events delivered at least this long
   * ago, so its frontier age is at least this. */
  lag = 0;
  /** Entries per page of a history answer. */
  pageSize = PAGE;
  /** A dishonest witness, colluding with a PDS: it leaves these relay
   * sequence numbers out of an account's history, reporting neither the
   * commits nor gaps. Out of the proposal's reach. */
  readonly omits = new Map<Did, Set<number>>();
  /** Its relay subscription cursor: the last relay sequence number processed. */
  cursor = 0;
  /** The relay time of the newest event it has processed in order. */
  frontier: number;
  /** Whether it holds every account's history from the relay's start: false
   * once it starts late (or is rebuilt) or a stream gap breaks its history. */
  private complete: boolean;
  /** Where its history of an account it has not met yet starts: the relay
   * time and sequence number at which it started following the relay, or
   * last resumed after a stream gap. */
  private startedAt: number;
  private startSeq: number;
  private resume = false;
  private local = 0;
  readonly accounts = new Map<Did, Account>();
  readonly streamGaps: { seq: number; toSeq: number; at: number }[] = [];
  /** Mutation hook point: later resynchronization never erases a gap. */
  private readonly eraseGapsOnResync = false;

  constructor(
    readonly id: string,
    readonly app: string,
    private readonly relay: Relay,
    private readonly fetchRepo: (witness: string, did: Did) => Snapshot | null,
    private readonly worldNow: () => number,
    opts: { late?: boolean } = {},
  ) {
    // A late (or rebuilt) witness starts following the relay now, holding no
    // history.
    this.complete = !opts.late;
    if (opts.late) this.cursor = relay.headSeq();
    this.startedAt = relay.now();
    this.startSeq = this.cursor;
    this.frontier = relay.networkTime(id, relay.now());
  }

  now(): number {
    return this.worldNow() + this.clockOffset;
  }

  setConnected(on: boolean): void {
    if (on && !this.connected) this.resume = true;
    this.connected = on;
  }

  /** Its frontier for `did`: the relay time of the newest event processed
   * in order, or, while a commit for the account awaits a fetch, that
   * commit's time. Other accounts' progress is unaffected. */
  accountFrontier(did: Did): number {
    const p = this.accounts.get(did)?.pending;
    return p ? Math.min(this.frontier, p.e.time) : this.frontier;
  }

  /** Whether `did`'s frontier is more than CLOCK_SKEW ahead of this
   * witness's clock: a fault, reported until resolved. */
  clockFault(did: Did): boolean {
    return this.accountFrontier(did) - this.now() > CLOCK_SKEW;
  }

  /** Its clock minus the account's frontier, as a duration; while the
   * frontier is ahead beyond CLOCK_SKEW, over any limit. */
  frontierAge(did: Did): number {
    if (this.clockFault(did)) return Infinity;
    return Math.max(0, this.now() - this.accountFrontier(did));
  }

  /** The account's state, created when first met. `startAt`: the commit a
   * witness lacking history starts it at, if known (null: none); otherwise
   * the relay's latest published commit for it when the witness started
   * following. */
  private account(did: Did, startAt?: RelayEvent | null): Account {
    let a = this.accounts.get(did);
    if (!a) {
      this.accounts.set(did, (a = { state: null, history: [], pending: null, open: null, lastRev: 0, prunedThrough: 0, integrity: [] }));
      // An account first met by a witness that lacks history (it started
      // late, was rebuilt, or broke its stream): what it lacks is a gap in
      // that history. Like a stream gap's, the interval can't end at the
      // starting revision: a PDS may have published an impostor and then
      // replayed an earlier revision before the witness started. It runs
      // from the account's first event through REV_ALLOWANCE past the relay
      // time the witness started following at, or through the starting
      // revision if higher; a cursor moves past it only to the starting
      // revision.
      if (!this.complete) {
        const s = startAt === undefined ? this.relay.latestCommit(did, this.startSeq, inAllowance) : startAt;
        const start = s?.commit.rev ?? 0;
        const toRev = Math.max(revAt(this.startedAt + REV_ALLOWANCE), start);
        // With the starting commit, and the relay time it started following
        // at: an installation whose cursor a commit sequenced before then set
        // checks the starting commit against it.
        this.push(a, {
          seq: this.startSeq, at: this.now(), local: 0, time: s?.time, kind: "gap", id: `${this.id}:start:${this.startSeq}:${did}`, rev: null, fromRev: 1, toRev,
          reason: "before this witness's history of the account starts", stream: false, start: true, resync: start, startCommit: s?.commit, followedFrom: this.startedAt,
        });
      }
    }
    return a;
  }

  /** An account a client asks about that this witness has not met. One
   * that holds every account's history has nothing for it; otherwise it
   * starts the account from the relay's latest published commit. */
  private meet(did: Did): Account {
    const a = this.accounts.get(did);
    if (a || this.complete) return a ?? this.account(did);
    const latest = this.relay.latestCommit(did, this.cursor, inAllowance);
    const b = this.account(did, latest);
    if (latest) this.reconstructByFetch(did, latest, "resync", latest.seq);
    return b;
  }

  /** Process what the relay has delivered. Returns how many events. */
  pump(): number {
    if (!this.connected) return 0;
    let n = 0;
    if (this.resume) {
      this.resume = false;
      this.relay.resume(this.id);
      if (this.relay.outdated(this.cursor)) {
        // The relay refuses the resume: a stream gap for every account, then
        // each known account is resynchronized at its latest published commit.
        // Even one resynchronized at the revision it already held: a relay
        // that passes on non-increasing revisions may have published an
        // impostor and then that revision again meanwhile.
        const to = this.relay.restartCursor();
        const g = { seq: this.cursor + 1, toSeq: to, at: this.now() };
        const resumedAt = this.relay.now();
        this.streamGaps.push(g);
        this.complete = false;
        this.cursor = to;
        this.startedAt = resumedAt;
        this.startSeq = to;
        for (const [did, a] of this.accounts) {
          a.state = null;
          a.pending = null;
          a.open = null;
          const latest = this.relay.latestCommit(did, to, inAllowance);
          // The relay may have carried any revision the witness would have
          // accepted meanwhile, whatever revision it resumes the account at:
          // up to REV_ALLOWANCE past the relay time it resumed at. A cursor
          // moves past the gap only to the revision it resumes at.
          const resync = latest?.commit.rev ?? a.lastRev;
          const toRev = Math.max(revAt(resumedAt + REV_ALLOWANCE), resync);
          this.push(a, { seq: g.seq, at: g.at, local: 0, time: latest?.time, kind: "gap", id: `${this.id}:stream:${g.seq}`, rev: null, fromRev: a.lastRev + 1, toRev, reason: "stream gap: the relay refused to resume", stream: true, resync });
          // Resynchronized below the revision it held: the relay published a
          // non-increasing revision meanwhile.
          if (latest && latest.commit.rev < a.lastRev)
            a.integrity.push({ id: `${this.id}:order:${latest.seq}`, seq: latest.seq, rev: latest.commit.rev, after: a.lastRev, reason: `after a stream gap the relay's latest commit is at revision ${latest.commit.rev}, below revision ${a.lastRev}` });
          if (latest) this.reconstructByFetch(did, latest, "resync", to);
        }
      }
    }
    // Retry fetches still outstanding; past FETCH_TIMEOUT each is a gap.
    for (const [did, a] of this.accounts) if (a.pending && this.retry(did, a)) n++;
    // Sent to it at least `lag` ago.
    const by = this.relay.now() - this.lag;
    let newest = -Infinity;
    for (const e of this.relay.delivered(this.id, this.cursor, by)) {
      this.process(e);
      this.cursor = e.seq;
      newest = Math.max(newest, e.time);
      n++;
    }
    // The stream is one ordered sequence, never idle: the frontier is the
    // relay time on the newest event processed, the rest of the network's
    // included. From the reference relay that is when the event was
    // sequenced, however late it arrived.
    this.frontier = Math.max(this.frontier, this.relay.networkTime(this.id, by), newest);
    this.prune();
    return n;
  }

  private process(e: RelayEvent): void {
    const a = this.account(e.did);
    if (a.pending) {
      a.pending.queue.push(e); // in order, behind the commit awaiting a fetch
      return;
    }
    // Reference relay: a revision more than REV_ALLOWANCE ahead of the
    // event's relay time is not accepted into the history. It is a gap, not
    // an alarm (a PDS clock can simply be wrong), the account's latest
    // revision stays where it was, and the next commit is one after a gap.
    if (beyondAllowance(e.commit.rev, e.time)) return this.future(a, e);
    // Cursors need revisions to increase in relay order: one that doesn't
    // is a gap and an integrity alarm.
    if (e.commit.rev <= a.lastRev) return this.backward(a, e);
    if (e.kind === "commit") {
      if (a.state) {
        // The commit must follow the state held: its previous root is that
        // state's, and its operations take that root to its own; otherwise
        // it is a gap. A commit the relay dropped in between fails here by
        // its root, unless it changed nothing or a later one cancelled it
        // out; its `since` then names a revision other than the state's,
        // which records a gap before it, though the commit itself is
        // reconstructed from its operations.
        const follows = e.since === a.state.commit.rev;
        const prev = new Map(a.state.records);
        const next = snapshotData(prev) === e.prevData ? applyOps(prev, e.ops) : null;
        const inverts = !!next && snapshotData(next) === e.commit.data && invert(next, e.ops, e.prevData);
        if (next && inverts) {
          if (!follows) this.sinceGap(a, e);
          this.record(e.did, { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "state", rev: e.commit.rev, snap: { commit: e.commit, records: next }, via: "commit" });
        } else this.gap(e.did, e, "operations fail inversion");
        return;
      }
      if (e.prevData === null && !a.history.length) {
        // The account's first commit: from the empty repo.
        const next = applyOps(new Map(), e.ops);
        if (next && snapshotData(next) === e.commit.data && invert(next, e.ops, null)) {
          this.record(e.did, { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "state", rev: e.commit.rev, snap: { commit: e.commit, records: next }, via: "commit" });
        } else this.gap(e.did, e, "operations fail inversion");
        return;
      }
      // No previous state held: reconstruct at this commit's exact root.
      this.reconstructByFetch(e.did, e, "sync", e.seq);
      return;
    }
    this.reconstructByFetch(e.did, e, "sync", e.seq);
  }

  /** A commit whose revision is beyond REV_ALLOWANCE: a gap from just after
   * the latest revision, through the next revision reconstructed (or the
   * open stream gap it falls in), without an alarm or a new latest revision. */
  private future(a: Account, e: RelayEvent): void {
    a.state = null;
    if (a.open) return;
    const gap: Gap = { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "gap", id: `${this.id}:${e.seq}`, rev: e.commit.rev, fromRev: a.lastRev + 1, toRev: Infinity, reason: "its revision is more than REV_ALLOWANCE ahead of its relay time", stream: false };
    this.push(a, gap);
    a.open = gap;
  }

  /** A commit whose revision is not above the account's latest: a gap at
   * that revision, and an integrity alarm. The gap lies at or below the
   * cursor of anyone already past it, so the alarm is reported apart from
   * the history, with every answer. */
  private backward(a: Account, e: RelayEvent): void {
    a.state = null;
    this.push(a, { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "gap", id: `${this.id}:${e.seq}`, rev: e.commit.rev, fromRev: e.commit.rev, toRev: e.commit.rev, reason: "its revision is not above the account's previous one", stream: false });
    a.integrity.push({ id: `${this.id}:order:${e.seq}`, seq: e.seq, rev: e.commit.rev, after: a.lastRev, reason: `the relay published revision ${e.commit.rev} after revision ${a.lastRev}` });
  }

  /** Fetch the repo and accept it only at `e`'s exact root. A fetch that
   * isn't answered leaves the commit awaiting a fetch, retried until
   * FETCH_TIMEOUT. */
  private reconstructByFetch(did: Did, e: RelayEvent, via: "sync" | "resync", seq: number): void {
    const s = this.fetchRepo(this.id, did);
    if (!s) {
      this.account(did).pending = { e, via, seq, since: this.now(), queue: [] };
      return;
    }
    this.fetched(did, e, via, seq, s);
  }

  private fetched(did: Did, e: RelayEvent, via: "sync" | "resync", seq: number, s: Snapshot): void {
    if (s.commit.rev === e.commit.rev && s.commit.data === e.commit.data && snapshotData(s.records) === e.commit.data) {
      if (this.eraseGapsOnResync) {
        const a = this.account(did);
        a.history = a.history.filter((h) => h.kind !== "gap");
      }
      this.record(did, { seq, at: this.now(), local: 0, time: e.time, kind: "state", rev: e.commit.rev, snap: { commit: e.commit, records: new Map(s.records) }, via });
    } else this.gap(did, e, `the repo served was not at revision ${e.commit.rev}'s root`);
  }

  /** Retry an outstanding fetch. Returns whether it was resolved, and then
   * processes the events that waited behind it. */
  private retry(did: Did, a: Account): boolean {
    const p = a.pending!;
    const s = this.fetchRepo(this.id, did);
    if (!s && this.now() - p.since < FETCH_TIMEOUT) return false;
    a.pending = null;
    if (s) this.fetched(did, p.e, p.via, p.seq, s);
    else this.gap(did, p.e, "the repo was not served within FETCH_TIMEOUT");
    for (const q of p.queue) this.process(q);
    return true;
  }

  private push(a: Account, entry: HistoryEntry): void {
    entry.local = ++this.local;
    a.history.push(entry);
  }

  /** Close the open gap a commit beyond REV_ALLOWANCE began at revision
   * `rev`, the next the witness records. Revisions increase but are not
   * consecutive (atproto revisions are timestamps): the gap runs through
   * `rev`. */
  private close(a: Account, rev: number): void {
    if (a.open) a.open.toRev = rev;
    a.open = null;
  }

  private record(did: Did, entry: State): void {
    const a = this.account(did);
    this.close(a, entry.rev);
    a.state = entry.snap;
    a.lastRev = Math.max(a.lastRev, entry.rev);
    this.push(a, entry);
  }

  /** A published commit not reconstructed: a gap from just after the
   * latest revision recorded through the commit's own, since a commit the
   * relay dropped before it may lie anywhere in between. */
  private gap(did: Did, e: RelayEvent, reason: string): void {
    const a = this.account(did);
    this.close(a, e.commit.rev);
    a.state = null;
    const fromRev = Math.min(a.lastRev + 1, e.commit.rev);
    a.lastRev = Math.max(a.lastRev, e.commit.rev);
    this.push(a, { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "gap", id: `${this.id}:${e.seq}`, rev: e.commit.rev, fromRev, toRev: e.commit.rev, reason, stream: false });
  }

  /** A `#commit` whose `since` names a revision other than the last one
   * recorded: commits the relay did not publish in order (dropped by an
   * honest relay, perhaps, even ones that change nothing or cancel out) may
   * lie between, a gap before it. */
  private sinceGap(a: Account, e: RelayEvent): void {
    this.push(a, { seq: e.seq, at: this.now(), local: 0, time: e.time, kind: "gap", id: `${this.id}:since:${e.seq}`, rev: null, fromRev: a.lastRev + 1, toRev: e.commit.rev - 1, reason: `its since names revision ${e.since}, not the previous revision ${a.lastRev}`, stream: false });
  }

  /** Drop entries older than WITNESS_RETENTION, remembering the newest
   * revision dropped. */
  private prune(): void {
    const horizon = this.now() - WITNESS_RETENTION;
    for (const a of this.accounts.values()) {
      // Keep the latest state as a starting point even if old.
      const last = a.history[a.history.length - 1];
      a.history = a.history.filter((h) => {
        if (h.at >= horizon || h === last || h === a.open) return true;
        a.prunedThrough = Math.max(a.prunedThrough, this.position(h));
        return false;
      });
    }
  }

  /** An entry's position in the account's history, which clients keep as
   * their cursor: the account's repo revision (the last an interval
   * covers), the same at every witness. */
  private position(h: HistoryEntry): number {
    if (h.kind === "gap" && h.stream && h.resync !== undefined) return h.resync; // past a stream gap, only to where it resumed
    if (h.kind === "gap" && h.start) return h.resync ?? 0; // past where history starts, only to the starting revision
    return h.kind === "state" ? h.rev : h.toRev; // a repo revision
  }

  history(_observer: string, did: Did, from: number | null, limit = this.pageSize, req?: string): HistoryResponse {
    const a = this.meet(did);
    const start = from ?? 0;
    const all = a.history
      .filter((h) => h !== a.open && (h.kind === "state" || h.fromRev <= h.toRev) && this.served(h, start) && !this.omits.get(did)?.has(h.seq))
      .sort((x, y) => x.local - y.local);
    const entries = all.slice(0, limit).map((h) => ({ ...h, pos: this.position(h) }));
    const fault: FrontierFault = this.clockFault(did) ? "clock" : a.pending ? "fetch" : null;
    const integrity = a.integrity.filter((x) => !this.omits.get(did)?.has(x.seq));
    return { req, entries, more: all.length > limit, frontierAge: this.frontierAge(did), fault, truncatedTo: a.prunedThrough > start ? a.prunedThrough : null, integrity };
  }

  /** Whether an entry is served to a cursor at `start`: one after it, or a
   * stream gap or the gap before the witness's history starts whose interval
   * reaches it. Such a gap resumed or started at the revision the cursor
   * holds lies at that cursor, not after it, yet covers what the relay may
   * have published since the client last read. */
  private served(h: HistoryEntry, start: number): boolean {
    return this.position(h) > start
      || (h.kind === "gap" && h.stream && h.toRev >= start)
      || (h.kind === "gap" && !!h.start && h.toRev >= start);
  }

  commitAt(_observer: string, did: Did, rev: number): CommitStatus {
    const a = this.meet(did);
    const es = a.history.filter((h) => !this.omits.get(did)?.has(h.seq)).sort((x, y) => x.local - y.local);
    for (let i = es.length - 1; i >= 0; i--) {
      const h = es[i];
      if (h.rev !== rev) continue;
      return h.kind === "state" ? { status: "reconstructed", data: h.snap.commit.data } : { status: "gap" };
    }
    // Inside a recorded gap: part of what the witness reports it could not check.
    if (es.some((h) => h.kind === "gap" && h !== a.open && h.fromRev <= rev && rev <= h.toRev)) return { status: "gap" };
    // Strictly between two commits reconstructed consecutively, the later
    // a #commit whose since names the earlier's revision and whose
    // operations invert to the earlier's root (process() records such a
    // commit "via commit", and any other as a gap), with no gap recorded
    // between them: the relay published nothing there.
    for (let i = 0; i + 1 < es.length; i++) {
      const lo = es[i], hi = es[i + 1];
      if (lo.kind === "state" && hi.kind === "state" && hi.via === "commit" && lo.rev < rev && rev < hi.rev)
        return { status: "unpublished", below: lo.rev, above: hi.rev };
    }
    return { status: "unknown" };
  }

  latest(_observer: string, did: Did): { pos: number; snap: Snapshot; time?: number } | null {
    const a = this.meet(did);
    const last = a.history[a.history.length - 1];
    // The latest published commit must itself be reconstructed, with nothing
    // after it awaiting a fetch or an unresolved stream gap.
    if (!last || last.kind !== "state" || !a.state || a.pending || a.open) return null;
    return { pos: this.position(last), snap: last.snap, time: last.time };
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

  history(observer: string, did: Did, from: number | null): HistoryResponse {
    const s = this.serve(observer, did);
    const rev = s?.commit.rev ?? 0;
    return {
      entries: s && rev > (from ?? 0) ? [{ seq: 1e9 + rev, at: 0, local: 0, pos: rev, kind: "state", rev, snap: s, via: "sync" }] : [],
      more: false, frontierAge: 0, fault: null, truncatedTo: null, integrity: [],
    };
  }

  commitAt(observer: string, did: Did, rev: number): CommitStatus {
    const s = this.serve(observer, did);
    return s && s.commit.rev === rev ? { status: "reconstructed", data: s.commit.data } : { status: "unknown" };
  }

  latest(observer: string, did: Did): { pos: number; snap: Snapshot } | null {
    const s = this.serve(observer, did);
    return s ? { pos: s.commit.rev, snap: s } : null;
  }
}

/** A commit within REV_ALLOWANCE of its relay time: where a witness may
 * restart an account. */
const inAllowance = (e: RelayEvent): boolean => !beyondAllowance(e.commit.rev, e.time);

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
