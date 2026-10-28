// Client side of the Relay-Witnessed Repos proposal
// (proposal-reliable-detection.md): what an installation keeps about its
// trusted witness's history. Cursors per followed account (repo revisions,
// the same at every witness, so an installation can move between
// witnesses), the monitoring frontier and coverage age for its own account,
// its own account's historical gaps (each an acknowledgeable warning), and
// gaps in pinned accounts' histories, reported in audit.

import type { Commit, Snapshot } from "./repo";
import type { Did } from "./types";

/** The liveness deadline, in hours of coverage age. */
export const LIVENESS_LIMIT = 24;

/** A permanent record of history this installation could not check.
 * `fromRev`..`toRev`: the account's repo revisions it covers, inclusive. */
export type GapRecord = {
  key: string; account: Did; fromRev: number; toRev: number; rev: number | null; reason: string;
  /** Local time it was recorded, and world time (ground truth for checks). */
  at: number; world: number;
};

export type GapWarning = GapRecord & { acked: boolean };

/** Coverage age is `base` plus monotonic time since `mono`, within one run:
 * `base` is the frontier age the witness reported (for an answer in several
 * pages, the one computed when the first page's request arrived), and
 * `mono` when the installation sent the request that produced that answer
 * (the first page's), so time in transit counts.
 * Across a restart it is the age at the last checkpoint plus the wall-clock
 * interval since; an interval that can't be established makes it unknown
 * (null), which counts as exceeding any limit until the frontier advances. */
export type Coverage = { base: number; mono: number } | null;

/** What a witness says holds an account's frontier back: a commit awaiting
 * a fetch, or a frontier more than CLOCK_SKEW ahead of its clock. */
export type FrontierFault = "fetch" | "clock" | null;

export type WitnessClientState = {
  /** account -> repo revision up to which its history was processed. */
  cursors: Map<Did, number>;
  /** account -> the reference relay's sequence number for the commit that
   * set its cursor: whether a witness's history of the account starts after
   * it. Absent where unknown (a cursor saved before this rule, or moved by an
   * entry that names no commit), and then the order can't be established. */
  cursorSeqs: Map<Did, number>;
  coverage: Coverage;
  /** Wall-clock (local) time of the last checkpoint and the coverage age
   * then; persisted so a restart can carry coverage across. */
  checkpoint: { wall: number; age: number } | null;
  /** Own account's historical gaps, each its own warning. */
  gaps: GapWarning[];
  /** Pinned accounts' gaps: intervals the client could not check. */
  auditGaps: GapRecord[];
  /** Whether the last request to the witness was answered. */
  reachable: boolean;
  /** The fault the witness last reported for the own account. */
  fault: FrontierFault;
  /** Accounts whose PDS serves a commit the witness does not yet report. */
  incomplete: Set<Did>;
};

export function emptyWitnessState(): WitnessClientState {
  return { cursors: new Map(), cursorSeqs: new Map(), coverage: null, checkpoint: null, gaps: [], auditGaps: [], reachable: true, fault: null, incomplete: new Set() };
}

export function cloneWitnessState(s: WitnessClientState): WitnessClientState {
  return {
    cursors: new Map(s.cursors), cursorSeqs: new Map(s.cursorSeqs), coverage: s.coverage && { ...s.coverage }, checkpoint: s.checkpoint && { ...s.checkpoint },
    gaps: s.gaps.map((g) => ({ ...g })), auditGaps: s.auditGaps.map((g) => ({ ...g })), reachable: s.reachable, fault: s.fault, incomplete: new Set(s.incomplete),
  };
}

/** A coverage segment, for the goal check: from world time `world` the
 * installation's coverage age was `base` plus elapsed time, and its own
 * account's history was processed through revision `cursor`. */
export type CoverageSegment = { world: number; base: number; cursor: number };

/** One entry of an account's witnessed history. A state entry holds the
 * reconstructed public repo at the commit's exact root. A gap entry covers
 * revisions `fromRev`..`toRev` the witness could not check: a published
 * commit it could not reconstruct (`fromRev` = `toRev` = `rev`), a break in
 * its subscription (`stream`), or history from before it began following
 * the account. A stream gap runs from just after the account's last
 * revision through REV_ALLOWANCE past the relay time at which the witness
 * resumed, or through `resync`, the revision it resynchronized the account
 * at, if that is higher: the relay may have carried any revision up to
 * there. Its position, where a cursor moves past it, is `resync`, so a
 * commit relayed afterward with a revision inside the interval is still
 * read; it is served to any cursor its interval reaches. The gap before
 * the witness's history of an account starts (`start`: it started following
 * late, was rebuilt, or met the account after a stream gap) is bounded the
 * same way: from the account's first revision through REV_ALLOWANCE past the
 * relay time at which it started following, or through `resync`, the
 * starting revision, if higher; its position is `resync`. It carries the
 * starting commit (`startCommit`) and the relay sequence number after which
 * the witness started following the account (`followedAfter`), for the
 * installation's starting-commit check: sequence numbers order the relay's
 * one stream exactly, where relay times are not unique. `time` and
 * `commitSeq`, where known: the relay time and sequence number of the commit
 * at the entry's position; a cursor moved there keeps the sequence number. `seq` (the relay
 * event's sequence number; for a stream gap, the first it spans), `at` (the witness's clock when it recorded the
 * entry), and `local` (the order in which it recorded its entries) are the
 * witness's own. `pos`, set on the entries a witness serves, is the
 * position a client keeps as its cursor. */
export type HistoryEntry =
  | { seq: number; at: number; local: number; pos?: number; time?: number; commitSeq?: number; kind: "state"; rev: number; snap: Snapshot; via: "commit" | "sync" | "resync" }
  | {
    seq: number; at: number; local: number; pos?: number; time?: number; commitSeq?: number; kind: "gap"; id: string; rev: number | null; fromRev: number; toRev: number; reason: string; stream: boolean;
    start?: boolean; resync?: number; startCommit?: Commit; followedAfter?: number;
  };

export type HistoryResponse = {
  /** The request this answers, echoed. */
  req?: string;
  entries: HistoryEntry[];
  /** More entries follow: a partial answer, which must not advance a frontier. */
  more: boolean;
  /** The witness's clock now minus its frontier for the account (the relay
   * time of the newest event it processed in order, or of a commit for the
   * account awaiting a fetch), as a duration; Infinity while that frontier
   * is more than CLOCK_SKEW ahead of its clock. */
  frontierAge: number;
  /** What holds the frontier back, if anything the witness can name. */
  fault: FrontierFault;
  /** The witness no longer holds the account's history up to this revision
   * (pruned past WITNESS_RETENTION): revisions after the cursor asked for,
   * up to this one, are gone. */
  truncatedTo: number | null;
  /** Integrity alarms the witness raised for the account, whatever the
   * cursor: a commit the relay published at a revision not above the
   * account's previous one. */
  integrity: IntegrityReport[];
};

/** An integrity alarm a witness raised about what the relay published:
 * relay sequence number `seq` carried revision `rev`, not above `after`. */
export type IntegrityReport = { id: string; seq: number; rev: number; after: number; reason: string };

/** What a witness knows of an account's commit at a revision: reconstructed
 * (with its root); inside a recorded gap, including a commit it did not
 * accept for its revision; strictly between two commits it reconstructed
 * consecutively, the later from a `#commit` whose `since` names the
 * earlier's revision and whose operations inverted to the earlier's root,
 * with no gap between them (`unpublished`: the relay published nothing there
 * in order); or nothing (`unknown`). */
export type CommitStatus =
  | { status: "reconstructed"; data: string } | { status: "gap" }
  | { status: "unpublished"; below: number; above: number } | { status: "unknown" };

/** What a client asks its trusted witness. Every answer carries the
 * frontier age (in `history`); `latest` is a starting point for an account
 * the client starts following. Cursors are positions in an account's
 * history: its repo revisions. */
export interface WitnessApi {
  readonly id: string;
  /** Null while no answer has arrived: the request (`req`, echoed in its
   * answer) has been sent, and the client asks again until one does. An
   * answer that arrives may be to an earlier request. */
  history(observer: string, did: Did, from: number | null, limit?: number, req?: string): HistoryResponse | null;
  commitAt(observer: string, did: Did, rev: number): CommitStatus;
  /** The latest published commit for `did`, if reconstructed, with its position. */
  latest(observer: string, did: Did): { pos: number; snap: Snapshot; time?: number; commitSeq?: number } | null;
}
