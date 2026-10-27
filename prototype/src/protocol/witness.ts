// Client side of the Relay-Witnessed Repos proposal
// (proposal-reliable-detection.md): what an installation keeps about its
// trusted witness's history. Cursors per followed account, the monitoring
// frontier and coverage age for its own account, its own account's
// historical gaps (each an acknowledgeable warning), and gaps in pinned
// accounts' histories, reported in audit.

import type { Snapshot } from "./repo";
import type { Did } from "./types";

/** The liveness deadline, in hours of coverage age. */
export const LIVENESS_LIMIT = 24;

/** A permanent record of history this installation could not check.
 * `fromSeq`..`toSeq`: the relay sequence numbers it covers. */
export type GapRecord = {
  key: string; account: Did; fromSeq: number; toSeq: number; rev: number | null; reason: string;
  /** Local time it was recorded, and world time (ground truth for checks). */
  at: number; world: number;
};

export type GapWarning = GapRecord & { acked: boolean };

/** Coverage age is `base` plus monotonic time since `mono`, within one run.
 * Across a restart it is the age at the last checkpoint plus the wall-clock
 * interval since; an interval that can't be established makes it unknown
 * (null), which counts as exceeding any limit until the frontier advances. */
export type Coverage = { base: number; mono: number } | null;

export type WitnessClientState = {
  /** account -> witness sequence up to which its history was processed. */
  cursors: Map<Did, number>;
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
  /** Accounts whose PDS serves a commit the witness does not yet report. */
  incomplete: Set<Did>;
};

export function emptyWitnessState(): WitnessClientState {
  return { cursors: new Map(), coverage: null, checkpoint: null, gaps: [], auditGaps: [], reachable: true, incomplete: new Set() };
}

export function cloneWitnessState(s: WitnessClientState): WitnessClientState {
  return {
    cursors: new Map(s.cursors), coverage: s.coverage && { ...s.coverage }, checkpoint: s.checkpoint && { ...s.checkpoint },
    gaps: s.gaps.map((g) => ({ ...g })), auditGaps: s.auditGaps.map((g) => ({ ...g })), reachable: s.reachable, incomplete: new Set(s.incomplete),
  };
}

/** A coverage segment, for the goal check: from world time `world` the
 * installation's coverage age was `base` plus elapsed time, and its own
 * account's history was processed through `cursor`. */
export type CoverageSegment = { world: number; base: number; cursor: number };

/** One entry of an account's witnessed history. A state entry holds the
 * reconstructed public repo at the commit's exact root; a gap entry is a
 * published commit the witness could not reconstruct, or (with `stream`) a
 * break in its subscription covering seqs `seq`..`toSeq` for every account. */
export type HistoryEntry =
  | { seq: number; at: number; kind: "state"; rev: number; snap: Snapshot; via: "commit" | "sync" | "resync" }
  | { seq: number; at: number; kind: "gap"; rev: number | null; reason: string; toSeq: number; stream: boolean };

export type HistoryResponse = {
  entries: HistoryEntry[];
  /** More entries follow: a partial answer, which must not advance a frontier. */
  more: boolean;
  /** Time since the witness was last live, on its own clock. */
  frontierAge: number;
  /** Where to resume. */
  head: number;
  /** The cursor asked for is older than the retained history: entries in
   * (cursor, truncatedTo] are gone. */
  truncatedTo: number | null;
};

export type CommitStatus = { status: "reconstructed"; data: string; seq: number } | { status: "gap"; seq: number } | { status: "unknown" };

/** What a client asks its trusted witness. Every answer carries the
 * frontier age (in `history`); `latest` is a starting point for an account
 * the client starts following. */
export interface WitnessApi {
  readonly id: string;
  history(observer: string, did: Did, from: number | null, limit?: number): HistoryResponse;
  commitAt(observer: string, did: Did, rev: number): CommitStatus;
  /** The latest published commit for `did`, if reconstructed. */
  latest(observer: string, did: Did): { seq: number; snap: Snapshot } | null;
}

