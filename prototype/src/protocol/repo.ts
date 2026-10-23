// Repo observations (device-enrollment.md#repo-observations), simplified: a
// snapshot is a full record map at a signed commit, so verifying the commit
// proves both presence and absence.

import { type Cbor, ref } from "./encoding";
import { verify } from "./crypto";
import type { Did } from "./types";

export type RecordPath = string; // `${collection}/${rkey}`
export type Commit = { did: Did; repo: string; rev: number; data: string; sig: Uint8Array };
export type Snapshot = { commit: Commit; records: ReadonlyMap<RecordPath, Cbor> };
export type WriteOp =
  | { action: "create"; collection: string; rkey: string; value: Cbor }
  | { action: "delete"; collection: string; rkey: string };

export function snapshotData(records: ReadonlyMap<RecordPath, Cbor>): string {
  const sorted = [...records.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return ref(sorted.map(([k, v]) => [k, v]));
}

export function commitUnsigned(c: Omit<Commit, "sig">): Cbor {
  return ["atproto/commit", { did: c.did, repo: c.repo, rev: c.rev, data: c.data }];
}

// Snapshots are immutable, so a verification result can be reused for the
// same object and key (simulation speed only; it changes no outcome).
const verified = new WeakMap<Snapshot, Map<string, boolean>>();

/** Check the commit signature against the account's repo key and the record
 * map against the commit. Anything else proves nothing. */
export function verifySnapshot(s: Snapshot, did: Did, repoKey: Uint8Array): boolean {
  const k = did + ":" + Array.from(repoKey, (b) => b.toString(16).padStart(2, "0")).join("");
  let m = verified.get(s);
  const cached = m?.get(k);
  if (cached !== undefined) return cached;
  const c = s.commit;
  const ok = c.did === did && snapshotData(s.records) === c.data && verify(c.sig, commitUnsigned(c) as unknown[], repoKey);
  if (!m) verified.set(s, (m = new Map()));
  m.set(k, ok);
  return ok;
}

export function recordsIn(s: Snapshot, collection: string): [string, Cbor][] {
  const prefix = collection + "/";
  return [...s.records.entries()].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length), v]);
}
