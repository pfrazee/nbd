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

/** Check the commit signature against the account's repo key and the record
 * map against the commit. Anything else proves nothing. */
export function verifySnapshot(s: Snapshot, did: Did, repoKey: Uint8Array): boolean {
  const c = s.commit;
  if (c.did !== did) return false;
  if (snapshotData(s.records) !== c.data) return false;
  return verify(c.sig, commitUnsigned(c) as unknown[], repoKey);
}

export function recordsIn(s: Snapshot, collection: string): [string, Cbor][] {
  const prefix = collection + "/";
  return [...s.records.entries()].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length), v]);
}
