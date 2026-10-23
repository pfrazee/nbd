// A malicious PDS. It holds each hosted account's repo key, so it can
// withhold newer commits from chosen observers or sign forged snapshots for
// them. Policies apply only to an account's public repo, and only to the
// observers they name; everyone else keeps the honest view.

import type { Cbor } from "../protocol/encoding";
import type { RecordPath, Snapshot } from "../protocol/repo";
import type { Did } from "../protocol/types";
import type { Pds, Repo } from "./pds";

export type Policy =
  | { id: number; kind: "withhold"; did: Did; observers: string[]; rev: number; describe: string }
  | {
      id: number; kind: "forge"; did: Did; observers: string[]; describe: string;
      /** Revisions ahead of the real repo: 0 for a victim that never saw the
       * real state, 1 to fork a victim that did without it noticing. */
      revOffset: number;
      transform: (records: Map<RecordPath, Cbor>) => Map<RecordPath, Cbor>;
    };

type NewPolicy =
  | Omit<Extract<Policy, { kind: "withhold" }>, "id">
  | Omit<Extract<Policy, { kind: "forge" }>, "id">;

export class Adversary {
  readonly policies: Policy[] = [];
  private counter = 0;
  private forged = new Map<string, Snapshot>();

  constructor(private readonly pdsOf: (did: Did) => Pds | undefined) {}

  add(p: NewPolicy): Policy {
    const policy = { ...p, id: ++this.counter } as Policy;
    this.policies.push(policy);
    this.install(policy.did);
    return policy;
  }

  remove(id: number): void {
    const i = this.policies.findIndex((p) => p.id === id);
    if (i >= 0) this.policies.splice(i, 1);
  }

  private install(did: Did): void {
    const pds = this.pdsOf(did);
    if (pds && !pds.viewHook) pds.viewHook = (observer, repo) => this.view(observer, repo);
  }

  private view(observer: string, repo: Repo): Snapshot | null {
    if (repo.name !== repo.did) return null; // space repos stay honest
    for (let i = this.policies.length - 1; i >= 0; i--) {
      const p = this.policies[i];
      if (p.did !== repo.did || !p.observers.includes(observer)) continue;
      if (p.kind === "withhold") return repo.atRev(p.rev) ?? null;
      // A victim that later sees the real commit for the same revision, in
      // grant evidence, detects the fork.
      const rev = repo.rev + p.revOffset;
      const key = `${p.id}:${rev}`;
      let snap = this.forged.get(key);
      if (!snap) {
        snap = repo.sign(p.transform(new Map(repo.records)), rev);
        this.forged.set(key, snap);
      }
      return snap;
    }
    return null;
  }
}
