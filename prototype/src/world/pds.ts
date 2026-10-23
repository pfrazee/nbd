// Emulated PDS. Each repo is a record map with signed commits and a
// monotonic revision. An enumeration is the whole record map at a signed
// commit (no MST: presence and absence are proven by the signed snapshot).
//
// Sessions model OAuth scopes as PEEP requests them
// (device-enrollment.md#revocation-authority): app sessions are create-only
// for device and approval records; deleting a device record needs a
// short-lived delete authorization or a broad credential.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, type Rng, sign, signingKeyPair } from "../protocol/crypto";
import { type RecordPath, type Snapshot, type WriteOp, commitUnsigned, snapshotData } from "../protocol/repo";
import { COL, type Did } from "../protocol/types";

export type SessionKind = "app" | "delete-auth" | "password";
export type Session = { id: string; did: Did; kind: SessionKind; alive: boolean; label: string };

const PROTECTED = new Set<string>([COL.device, COL.approval]);

/** One repository: the account's public repo, or its repo in one space. */
export class Repo {
  rev = 0;
  records = new Map<RecordPath, Cbor>();
  history: Snapshot[] = [];

  constructor(readonly did: Did, readonly name: string, private readonly key: KeyPair) {
    this.commit();
  }

  commit(): Snapshot {
    this.rev += 1;
    const unsigned = { did: this.did, repo: this.name, rev: this.rev, data: snapshotData(this.records) };
    const commit = { ...unsigned, sig: sign(this.key.secretKey, commitUnsigned(unsigned) as unknown[]) };
    const snap = { commit, records: new Map(this.records) };
    this.history.push(snap);
    return snap;
  }

  latest(): Snapshot {
    return this.history[this.history.length - 1];
  }
}

/** Per-observer views let a malicious PDS show different clients different
 * states (M3). Honest by default: everyone sees the latest commit. */
export type ViewHook = (observer: string, repo: Repo) => Snapshot | null;

export class Pds {
  readonly repos = new Map<string, Repo>();
  readonly sessions = new Map<string, Session>();
  private keys = new Map<Did, KeyPair>();
  viewHook: ViewHook | null = null;
  private sessionCounter = 0;

  constructor(readonly name: string, private readonly rng: Rng) {}

  createAccount(did: Did): Uint8Array {
    const key = signingKeyPair(this.rng.derive(`repo-key/${did}`));
    this.keys.set(did, key);
    this.repos.set(did, new Repo(did, did, key));
    return key.publicKey;
  }

  hosts(did: Did): boolean {
    return this.keys.has(did);
  }

  repo(did: Did, space?: string): Repo {
    const name = space ? `${did}|${space}` : did;
    let r = this.repos.get(name);
    if (!r) {
      const key = this.keys.get(did);
      if (!key) throw new Error(`pds ${this.name}: no account ${did}`);
      r = new Repo(did, name, key);
      this.repos.set(name, r);
    }
    return r;
  }

  login(did: Did, kind: SessionKind, label: string): Session {
    if (!this.keys.has(did)) throw new Error(`pds ${this.name}: no account ${did}`);
    const s = { id: `${this.name}-s${++this.sessionCounter}`, did, kind, alive: true, label };
    this.sessions.set(s.id, s);
    return s;
  }

  endSession(id: string): void {
    const s = this.sessions.get(id);
    if (s) s.alive = false;
  }

  liveSessions(did: Did): Session[] {
    return [...this.sessions.values()].filter((s) => s.did === did && s.alive);
  }

  /** Apply operations in one commit. Permission checks follow PEEP's scopes. */
  write(sessionId: string, ops: WriteOp[], space?: string): Snapshot {
    const s = this.sessions.get(sessionId);
    if (!s || !s.alive) throw new Error("pds: session ended");
    const repo = this.repo(s.did, space);
    for (const op of ops) {
      const path = `${op.collection}/${op.rkey}`;
      if (op.action === "create") {
        if (s.kind === "delete-auth") throw new Error("pds: delete authorization cannot create");
        if (repo.records.has(path) && ref(repo.records.get(path)!) !== ref(op.value))
          throw new Error(`pds: ${path} exists with different bytes`);
        repo.records.set(path, op.value);
      } else {
        if (PROTECTED.has(op.collection) && s.kind === "app")
          throw new Error("pds: app sessions cannot delete device or approval records");
        repo.records.delete(path);
      }
    }
    const snap = repo.commit();
    if (s.kind === "delete-auth") s.alive = false; // used once, then discarded
    return snap;
  }

  /** What `observer` gets when it enumerates a repo. */
  enumerate(observer: string, did: Did, space?: string): Snapshot {
    const repo = this.repo(did, space);
    return this.viewHook?.(observer, repo) ?? repo.latest();
  }
}
