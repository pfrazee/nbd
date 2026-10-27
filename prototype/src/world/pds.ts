// Emulated PDS. Each repo is a record map with signed commits and a
// monotonic revision. An enumeration is the whole record map at a signed
// commit (no MST: presence and absence are proven by the signed snapshot).
//
// Sessions model OAuth scopes as NBD requests them
// (device-enrollment.md#revocation-authority): app sessions are create-only
// for device and approval records; deleting a device record needs a
// short-lived delete authorization or a broad credential.

import { type Cbor, ref } from "../protocol/encoding";
import { type KeyPair, type Rng, sign, signingKeyPair } from "../protocol/crypto";
import { type RecordPath, type Snapshot, type WriteOp, commitUnsigned, snapshotData } from "../protocol/repo";
import { COL, type Did } from "../protocol/types";
import type { Emitted, RelayOp } from "./relay";

export type SessionKind = "app" | "delete-auth" | "password";
export type Session = { id: string; did: Did; kind: SessionKind; alive: boolean; label: string };

const PROTECTED = new Set<string>([COL.device, COL.approval]);

/** One repository: the account's public repo, or its repo in one space. */
export class Repo {
  rev = 0;
  records = new Map<RecordPath, Cbor>();
  history: Snapshot[] = [];
  times: number[] = []; // world time of each commit in history
  /** Called with each new commit (the PDS sends public-repo commits to the relay). */
  onCommit: ((snap: Snapshot) => void) | null = null;

  constructor(readonly did: Did, readonly name: string, private key: KeyPair, private readonly clock: () => number,
    init?: { rev: number; records: Map<RecordPath, Cbor> }, onCommit?: (snap: Snapshot) => void) {
    if (init) {
      this.rev = init.rev;
      this.records = new Map(init.records);
    }
    this.onCommit = onCommit ?? null;
    this.commit();
  }

  /** Sign future commits with a new key, and issue a commit under it. */
  rekey(key: KeyPair): void {
    this.key = key;
    this.commit();
  }

  commit(): Snapshot {
    this.rev += 1;
    const snap = this.sign(new Map(this.records), this.rev);
    this.history.push(snap);
    this.times.push(this.clock());
    this.onCommit?.(snap);
    return snap;
  }

  /** Sign an arbitrary record map at a revision: what the PDS, which holds
   * the repo key, can always do. Honest flows only sign real state. */
  sign(records: Map<RecordPath, Cbor>, rev: number): Snapshot {
    const unsigned = { did: this.did, repo: this.name, rev, data: snapshotData(records) };
    return { commit: { ...unsigned, sig: sign(this.key.secretKey, commitUnsigned(unsigned) as unknown[]) }, records };
  }

  latest(): Snapshot {
    return this.history[this.history.length - 1];
  }

  /** The newest commit made at or before world time `t`. */
  asOf(t: number): Snapshot {
    let i = this.times.length - 1;
    while (i > 0 && this.times[i] > t) i--;
    return this.history[i];
  }

  atRev(rev: number): Snapshot | undefined {
    return this.history.find((s) => s.commit.rev === rev);
  }
}

/** Per-observer views let a malicious PDS show different clients different
 * states (see adversary.ts). Honest by default: everyone sees the latest
 * commit, delayed by the observer's network lag. */
export type ViewHook = (observer: string, repo: Repo) => Snapshot | null;

/** Relay behavior of a malicious PDS for one public repo (witness policy):
 * `transform` edits what it sends the relay (a fork of what it serves);
 * `drop` sends nothing; `kind` "sync" sends `#sync` events (commit only)
 * instead of `#commit`; `badOps` sends operations that fail inversion. */
export type RelayHook = (did: Did, records: Map<RecordPath, Cbor>) => {
  records?: Map<RecordPath, Cbor>; drop?: boolean; kind?: "commit" | "sync"; badOps?: boolean;
} | null;
/** What a malicious PDS serves a witness fetching a repo: a snapshot, null
 * to withhold, or undefined for the honest latest commit. */
export type FetchHook = (witness: string, repo: Repo) => Snapshot | null | undefined;

export class Pds {
  readonly repos = new Map<string, Repo>();
  readonly sessions = new Map<string, Session>();
  private keys = new Map<Did, KeyPair>();
  viewHook: ViewHook | null = null;
  /** Malicious relay and fetch behaviors, newest first wins. */
  readonly relayHooks: RelayHook[] = [];
  readonly fetchHooks: FetchHook[] = [];
  /** Where public-repo commits go (witness policy only). */
  relay: { send(e: Emitted): void } | null = null;
  /** What this PDS last sent the relay per account: its records and root. */
  private relayed = new Map<Did, { records: Map<RecordPath, Cbor>; data: string } | null>();
  /** Commits signed for the relay alone (forks), by account and revision. */
  readonly relayForks = new Map<string, Snapshot>();
  private sessionCounter = 0;

  constructor(readonly name: string, private readonly rng: Rng, private readonly clock: () => number) {}

  createAccount(did: Did): Uint8Array {
    const key = signingKeyPair(this.rng.derive(`repo-key/${did}`));
    this.keys.set(did, key);
    this.repos.set(did, new Repo(did, did, key, this.clock, undefined, (s) => this.emit(did, s)));
    return key.publicKey;
  }

  /** Send a public-repo commit to the relay, as this PDS chooses to. */
  private emit(did: Did, snap: Snapshot, kind: "commit" | "sync" = "commit"): void {
    if (!this.relay) return;
    const real = new Map(snap.records);
    let hook: ReturnType<RelayHook> = null;
    for (let i = this.relayHooks.length - 1; i >= 0 && !hook; i--) hook = this.relayHooks[i](did, real);
    if (hook?.drop) return;
    let commit = snap.commit;
    let records = real;
    if (hook?.records) {
      records = hook.records;
      const forked = this.repos.get(did)!.sign(records, snap.commit.rev);
      this.relayForks.set(`${did}:${snap.commit.rev}`, forked);
      commit = forked.commit;
    }
    const prev = this.relayed.get(did) ?? null;
    const ops: RelayOp[] = [];
    const before = prev?.records ?? new Map<RecordPath, Cbor>();
    for (const [k, v] of before) if (!records.has(k)) ops.push({ path: k, prev: v, value: null });
    for (const [k, v] of records) {
      const old = before.get(k);
      if (old === undefined) ops.push({ path: k, prev: null, value: v });
      else if (ref(old) !== ref(v)) ops.push({ path: k, prev: old, value: v });
    }
    this.relayed.set(did, { records: new Map(records), data: commit.data });
    this.relay.send({
      kind: hook?.kind ?? kind, did, commit, prevData: prev ? prev.data : null,
      ops: hook?.badOps ? ops.filter((o) => !o.path.startsWith(COL.device + "/")) : ops,
    });
  }

  /** What a witness gets when it fetches `did`'s public repo. */
  serveFetch(witness: string, did: Did): Snapshot | null {
    const repo = this.repos.get(did);
    if (!repo) return null;
    for (let i = this.fetchHooks.length - 1; i >= 0; i--) {
      const hooked = this.fetchHooks[i](witness, repo);
      if (hooked !== undefined) return hooked;
    }
    // A PDS forking the relay serves witnesses the fork it published.
    return this.relayForks.get(`${did}:${repo.rev}`) ?? repo.latest();
  }

  /** Rotate an account's repo signing key; returns the new public key. */
  rotateKey(did: Did): Uint8Array {
    const key = signingKeyPair(this.rng.derive(`repo-key/${did}/${this.repos.size}/${this.clock()}`));
    this.keys.set(did, key);
    for (const r of this.repos.values()) if (r.did === did) r.rekey(key);
    return key.publicKey;
  }

  /** Take in a migrating account: its repos continue at their revisions. */
  adopt(did: Did, repos: { name: string; rev: number; records: Map<RecordPath, Cbor> }[]): Uint8Array {
    const key = signingKeyPair(this.rng.derive(`repo-key/${did}/adopted/${this.clock()}`));
    this.keys.set(did, key);
    for (const r of repos) this.repos.set(r.name, new Repo(did, r.name, key, this.clock, r, r.name === did ? (s) => this.emit(did, s, "sync") : undefined));
    return key.publicKey;
  }

  /** Stop hosting an account that migrated away. */
  release(did: Did): void {
    this.keys.delete(did);
    for (const [name, r] of [...this.repos]) if (r.did === did) this.repos.delete(name);
    for (const s of this.sessions.values()) if (s.did === did) s.alive = false;
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
      r = new Repo(did, name, key, this.clock);
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

  /** Apply operations in one commit. Permission checks follow NBD's scopes. */
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

  /** What `observer` gets when it enumerates a repo, `lag` hours late. */
  enumerate(observer: string, did: Did, space?: string, lag = 0): Snapshot {
    const repo = this.repo(did, space);
    return this.viewHook?.(observer, repo) ?? (lag > 0 ? repo.asOf(this.clock() - lag) : repo.latest());
  }
}
