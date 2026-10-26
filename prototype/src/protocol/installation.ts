// One app installation: its keys, private state, and the sync loop that
// reads verified repos and host state, then requests, issues, and accepts
// grants. Everything it learns comes through `Network`, so different
// installations can see different, delayed, or forged views.

import { type Cbor, ref } from "./encoding";
import { type KeyPair, Rng, encryptionKeyPair, randomId, sign, signingKeyPair, verify } from "./crypto";
import { decryptRecord, encryptRecord } from "./content";
import {
  type HostView, acceptGrant, authorizeExchange, buildGrant, commitment, keyRequestPayload,
} from "./grants";
import { type Issuance, move } from "./publish";
import { type Snapshot, type WriteOp, recordsIn, verifySnapshot } from "./repo";
import { type TrustState, REENROLL_HOLD, Trust, approvalPayload, cloneTrust, emptyTrust, invitePayload } from "./trust";
import {
  type Approval, type Binding, COL, type Configuration, type Did, type Envelope, type Evidence, type Invite, type KeyRequest,
  type Membership, type Policy, type SpaceKeyGrant, asCbor, bindingId, label, sameBinding, withoutProof,
} from "./types";

export interface HostApi {
  reserveUri(): string;
  createSpace(admin: Did, uri: string, name: string, keyId: string, commitment: Uint8Array): string;
  setMembership(by: Did, uri: string, account: Did, eligible: boolean): Membership;
  spaceName(uri: string): string;
  admin(uri: string): Did;
  configuration(uri: string): Configuration;
  membership(uri: string, account: Did): Membership | null;
  knownAccounts(uri: string): Did[];
}

export interface Network {
  now(): number;
  repoKey(did: Did): Uint8Array | null;
  enumerate(observer: string, did: Did): Snapshot | null;
  credential(sessionId: string, space: string): number | null;
  readSpace(observer: string, credentialExpiry: number, did: Did, space: string): Snapshot | null;
  /** Returns the revision of the commit the write produced. */
  write(sessionId: string, ops: WriteOp[], space?: string): number;
  spaceWriters(space: string): Did[];
  host: HostApi;
  /** The grant rule every installation follows. */
  readonly policy: Policy;
  /** Spaces in which `did`'s own PDS holds a repo for it. */
  accountSpaces(did: Did): string[];
  /** Ground truth for the checks: an invite record was published. */
  invited?(e: InviteEvent): void;
}

/** What an inviting installation did, for the goal check and traces. */
export type InviteEvent = { by: Binding; space: string; record: Invite; firstMet: boolean; vouched: Binding[] };

export type Message =
  | { author: Did; rkey: string; text: string; device: string; at: number }
  | { author: Did; rkey: string; locked: true; at: number };

type SpaceLocal = {
  uri: string;
  host: HostView;
  key: Uint8Array | null;
  keyFrom: string | null;
  /** The key came only from an archived grant: it reads history but
   * authorizes no issuance or posting (audit.md#archived-grants). */
  archived: boolean;
  credentialExpiry: number;
  requested: string | null; // rkey of this device's key request
  issuances: Map<string, Issuance>; // current issuance per recipient binding ID
  stopped: Issuance[]; // stopped issuances, retained with their outcomes
  outbox: { rkey: string; text: string }[]; // drafts waiting for the key
  sawOtherHolder: boolean;
};

export type InstallationState = { trust: TrustState; spaces: Map<string, SpaceLocal> };

export class Installation {
  readonly binding: Binding;
  readonly signKey: KeyPair;
  readonly encKey: KeyPair;
  readonly rng: Rng;
  trust: Trust;
  spaces = new Map<string, SpaceLocal>();
  sessionId: string | null = null;
  online = true;
  /** "eager" pins every member of every joined space, as the spec requires;
   * "lazy" pins an account only when it first exchanges keys with it, which
   * the prototype keeps to show what eager pinning prevents. */
  pinning: "eager" | "lazy" = "eager";
  private contacts = new Set<Did>();
  writes = 0;
  imports = 0; // pairing and backup imports, for the invariant monitor
  lastDecisions: string[] = [];

  constructor(
    private readonly net: Network,
    readonly id: string, // e.g. "bob/phone"
    readonly name: string,
    did: Did,
    rng: Rng,
    public clockOffset = 0,
    keys?: { sign: KeyPair; enc: KeyPair; deviceId: string },
  ) {
    this.rng = rng;
    this.signKey = keys?.sign ?? signingKeyPair(rng.derive("sign"));
    this.encKey = keys?.enc ?? encryptionKeyPair(rng.derive("enc"));
    const deviceId = keys?.deviceId ?? randomId(rng.derive("device-id"));
    this.binding = { account: did, device: { deviceId, authPubkey: this.signKey.publicKey, encryptPubkey: this.encKey.publicKey } };
    const state = emptyTrust();
    state.accepted.set(bindingId(this.binding), { binding: this.binding, evidence: "own" });
    this.trust = new Trust(state, this.binding, () => this.localNow(), net.policy);
  }

  get did(): Did {
    return this.binding.account;
  }

  localNow(): number {
    return this.net.now() + this.clockOffset;
  }

  /** Write in one commit; returns its revision, or null on failure. */
  private writeRev(ops: WriteOp[], space?: string): number | null {
    if (!this.sessionId) return null;
    try {
      const rev = this.net.write(this.sessionId, ops, space);
      this.writes++;
      return rev;
    } catch {
      return null;
    }
  }

  private write(ops: WriteOp[], space?: string): boolean {
    return this.writeRev(ops, space) !== null;
  }

  // ---- devices -----------------------------------------------------------

  deviceRecord(): WriteOp {
    return { action: "create", collection: COL.device, rkey: this.binding.device.deviceId, value: { $type: COL.device, value: asCbor(this.binding) } };
  }

  /** The first device of an account publishes its record alone. */
  publishOwnRecord(): boolean {
    return this.write([this.deviceRecord()]);
  }

  /** Approve a paired device: approval and its record in one commit. */
  approve(target: Installation): boolean {
    const unsigned = { version: 1 as const, signer: this.binding, target: target.binding };
    const approval: Approval = { ...unsigned, proof: sign(this.signKey.secretKey, approvalPayload(unsigned)) };
    // The signed approval is persisted before publication; acceptance waits
    // for an acknowledged commit, or for the approval proven in the repo.
    const id = bindingId(target.binding);
    this.trust.state.approvedByMe.add(id);
    const rev = this.writeRev([
      { action: "create", collection: COL.approval, rkey: ref(asCbor(approval)), value: { $type: COL.approval, value: asCbor(approval) } },
      target.deviceRecord(),
    ]);
    if (rev === null) return false;
    // The commit this device wrote proves the target present at its revision.
    this.trust.state.accepted.set(id, { binding: target.binding, evidence: `approved by ${label(this.binding)} (this device)`, rev });
    return true;
  }

  /** Pairing copies pins from the approving installation. */
  pairFrom(approver: Installation): void {
    this.imports++;
    this.trust.importFrom(cloneTrust(approver.trust.state));
    // The approver's commit published this device's record.
    const published = approver.trust.state.accepted.get(bindingId(this.binding))?.rev;
    this.trust.state.accepted.set(bindingId(this.binding), { binding: this.binding, evidence: "own", rev: published });
    this.trust.state.approvedByMe.add(bindingId(this.binding));
    // Own devices known at pairing are not news to this user.
    for (const [id, a] of this.trust.state.accepted) if (a.binding.account === this.did) this.trust.state.noticed.add(`added:${id}`);
  }

  exportState(): InstallationState {
    this.trust.tick();
    return { trust: cloneTrust(this.trust.state), spaces: new Map([...this.spaces].map(([k, s]) => [k, { ...s, issuances: new Map(s.issuances), stopped: [...s.stopped], outbox: [...s.outbox] }])) };
  }

  importState(s: InstallationState): void {
    this.imports++;
    this.trust.importFrom(cloneTrust(s.trust));
    for (const [uri, sp] of s.spaces) {
      const mine = this.spaces.get(uri);
      if (!mine) this.spaces.set(uri, { ...sp, issuances: new Map(), stopped: [], outbox: [], requested: null });
      else if (!mine.key && sp.key) Object.assign(mine, { key: sp.key, keyFrom: "imported", archived: sp.archived });
    }
    this.sync();
  }

  // ---- spaces --------------------------------------------------------------

  createSpace(name: string): string {
    const key = this.rng.bytes(32);
    const keyId = randomId(this.rng);
    const uri = this.net.host.reserveUri();
    const space = this.net.host.createSpace(this.did, uri, name, keyId, commitment(uri, keyId, key));
    this.join(space);
    const sp = this.spaces.get(space)!;
    sp.key = key;
    sp.keyFrom = "generated";
    this.refreshHost(sp);
    return space;
  }

  /** This device lost its saved trust state (a reinstall without restore):
   * it keeps its own keys, pins everyone again on first use, and must report
   * the loss (device-enrollment.md#local-trust). */
  /** Start over after total device loss: no history for this account, so its
   * other devices become a list to remove (device-enrollment.md#total-device-loss). */
  beginStartOver(): void {
    this.trust.state.startOver = { list: null, done: false };
  }

  finishStartOver(): void {
    if (this.trust.state.startOver) this.trust.state.startOver.done = true;
  }

  lostState = false;
  resetLocalState(): void {
    const own = bindingId(this.binding);
    const st = this.trust.state;
    for (const id of [...st.accepted.keys()]) if (id !== own) st.accepted.delete(id);
    st.revoked.clear();
    st.holds.clear();
    st.candidatesSeen.clear();
    st.views.clear();
    st.vouches.clear();
    st.approvers.clear();
    st.fcHolds.clear();
    this.lostState = true;
  }

  /** Lose this device's copy of a space key (a wiped cache, a key-less
   * restore). It requests a grant again. */
  forgetKey(space: string): void {
    const sp = this.spaces.get(space);
    if (sp) Object.assign(sp, { key: null, keyFrom: null, archived: false, requested: null });
  }

  /** Admit `account` to `space`. Under the inviters policy this first meets
   * the account and publishes an invite record, and admits only if the
   * record was published. Returns whether the account was admitted. */
  invite(space: string, account: Did): boolean {
    if (this.net.policy === "inviters" && !this.publishInvite(space, account)) return false;
    this.net.host.setMembership(this.did, space, account, true);
    return true;
  }

  /** proposal-inviters.md#invite-records: sync the account's repo, pin it on
   * first use if this installation has no pin for it, and publish an
   * immutable invite record in this account's repo for the space. It vouches
   * only for bindings first met in making it. */
  private publishInvite(space: string, account: Did): boolean {
    const knew = this.trust.knew(account);
    this.trust.tick();
    this.observeAccount(account);
    this.contacts.add(account); // keep the pin current, whatever the pinning mode
    const st = this.trust.state;
    const live = this.trust.live(account);
    const met = knew ? [] : live.filter((b) => st.accepted.get(bindingId(b))!.evidence === "first use");
    const unsigned = {
      version: 1 as const, space, account, bindings: live, vouched: met.length > 0,
      issuer: { account: this.did, deviceId: this.binding.device.deviceId },
    };
    const record: Invite = { ...unsigned, proof: sign(this.signKey.secretKey, invitePayload(unsigned)) };
    const rkey = ref(asCbor(record));
    const value: Cbor = { $type: COL.invite, value: asCbor(record) };
    // A write whose acknowledgement was lost may still have landed.
    if (!this.write([{ action: "create", collection: COL.invite, rkey, value }], space) && !this.ownSpaceRecords(space, COL.invite).some(([k]) => k === rkey))
      return false;
    for (const b of met) this.trust.vouch(space, b);
    this.net.invited?.({ by: this.binding, space, record, firstMet: !knew, vouched: met });
    return true;
  }

  /** Records of one collection in this account's own repo for a space. */
  private ownSpaceRecords(space: string, collection: string): [string, Cbor][] {
    if (!this.sessionId) return [];
    const expiry = this.net.credential(this.sessionId, space);
    if (expiry === null) return [];
    const snap = this.net.readSpace(this.id, expiry, this.did, space);
    const key = this.net.repoKey(this.did);
    if (!snap || !key || !verifySnapshot(snap, this.did, key)) return [];
    return recordsIn(snap, collection);
  }

  /** Take vouches from this account's invite records: a valid record signed
   * by an own device this installation accepted (even if since removed),
   * for an account it has never pinned. */
  private adoptOwnInvites(): void {
    const st = this.trust.state;
    for (const space of this.net.accountSpaces(this.did))
      for (const [, v] of this.ownSpaceRecords(space, COL.invite)) {
        const rec = (v as { value?: Invite }).value;
        if (!rec || rec.version !== 1 || rec.space !== space || !rec.vouched || rec.issuer?.account !== this.did || !Array.isArray(rec.bindings)) continue;
        const issuer = [...st.accepted.values()].find((a) => a.binding.account === this.did && a.binding.device.deviceId === rec.issuer.deviceId)?.binding;
        if (!issuer || !(rec.proof instanceof Uint8Array) || !verify(rec.proof, invitePayload(withoutProof(rec)), issuer.device.authPubkey)) continue;
        if (this.trust.adoptInvite(rec)) this.contacts.add(rec.account);
      }
  }

  removeMember(space: string, account: Did): void {
    this.net.host.setMembership(this.did, space, account, false);
  }

  join(space: string): void {
    if (this.spaces.has(space)) return;
    this.spaces.set(space, {
      uri: space, key: null, keyFrom: null, archived: false, credentialExpiry: -1, requested: null, issuances: new Map(), stopped: [], outbox: [], sawOtherHolder: false,
      host: { config: null, firstKeyId: null, firstCommitment: null, memberships: new Map() },
    });
  }

  post(space: string, text: string): void {
    const sp = this.spaces.get(space);
    if (!sp) throw new Error("not joined");
    const rkey = randomId(this.rng);
    if (!sp.key || sp.archived) {
      sp.outbox.push({ rkey, text });
      return;
    }
    this.publishMessage(sp, rkey, text);
  }

  private publishMessage(sp: SpaceLocal, rkey: string, text: string): void {
    // Send time in whole seconds of world time, inside the encrypted content.
    const content = { $type: "app.example.message#content", text, device: this.name, at: Math.round(this.net.now() * 3600) };
    const envelope = encryptRecord({
      key: sp.key!, keyId: sp.host.config!.keyId, space: sp.uri, author: this.did, collection: COL.message, rkey, content, rng: this.rng,
    });
    this.write([{ action: "create", collection: COL.message, rkey, value: { $type: COL.message, envelope: asCbor(envelope) } }], sp.uri);
  }

  messages(space: string): Message[] {
    const sp = this.spaces.get(space);
    if (!sp || !this.sessionId) return [];
    const out: Message[] = [];
    for (const [did, snap] of this.readSpaceRepos(sp)) {
      for (const [rkey, v] of recordsIn(snap, COL.message)) {
        const env = (v as { envelope?: Envelope }).envelope;
        if (!sp.key || !env) {
          out.push({ author: did, rkey, locked: true, at: snap.commit.rev });
          continue;
        }
        try {
          const c = decryptRecord({ key: sp.key, envelope: env, space: sp.uri, author: did, collection: COL.message, rkey }) as { text: string; device: string; at: number };
          out.push({ author: did, rkey, text: c.text, device: c.device, at: c.at / 3600 });
        } catch {
          out.push({ author: did, rkey, locked: true, at: snap.commit.rev });
        }
      }
    }
    return out.sort((a, b) => a.at - b.at);
  }

  // ---- sync ----------------------------------------------------------------

  /** One round: repos, host state, then space repos. Returns whether
   * anything changed, for the world's settle loop. */
  sync(): boolean {
    if (!this.online) return false;
    const before = this.fingerprint();
    if (this.net.policy === "inviters") {
      // Credit time up to now before any observation can revoke.
      this.trust.tick();
      this.adoptOwnInvites();
    }
    for (const did of this.trackedAccounts()) this.observeAccount(did);
    for (const sp of this.spaces.values()) this.syncSpace(sp);
    return this.fingerprint() !== before;
  }

  trackedAccounts(): Did[] {
    const out = new Set<Did>([this.did, ...this.contacts]);
    if (this.pinning === "eager")
      for (const sp of this.spaces.values()) for (const d of this.net.host.knownAccounts(sp.uri)) out.add(d);
    return [...out];
  }

  /** A lazy client meets an account when it first exchanges keys with it. */
  private contact(did: Did): void {
    if (this.pinning === "eager" || this.contacts.has(did)) return;
    this.contacts.add(did);
    this.observeAccount(did);
  }

  private observeAccount(did: Did): void {
    const snap = this.net.enumerate(this.id, did);
    const key = this.net.repoKey(did);
    if (!snap || !key || !verifySnapshot(snap, did, key)) return;
    this.trust.observe(did, snap);
  }

  private refreshHost(sp: SpaceLocal): void {
    const cfg = this.net.host.configuration(sp.uri);
    if (sp.host.firstKeyId === null) {
      sp.host.firstKeyId = cfg.keyId;
      sp.host.firstCommitment = cfg.commitment;
    }
    // A configuration that changes the creation-fixed key ID or commitment is
    // invalid: keep the last valid one and alarm, but keep following
    // membership, which the bad configuration does not affect.
    const tampered = sp.host.firstKeyId !== cfg.keyId || ref(sp.host.firstCommitment!) !== ref(cfg.commitment);
    if (tampered) this.trust.raise(`host-integrity:${sp.uri}`, "host-integrity", `The host changed ${this.net.host.spaceName(sp.uri)}'s key commitment`);
    else if (!sp.host.config || cfg.revision >= sp.host.config.revision) sp.host.config = { ...cfg };
    // Surface admissions, removals, and readmissions learned after this
    // device first looked at the space (core.md#trusted-host-state).
    const first = sp.host.memberships.size === 0;
    for (const d of this.net.host.knownAccounts(sp.uri)) {
      const m = this.net.host.membership(sp.uri, d);
      const prev = sp.host.memberships.get(d);
      if (m && (!prev || m.revision > prev.revision)) {
        sp.host.memberships.set(d, m);
        const change = prev ? prev.eligible !== m.eligible : !first && m.eligible;
        if (change)
          this.trust.notice(`member:${sp.uri}:${d}:${m.revision}`, "membership", `${d} was ${m.eligible ? "added to" : "removed from"} ${this.net.host.spaceName(sp.uri)}`, { account: d });
      }
    }
  }

  private readSpaceRepos(sp: SpaceLocal): [Did, Snapshot][] {
    const now = this.net.now();
    if (sp.credentialExpiry <= now && this.sessionId) sp.credentialExpiry = this.net.credential(this.sessionId, sp.uri) ?? -1;
    if (sp.credentialExpiry <= now) return [];
    const out: [Did, Snapshot][] = [];
    for (const did of this.net.spaceWriters(sp.uri)) {
      const snap = this.net.readSpace(this.id, sp.credentialExpiry, did, sp.uri);
      const key = this.net.repoKey(did);
      if (snap && key && verifySnapshot(snap, did, key)) out.push([did, snap]);
    }
    return out;
  }

  private syncSpace(sp: SpaceLocal): void {
    this.refreshHost(sp);
    const repos = this.readSpaceRepos(sp);
    const grants: [Did, SpaceKeyGrant, Evidence | null][] = [];
    const requests: [Did, string, KeyRequest][] = [];
    for (const [did, snap] of repos) {
      const evidence = new Map(recordsIn(snap, COL.evidence).map(([k, v]) => [k, (v as { value: Evidence }).value]));
      for (const [, v] of recordsIn(snap, COL.grant)) {
        const g = (v as { value: SpaceKeyGrant }).value;
        if (g?.issuer?.account === did) grants.push([did, g, evidence.get(g.authorization.evidence) ?? null]);
      }
      for (const [rkey, v] of recordsIn(snap, COL.keyRequest)) requests.push([did, rkey, (v as { value: KeyRequest }).value]);
    }

    // Accept a grant addressed to this device: a current exchange if any
    // issuer is still authorized, otherwise historical reading only.
    if (!sp.key || sp.archived) {
      const mine = grants.filter(([, g]) => g.recipient.account === this.did && g.recipient.deviceId === this.binding.device.deviceId);
      for (const mode of sp.key ? (["current"] as const) : (["current", "archive"] as const)) {
        const hit = mine.find(([, g, e]) => {
          this.contact(g.issuer.account);
          const d = acceptGrant({ grant: g, evidence: e, space: sp.uri, own: this.binding, ownEnc: this.encKey, trust: this.trust, host: sp.host, mode });
          this.decide(`accept (${mode}) from ${label(g.issuer)}: ${d.result} ${d.reason}`);
          if (d.result !== "OK" || !d.key) return false;
          Object.assign(sp, { key: d.key, keyFrom: label(g.issuer), archived: mode === "archive" });
          return true;
        });
        if (hit) break;
      }
    }

    // Commits in grant evidence: a different commit at a revision this
    // installation verified means the PDS showed different histories.
    for (const [, , e] of grants) {
      for (const b of e?.blocks ?? []) {
        const c = b as { did?: string; rev?: number; data?: string };
        if (typeof c.did !== "string" || typeof c.rev !== "number" || typeof c.data !== "string" || Object.keys(c).length !== 3) continue;
        const mine = this.trust.state.views.get(c.did)?.commits.get(c.rev);
        if (mine !== undefined && mine !== c.data)
          this.trust.raise(`fork:${c.did}:${c.rev}`, "fork", `${c.did}'s PDS showed different histories: another member saw a different commit at revision ${c.rev}.`, c.did);
      }
    }

    // Audit grants to this account's bindings (audit.md#direct-sync).
    for (const [, g, e] of grants) {
      if (g.recipient.account !== this.did) continue;
      const rb = e?.blocks.find((b) => ref(b) === g.authorization.recipientBinding) as Binding | undefined;
      if (rb && !this.trust.state.accepted.has(bindingId(rb)) && !this.trust.startOverHistory(rb))
        this.trust.raise(`grant-unapproved:${ref(asCbor(g))}`, "unapproved-grant",
          `A device you don't recognise (${label(rb)}) may have access to ${this.net.host.spaceName(sp.uri)}.`);
    }
    if ((sp.keyFrom && sp.keyFrom !== "generated") || grants.some(([, g]) => !(g.recipient.account === this.did && g.recipient.deviceId === this.binding.device.deviceId)))
      sp.sawOtherHolder = true;

    if (sp.key && !sp.archived) {
      for (const d of sp.outbox.splice(0)) this.publishMessage(sp, d.rkey, d.text);
      if (sp.requested) {
        this.write([{ action: "delete", collection: COL.keyRequest, rkey: sp.requested }], sp.uri);
        sp.requested = null;
      }
      this.answerRequests(sp, requests, grants, repos.find(([d]) => d === this.did)?.[1] ?? null);
    } else if (!sp.requested && this.trust.isAccepted(this.binding)) {
      const unsigned = { version: 1 as const, space: sp.uri, recipient: this.binding, issuer: null };
      const req: KeyRequest = { ...unsigned, proof: sign(this.signKey.secretKey, keyRequestPayload(unsigned)) };
      const rkey = ref(asCbor(req));
      if (this.write([{ action: "create", collection: COL.keyRequest, rkey, value: { $type: COL.keyRequest, value: asCbor(req) } }], sp.uri))
        sp.requested = rkey;
    }
  }

  private answerRequests(sp: SpaceLocal, requests: [Did, string, KeyRequest][], grants: [Did, SpaceKeyGrant, Evidence | null][], own: Snapshot | null): void {
    // Unfinished issuances first: they resend exact bytes or stop.
    for (const iss of sp.issuances.values()) this.publish(sp, iss, own);
    for (const [did, , req] of requests) {
      const r = req?.recipient;
      if (!r || r.account !== did || req.space !== sp.uri) continue;
      if (!verify(req.proof, keyRequestPayload(withoutProof(req)), r.device.authPubkey)) continue;
      const rid = bindingId(r);
      const current = sp.issuances.get(rid);
      if (sameBinding(r, this.binding) || (current && current.state !== "stopped")) continue;
      if (grants.some(([, g]) => g.issuer.deviceId === this.binding.device.deviceId && g.recipient.deviceId === r.device.deviceId)) continue;
      this.contact(r.account);
      const d = authorizeExchange(this.trust, sp.host, sp.uri, this.binding, r, "issuer", this.binding);
      this.decide(`grant to ${label(r)}: ${d.result} ${d.reason}`);
      if (d.result !== "OK") continue;
      // Evidence carries the approvals and the commit this device relied on
      // for each party's account.
      const extra: Cbor[] = [];
      for (const a of new Set([this.did, r.account])) {
        const v = this.trust.state.views.get(a);
        if (!v) continue;
        extra.push(...v.approvals.map((ap) => asCbor(ap)), { did: a, rev: v.rev, data: v.data });
      }
      const { grant, evidence } = buildGrant({
        space: sp.uri, key: sp.key!, config: sp.host.config!, issuer: this.binding, issuerSign: this.signKey, recipient: r,
        issuerMembership: sp.host.memberships.get(this.did)!, recipientMembership: sp.host.memberships.get(r.account)!,
        extraBlocks: extra, rng: this.rng,
      });
      // P1: save exact bytes and the authorization basis before any upload.
      if (current) sp.stopped.push(current);
      const iss: Issuance = {
        recipient: r, grant, evidence, grantKey: ref(asCbor(grant)), evidenceKey: ref(asCbor(evidence)), evidenceUp: false,
        basis: { config: sp.host.config!.revision, issuer: sp.host.memberships.get(this.did)!.revision, recipient: sp.host.memberships.get(r.account)!.revision },
        state: "prepared", history: ["prepared"],
      };
      sp.issuances.set(rid, iss);
      this.publish(sp, iss, own);
    }
  }

  /** Advance one issuance through P2-P8 (audit.md#publication). */
  private publish(sp: SpaceLocal, iss: Issuance, own: Snapshot | null): void {
    if (iss.state === "acknowledged" || iss.state === "stopped") return;
    const grantValue: Cbor = { $type: COL.grant, value: asCbor(iss.grant) };
    // P4: reconcile an uncertain write by reading the repo back.
    const seen = own?.records.get(`${COL.grant}/${iss.grantKey}`);
    if (seen !== undefined) {
      if (ref(seen) === ref(grantValue)) move(iss, "acknowledged", "found in the repo");
      else move(iss, "stopped", "different bytes at the grant's identity");
      return;
    }
    if (own?.records.has(`${COL.evidence}/${iss.evidenceKey}`)) iss.evidenceUp = true;
    // Ready: authorization repeated now, on the exact recorded basis (P5, P7).
    const m = { config: sp.host.config?.revision, issuer: sp.host.memberships.get(this.did)?.revision, recipient: sp.host.memberships.get(iss.recipient.account)?.revision };
    if (m.config !== iss.basis.config || m.issuer !== iss.basis.issuer || m.recipient !== iss.basis.recipient) {
      move(iss, "stopped", "host evidence changed");
      return;
    }
    const d = authorizeExchange(this.trust, sp.host, sp.uri, this.binding, iss.recipient, "issuer", this.binding);
    if (d.result !== "OK") {
      move(iss, "stopped", `authorization lost: ${d.reason}`);
      return;
    }
    // P2: evidence first, same bytes on every attempt.
    if (!iss.evidenceUp) {
      if (!this.write([{ action: "create", collection: COL.evidence, rkey: iss.evidenceKey, value: { $type: COL.evidence, value: asCbor(iss.evidence) } }], sp.uri)) return;
      iss.evidenceUp = true;
    }
    // P3: record the uncertainty before releasing grant bytes.
    if (iss.state !== "outcome-unknown") move(iss, "outcome-unknown", "uploading the grant");
    if (this.write([{ action: "create", collection: COL.grant, rkey: iss.grantKey, value: grantValue }], sp.uri))
      move(iss, "acknowledged", "write acknowledged");
  }

  // ---- reporting -----------------------------------------------------------

  /** Keep recent grant decisions, collapsing repeats from settle rounds. */
  private decide(text: string): void {
    if (this.lastDecisions.slice(-6).includes(text)) return;
    this.lastDecisions.push(text);
    if (this.lastDecisions.length > 20) this.lastDecisions.shift();
  }

  holdRemaining(account: Did): number | null {
    const h = this.trust.hold(account);
    if (!h) return null;
    return Math.max(0, REENROLL_HOLD - h.credited - Math.max(0, this.localNow() - h.checkpoint));
  }

  private fingerprint(): string {
    const st = this.trust.state;
    const holds = [...st.holds].map(([d, h]) => `${d}:${h.candidate.join(",")}:${h.credited >= REENROLL_HOLD}`).join(";");
    const keys = [...this.spaces.values()].map((s) => `${s.uri}:${!!s.key}:${s.requested}:${[...s.issuances.values()].map((i) => i.state).join("")}:${s.stopped.length}`).join(";");
    return [st.accepted.size, st.revoked.size, holds, keys, this.writes, st.alarms.length, st.notices.length].join("|");
  }
}

export function freshRng(label: string): Rng {
  return Rng.fromLabel(label);
}
