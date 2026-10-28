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
import { type TrustState, PENDING_INVITE_TTL, REENROLL_HOLD, Trust, approvalPayload, cloneTrust, emptyTrust, invitePayload } from "./trust";
import {
  type CoverageSegment, type GapWarning, type HistoryEntry, type HistoryResponse, LIVENESS_LIMIT, type WitnessApi, type WitnessClientState,
  cloneWitnessState, emptyWitnessState,
} from "./witness";
import {
  type Approval, type Binding, COL, type Configuration, type Did, type Envelope, type Evidence, type Invite, type KeyRequest,
  type Membership, type Policy, type SpaceKeyGrant, asCbor, bindingId, hasStanding, label, sameBinding, withoutProof,
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
  /** Ground truth for the checks: an invite record was signed and saved. */
  invitePrepared?(by: Binding, rkey: string, record: Invite, firstMet: boolean, vouched: Binding[]): void;
  /** Ground truth for the checks: an attempt to publish an invite record. */
  invited?(e: InviteEvent): void;
  /** Witness policy: this installation's trusted witness (its application's,
   * see Installation.app), or null while it is unreachable. */
  witness?(observer: string): WitnessApi | null;
  /** Other witnesses a client could ask, including one a PDS runs. A client
   * must never trust them (proposal: Trusted witnesses). */
  otherWitnesses?(observer: string): WitnessApi[];
  /** Ground truth for the checks: this installation newly accepted a binding
   * of another account; `rev` is the revision of the witnessed commit it
   * relied on, if any. */
  accepted?(by: Installation, b: Binding, rev: number | null, via: string): void;
}

/** A witness answer under way: its latest page's request `id`, when the
 * first page's request was sent (`first`) and the latest (`sent`), and its
 * frontier age, from the first page (null until it arrives). */
type Request = { id: string; first: number; sent: number; age: number | null };

/** A signed invite or capture record, saved with its vouch decision before
 * any upload. `firstMet`: the installation had no pin for the account when
 * it made the record. */
export type OutboxInvite = { space: string; account: Did; record: Invite; rkey: string; vouch: Binding[]; firstMet: boolean };

/** What an inviting installation did, for the goal check and traces:
 * `stage` is the first attempt when the invite was made, or a later resend
 * from the outbox; `abandoned` if the record no longer admitted its account. */
export type InviteEvent = {
  by: Binding; space: string; record: Invite; rkey: string; firstMet: boolean; vouched: Binding[];
  stage: "attempt" | "flush"; published: boolean; abandoned: boolean;
};

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

/** `invites`: the outbox, restored only onto the same device. `witness`:
 * the own-account audit cursor and the rest of the witness client state
 * (witness policy), which backups and transfers carry. */
export type InstallationState = {
  trust: TrustState; spaces: Map<string, SpaceLocal>; invites?: { device: string; outbox: OutboxInvite[] }; witness?: WitnessClientState;
};

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
  /** The application this installation belongs to; it trusts that
   * application's witness and no other (witness policy). */
  app = "lantern";
  /** Witness client state (witness policy). */
  mon: WitnessClientState = emptyWitnessState();
  /** Whether it has run since it last stopped: the first sync after a stop
   * is a restart, across which coverage is carried by wall clock. */
  running = false;
  /** Ground truth for the goal check (never transferred): coverage segments,
   * world time it was created and the world time its lineage of state began
   * (a restored installation inherits its backup's; a paired one is new),
   * and the world time of its latest sync. */
  segments: CoverageSegment[] = [];
  readonly createdAt: number;
  origin: number;
  /** The same as an event sequence position (World.tick), set by the world. */
  originOrder = Infinity;
  /** The lost installation this one was restored from, if any. */
  predecessor: Installation | null = null;
  /** Integrity alarms on PDS-served commits the relay never published, with
   * their proof: the served commit, and the revisions of the two commits the
   * witness reconstructed consecutively around it. */
  readonly unrelayedProofs: { did: Did; served: Snapshot["commit"]; below: number; above: number }[] = [];
  /** Proof of a starting-commit integrity alarm: the commit a witness's
   * history of `did` started at, below (or at) the cursor `cursor`. */
  readonly startProofs: { did: Did; start: Snapshot["commit"]; cursor: number }[] = [];
  lastRun = -Infinity;
  /** World-time intervals during which it ran (ground truth). */
  runs: { from: number; to: number }[] = [];
  private reported = new Set<string>();
  /** Witness answers under way, per account (lost on a restart): the
   * latest page's request, when the first page's request was sent and when
   * the latest one was, and the answer's frontier age, from its first page. */
  private requests = new Map<Did, Request>();
  private requestCount = 0;

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
    this.trust = new Trust(state, this.binding, () => this.localNow(), net.policy, () => this.net.now());
    this.createdAt = this.origin = net.now();
  }

  get witnessed(): boolean {
    return this.net.policy === "witness";
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
    // The new device resumes the approver's audit cursors (repo revisions,
    // so it may use another witness); its coverage is unknown until its own
    // frontier first advances.
    for (const [d, c] of approver.mon.cursors) this.mon.cursors.set(d, c);
    for (const d of approver.mon.cursors.keys()) this.cursorSeq(d, approver.mon.cursorSeqs.get(d));
    for (const g of approver.mon.gaps) if (!this.mon.gaps.some((x) => x.key === g.key)) this.mon.gaps.push({ ...g });
    // The approver's commit published this device's record. If its
    // acknowledgement was lost, the revision is unknown, but later than any
    // the approver had seen.
    const published = approver.trust.state.accepted.get(bindingId(this.binding))?.rev
      ?? (approver.trust.state.views.get(this.did)?.rev ?? 0) + 1;
    this.trust.state.accepted.set(bindingId(this.binding), { binding: this.binding, evidence: "own", rev: published });
    this.trust.state.approvedByMe.add(bindingId(this.binding));
    // Own devices known at pairing are not news to this user.
    for (const [id, a] of this.trust.state.accepted) if (a.binding.account === this.did) this.trust.state.noticed.add(`added:${id}`);
  }

  exportState(): InstallationState {
    this.trust.tick();
    if (this.witnessed) this.checkpoint();
    return {
      trust: cloneTrust(this.trust.state), spaces: new Map([...this.spaces].map(([k, s]) => [k, { ...s, issuances: new Map(s.issuances), stopped: [...s.stopped], outbox: [...s.outbox] }])),
      invites: { device: this.binding.device.deviceId, outbox: [...this.inviteOutbox] },
      witness: cloneWitnessState(this.mon),
    };
  }

  /** Restore a backup (or another saved state) onto this installation. */
  importState(s: InstallationState, origin?: { at: number; order: number }): void {
    this.imports++;
    this.trust.importFrom(cloneTrust(s.trust));
    if (s.witness) {
      // Resume from the backup's cursors, not from now, and replay since.
      // They are repo revisions, so the restored installation may use a
      // different witness: what that witness lacks after them is a gap.
      for (const [d, c] of s.witness.cursors) this.mon.cursors.set(d, c);
      for (const d of s.witness.cursors.keys()) this.cursorSeq(d, s.witness.cursorSeqs?.get(d));
      for (const g of s.witness.gaps) if (!this.mon.gaps.some((x) => x.key === g.key)) this.mon.gaps.push({ ...g });
      this.mon.auditGaps.push(...s.witness.auditGaps.map((g) => ({ ...g })));
      // Coverage carries across by wall clock from the backup's checkpoint.
      this.mon.checkpoint = s.witness.checkpoint && { ...s.witness.checkpoint };
      this.mon.coverage = null;
      this.running = false;
    }
    if (origin !== undefined) {
      this.origin = Math.min(this.origin, origin.at);
      this.originOrder = Math.min(this.originOrder, origin.order);
    }
    if (s.invites?.device === this.binding.device.deviceId) this.inviteOutbox = [...s.invites.outbox];
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
    st.authorized.clear();
    st.lineage.clear();
    st.admitted.clear();
    st.pending.clear();
    st.approvers.clear();
    st.fcHolds.clear();
    this.inviteOutbox = [];
    this.mon = emptyWitnessState();
    this.lostState = true;
  }

  /** Lose this device's copy of a space key (a wiped cache, a key-less
   * restore). It requests a grant again. */
  forgetKey(space: string): void {
    const sp = this.spaces.get(space);
    if (sp) Object.assign(sp, { key: null, keyFrom: null, archived: false, requested: null });
  }

  /** Admit `account` to `space`. Under the inviters policy this first meets
   * the account and saves a signed invite record, then publishes it and
   * admits the account; a record that fails to publish is resent byte for
   * byte on later syncs (core.md#invites). An invite
   * counts only if it admits the account, so none is made for a member.
   * Returns whether the account was admitted now. */
  invite(space: string, account: Did): boolean {
    if (!hasStanding(this.net.policy)) {
      this.net.host.setMembership(this.did, space, account, true);
      return true;
    }
    if (this.net.host.membership(space, account)?.eligible) return false;
    // Inviting again while an invite of the account to the space is unsent
    // resumes that invite: no second record.
    const unsent = this.inviteOutbox.find((e) => !e.record.captures && e.space === space && e.account === account);
    if (unsent) {
      this.flushInvites();
      return !this.inviteOutbox.includes(unsent);
    }
    const entry = this.prepareInvite(space, account);
    this.enqueueInvite(entry);
    return !this.inviteOutbox.includes(entry);
  }

  /** Save a new record: it goes out at once only if no older record is
   * unsent, and otherwise waits its turn. */
  private enqueueInvite(entry: OutboxInvite): void {
    const queued = this.inviteOutbox.length > 0;
    this.inviteOutbox.push(entry);
    if (queued) this.reportInvite(entry, "attempt", false);
    else this.flushInvites(entry);
  }

  private reportInvite(e: OutboxInvite, stage: "attempt" | "flush", published: boolean, abandoned = false): void {
    this.net.invited?.({ by: this.binding, space: e.space, record: e.record, rkey: e.rkey, firstMet: e.firstMet, vouched: e.vouch, stage, published, abandoned });
  }

  /** Invites saved but not yet published, oldest first. */
  inviteOutbox: OutboxInvite[] = [];

  /** core.md#invites: sync the account's repo, pin it on
   * first use if this installation has no pin for it, decide what the invite
   * vouches for and authorizes, save the vouch, and sign the record, once. An account with no devices
   * that this installation never pinned gets a pending invite. */
  private prepareInvite(space: string, account: Did): OutboxInvite {
    const knew = this.trust.knew(account);
    this.trust.tick();
    this.observeAccount(account);
    this.contacts.add(account); // keep the pin current, whatever the pinning mode
    const st = this.trust.state;
    const live = this.trust.live(account);
    const view = st.views.get(account);
    const pending = !knew && !!view && view.present.size === 0;
    const met = knew ? [] : live.filter((b) => st.accepted.get(bindingId(b))!.evidence === "first use");
    // It authorizes the listed bindings in this installation's first-contact
    // lineage, fixed now: a later pin never reaches back. A reset's held
    // candidate isn't accepted, so it isn't listed.
    const authorizes = live.filter((b) => this.trust.inLineage(b));
    const entry = this.signInvite(space, account, live, authorizes, met, pending, null, !knew);
    if (pending) this.trust.addPending(entry.rkey, space, account, this.binding.device.deviceId);
    return entry;
  }

  private signInvite(space: string, account: Did, bindings: Binding[], authorizes: Binding[], met: Binding[], pending: boolean, captures: string | null, firstMet: boolean): OutboxInvite {
    const unsigned = {
      version: 1 as const, space, account, bindings, authorizes, pending, captures,
      issuer: { account: this.did, deviceId: this.binding.device.deviceId },
    };
    const record: Invite = { ...unsigned, proof: sign(this.signKey.secretKey, invitePayload(unsigned)) };
    const rkey = ref(asCbor(record));
    this.net.invitePrepared?.(this.binding, rkey, record, firstMet, met);
    return { space, account, record, rkey, vouch: met, firstMet };
  }

  /** Publish saved invites in order, resending their exact bytes, and stop
   * at the first that fails. `current` is an invite being made now. */
  private flushInvites(current?: OutboxInvite): void {
    const report = (e: OutboxInvite, published: boolean, abandoned = false) => this.reportInvite(e, e === current ? "attempt" : "flush", published, abandoned);
    while (this.inviteOutbox.length) {
      const e = this.inviteOutbox[0];
      const { record, rkey } = e;
      // A write whose acknowledgement was lost may still have landed.
      const landed = () => this.ownSpaceRecords(e.space, COL.invite).some(([k]) => k === rkey);
      if (!record.captures && this.net.host.membership(e.space, e.account)?.eligible && !landed()) {
        // Someone else admitted the account meanwhile: the record would no
        // longer admit it, so it is abandoned unsent.
        this.inviteOutbox.shift();
        report(e, false, true);
        if (record.pending) {
          // Abandoning a pending invite ends it, persistently, with any
          // capture queued for it.
          this.trust.abandonPending(rkey);
          this.inviteOutbox = this.inviteOutbox.filter((x) => x.record.captures !== rkey);
        }
        continue;
      }
      if (record.captures) {
        // A capture goes out only once its pending invite has been published
        // by this account, and never for one that was abandoned.
        if (this.trust.state.abandoned.has(record.captures)) {
          this.inviteOutbox.shift();
          report(e, false, true);
          continue;
        }
        if (!this.ownSpaceRecords(e.space, COL.invite).some(([k]) => k === record.captures)) {
          if (current && this.inviteOutbox.includes(current)) report(current, false);
          return;
        }
      }
      if (!this.write([{ action: "create", collection: COL.invite, rkey, value: { $type: COL.invite, value: asCbor(record) } }], e.space) && !landed()) {
        if (current && this.inviteOutbox.includes(current)) report(current, false);
        return;
      }
      this.inviteOutbox.shift();
      report(e, true);
      // Admission and authorized standing start once the record is published.
      for (const b of record.authorizes) this.trust.authorize(e.space, b);
      this.trust.admit(e.account, e.space);
      if (!record.captures) this.net.host.setMembership(this.did, e.space, e.account, true);
    }
  }

  /** core.md#invites: the first time this installation
   * pins an account it made a pending invite for, it vouches for the devices
   * it met on first use and publishes a capture record, if the invite has
   * not expired. */
  private capturePending(): void {
    const st = this.trust.state;
    for (const [rkey, p] of st.pending) {
      if (p.done || !this.trust.knew(p.account)) continue;
      p.done = true;
      if (p.issuer !== this.binding.device.deviceId) continue; // only the device that made it
      if (p.credited >= PENDING_INVITE_TTL) continue; // expired: an ordinary first contact
      const live = this.trust.live(p.account);
      const met = live.filter((b) => st.accepted.get(bindingId(b))!.evidence === "first use");
      if (!met.length) continue;
      const entry = this.signInvite(p.space, p.account, live, met, met, false, rkey, true);
      // Queued behind its pending invite if that is still unsent.
      this.enqueueInvite(entry);
    }
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

  /** Learn from this account's invite records, each signed by an own device
   * this installation accepted (even if since removed): every record tells
   * it a space its account admitted the invited account to, and one that
   * authorizes devices carries that authorization (see Trust.adoptInvite). */
  private adoptOwnInvites(): void {
    const st = this.trust.state;
    for (const space of this.net.accountSpaces(this.did))
      for (const [, v] of this.ownSpaceRecords(space, COL.invite)) {
        const rec = (v as { value?: Invite }).value;
        if (!rec || rec.version !== 1 || rec.space !== space || rec.issuer?.account !== this.did || !Array.isArray(rec.bindings)) continue;
        const issuer = [...st.accepted.values()].find((a) => a.binding.account === this.did && a.binding.device.deviceId === rec.issuer.deviceId)?.binding;
        if (!issuer || !(rec.proof instanceof Uint8Array) || !verify(rec.proof, invitePayload(withoutProof(rec)), issuer.device.authPubkey)) continue;
        this.trust.admit(rec.account, space);
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
    const now = this.net.now();
    if (!this.running) {
      this.requests.clear();
      if (this.witnessed) this.restart();
      this.runs.push({ from: now, to: now });
    }
    this.running = true;
    this.runs[this.runs.length - 1].to = now;
    if (hasStanding(this.net.policy)) {
      // Credit time up to now before any observation can revoke.
      this.trust.tick();
      this.flushInvites();
      this.adoptOwnInvites();
    }
    for (const did of this.trackedAccounts()) this.observeAccount(did);
    if (hasStanding(this.net.policy)) this.capturePending();
    for (const sp of this.spaces.values()) this.syncSpace(sp);
    this.reportAccepts(null, "transferred or adopted");
    if (this.witnessed) this.checkpoint();
    this.lastRun = this.net.now();
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
    if (this.witnessed) return this.followAccount(did);
    const snap = this.net.enumerate(this.id, did);
    const key = this.net.repoKey(did);
    if (!snap || !key || !verifySnapshot(snap, did, key)) return;
    this.trust.observe(did, snap);
    this.reportAccepts(null, "observed");
  }

  // ---- witness policy (proposal-reliable-detection.md) ---------------------

  /** Ground truth: report bindings of other accounts accepted since last time. */
  private reportAccepts(rev: number | null, via: string, account?: Did): void {
    for (const [id, a] of this.trust.state.accepted) {
      if (this.reported.has(id) || a.binding.account === this.did || (account && a.binding.account !== account)) continue;
      if (this.trust.state.revoked.has(id)) continue; // accepted already revoked: never usable
      this.reported.add(id);
      this.net.accepted?.(this, a.binding, rev, via);
    }
  }

  /** Decisions on witnessed state: apply a commit the trusted witness
   * reports as published and reconstructed. */
  private observeWitnessed(did: Did, snap: Snapshot, via: string): void {
    this.reportAccepts(null, "transferred or adopted");
    this.trust.observe(did, snap);
    this.reportAccepts(snap.commit.rev, via, did);
  }

  /** Follow one account's history through the trusted witness: from the
   * saved cursor, every entry in order, each state applied and each gap
   * recorded. An account met for the first time starts at its latest
   * published commit, which must be reconstructed (INCOMPLETE otherwise);
   * the own account with no cursor replays its whole retained history
   * (fresh enrollment). */
  private followAccount(did: Did): void {
    const w = this.net.witness?.(this.id) ?? null;
    if (!w) {
      this.mon.reachable = false;
      return;
    }
    this.mon.reachable = true;
    const own = did === this.did;
    // A pinned account's history is followed from its cursor; an account
    // never pinned (a cursor kept while it had no devices, or copied by
    // pairing) is met afresh at its latest published commit.
    let cursor = own || this.trust.knew(did) ? this.mon.cursors.get(did) : undefined;
    if (cursor === undefined) {
      if (own) return this.enroll(w);
      const start = w.latest(this.id, did);
      if (!start) {
        this.mon.incomplete.add(did);
        this.decide(`INCOMPLETE ${did}: its latest published commit is not reconstructed`);
        return;
      }
      this.observeWitnessed(did, start.snap, "first contact");
      this.mon.cursors.set(did, start.pos);
      this.cursorSeq(did, start.commitSeq);
      this.crossCheck(w, did);
      return;
    }
    let last: HistoryResponse | null = null;
    let applied = false;
    let first = this.net.now();
    let age = Infinity;
    for (let more = true; more; ) {
      const got = this.ask(w, did, cursor);
      if (!got) break; // in transit: asked again next time
      const { r, req } = got;
      if (r.truncatedTo !== null && r.truncatedTo > cursor)
        this.recordGap(did, `${did}:retention:${cursor + 1}-${r.truncatedTo}`, cursor + 1, r.truncatedTo, null, "older than WITNESS_RETENTION");
      for (const e of own ? this.ownEntries(r.entries) : this.pinnedEntries(r.entries)) {
        if (e.kind === "state") {
          this.observeWitnessed(did, e.snap, e.via);
          applied = true;
        } else {
          this.startCheck(did, cursor, e);
          this.witnessGap(did, cursor, e);
        }
        if ((e.pos ?? 0) > cursor) this.cursorSeq(did, e.commitSeq);
        cursor = Math.max(cursor, e.pos ?? 0);
      }
      this.integrity(did, r);
      more = r.more;
      if (more) this.nextPage(req);
      else {
        last = r;
        first = req.first;
        age = req.age!;
        this.requests.delete(did);
      }
    }
    this.mon.cursors.set(did, cursor);
    // Nothing new: re-apply the rules to the witnessed view (holds elapse).
    if (!applied) this.trust.refresh(did);
    if (own && last) this.mon.fault = last.fault;
    if (own) this.advance(age, first);
    this.crossCheck(w, did);
  }

  /** Own account: every reconstructed commit, not only the latest. */
  private ownEntries(es: HistoryEntry[]): HistoryEntry[] {
    return es; // own: every entry
  }

  /** Pinned accounts: every commit in order, each applied or a gap; never a
   * later snapshot alone. */
  private pinnedEntries(es: HistoryEntry[]): HistoryEntry[] {
    return es; // pinned: every entry
  }

  /** Fresh enrollment: replay the own account's retained history and
   * present every binding that appeared in it, including deleted ones. */
  private enroll(w: WitnessApi): void {
    let cursor: number | null = null;
    const seen = new Map<string, Binding>();
    let last: Snapshot | null = null;
    let frontierAge = Infinity;
    let first = this.net.now();
    for (let more = true; more; ) {
      const got = this.ask(w, this.did, cursor);
      if (!got) return; // in transit: enrollment starts over next time
      const { r, req } = got;
      // History the witness no longer holds, from the account's first event.
      if (r.truncatedTo !== null && r.truncatedTo > (cursor ?? 0))
        this.recordGap(this.did, `${this.did}:retention:${(cursor ?? 0) + 1}-${r.truncatedTo}`, (cursor ?? 0) + 1, r.truncatedTo, null, "older than WITNESS_RETENTION");
      for (const e of r.entries) {
        const at = cursor ?? 0;
        if ((e.pos ?? 0) > at) this.cursorSeq(this.did, e.commitSeq);
        cursor = Math.max(at, e.pos ?? 0);
        if (e.kind === "gap") {
          this.witnessGap(this.did, at, e);
          continue;
        }
        last = e.snap;
        for (const [k, v] of recordsIn(e.snap, COL.device)) {
          const b = (v as { value?: Binding }).value;
          if (b?.device?.deviceId === k && b.account === this.did) seen.set(bindingId(b), b);
        }
      }
      this.integrity(this.did, r);
      more = r.more;
      if (more) this.nextPage(req);
      else {
        frontierAge = req.age!;
        this.mon.fault = r.fault;
        first = req.first;
        this.requests.delete(this.did);
      }
    }
    if (!last) return; // nothing reconstructed yet: INCOMPLETE
    this.observeWitnessed(this.did, last, "enrollment");
    const now = this.trust.state.views.get(this.did)!;
    for (const [id, b] of seen) {
      if (sameBinding(b, this.binding) || this.trust.state.approvedByMe.has(id)) continue;
      if (now.present.get(b.device.deviceId) && sameBinding(now.present.get(b.device.deviceId)!, b)) continue; // current: as starting over or first sync does
      this.trust.notice(`history:${id}`, "history-binding",
        `${label(b)} was on your account before this device was set up, and has since been removed. Not yours? Your account was impersonated.`, { about: b });
    }
    this.mon.cursors.set(this.did, cursor ?? 0);
    this.advance(frontierAge, first);
  }

  /** Ask the witness for a page of `did`'s history from `cursor`, for the
   * answer under way or a new one whose first request is sent now. Null
   * while nothing has arrived. An answer to an earlier request, such as one
   * sent before a restart, is discarded. A paged answer carries one frontier
   * age, computed when its first page's request arrived. */
  private ask(w: WitnessApi, did: Did, cursor: number | null): { r: HistoryResponse; req: Request } | null {
    let req = this.requests.get(did);
    if (!req) this.requests.set(did, (req = { id: this.requestId(), first: this.net.now(), sent: this.net.now(), age: null }));
    for (;;) {
      const r = w.history(this.id, did, cursor, undefined, req.id);
      if (!r) return null;
      if (r.req !== undefined && r.req !== req.id) continue; // not this request's answer: discarded
      if (req.age === null) req.age = r.frontierAge;
      return { r, req };
    }
  }

  /** The next page's request, sent now. */
  private nextPage(req: Request): void {
    req.id = this.requestId();
    req.sent = this.net.now();
  }

  private requestId(): string {
    return `${this.id}#${++this.requestCount}`;
  }

  /** Record a gap: the own account's raise their own warning; a pinned
   * account's are intervals audit reports as unchecked. */
  private recordGap(did: Did, key: string, fromRev: number, toRev: number, rev: number | null, reason: string): void {
    const g = { key, account: did, fromRev, toRev, rev, reason, at: this.localNow(), world: this.net.now() };
    if (did === this.did) {
      if (!this.mon.gaps.some((x) => x.key === key)) this.mon.gaps.push({ ...g, acked: false });
    } else if (!this.mon.auditGaps.some((x) => x.key === key)) this.mon.auditGaps.push(g);
  }

  /** Where a witness's history of an account starts. Its starting commit
   * may be one first published at a non-increasing revision, which a
   * witness not following the account then cannot tell. A cursor set by a
   * commit the relay sequenced before the witness started following, and
   * above the starting revision, or at it with a different commit, is an
   * integrity alarm, with the starting commit kept as proof, and a gap from
   * the starting revision through the cursor. A cursor set after the
   * witness started is past its start by construction. The order is by
   * the relay's sequence numbers, kept with the cursor and reported by the
   * witness: relay times are not unique. Where it can't be established (a
   * cursor carried without a sequence number), the same interval is a gap,
   * a warning rather than an alarm. */
  private startCheck(did: Did, cursor: number, e: Extract<HistoryEntry, { kind: "gap" }>): void {
    const s = e.startCommit;
    if (!e.start || !s) return;
    const set = this.mon.cursorSeqs.get(did);
    const known = set !== undefined && e.followedAfter !== undefined;
    if (known && set > e.followedAfter!) return; // sequenced after the witness started following: past its start
    const view = this.trust.state.views.get(did);
    const below = s.rev < cursor;
    const differs = s.rev === cursor && view?.rev === cursor && view.data !== s.data;
    if (!below && !differs) return;
    if (!known) {
      this.recordGap(did, `${did}:start-order:${e.id}:${cursor}`, s.rev, cursor, null, "the witness's history starts at a commit the relay may have sequenced after this device's cursor");
      return;
    }
    if (!this.startProofs.some((p) => p.did === did && p.start.rev === s.rev && p.cursor === cursor)) this.startProofs.push({ did, start: s, cursor });
    this.trust.raise(`relay-integrity:start:${did}:${s.rev}:${cursor}`, "relay-integrity",
      `The witness's history of ${did} starts at the relay's commit at revision ${s.rev}, ${below ? `below revision ${cursor}, which the relay published before it` : `a different commit from the one this device holds at that revision`}: revisions must increase.`, did);
    this.recordGap(did, `${did}:start-check:${e.id}:${cursor}`, s.rev, cursor, s.rev, "the witness's history starts at a commit published at a non-increasing revision");
  }

  /** A gap the witness reports, for the part after `cursor`: history from
   * before the cursor was already checked (with another witness, perhaps). */
  private witnessGap(did: Did, cursor: number, e: Extract<HistoryEntry, { kind: "gap" }>): void {
    const from = Math.max(e.fromRev, cursor + 1);
    if (from <= e.toRev) this.recordGap(did, `${did}:${e.id}`, from, e.toRev, e.rev, e.reason);
  }

  /** Keep, with `did`'s cursor, the relay sequence number of the commit
   * that set it, or forget it where that is unknown. */
  private cursorSeq(did: Did, seq: number | undefined): void {
    if (seq === undefined) this.mon.cursorSeqs.delete(did);
    else this.mon.cursorSeqs.set(did, seq);
  }

  /** Integrity alarms the witness raised for an account's history. */
  private integrity(did: Did, r: HistoryResponse): void {
    for (const x of r.integrity)
      this.trust.raise(`relay-integrity:${x.id}`, "relay-integrity", `The reference relay published ${did}'s commit at revision ${x.rev} after one at revision ${x.after}: revisions must increase.`, did);
  }

  /** The PDS may still serve records, but a commit it serves is checked
   * against the witness: a different commit at a witnessed revision is a
   * fork, and so is one strictly between two commits the witness
   * reconstructed consecutively (the later a `#commit` whose `since` names
   * the earlier's revision and whose operations invert to its root), which
   * the relay never published in order; one inside
   * a recorded gap is what the witness could not check, neither an alarm nor
   * INCOMPLETE; one above the witness's latest is INCOMPLETE. */
  private crossCheck(w: WitnessApi, did: Did): void {
    const snap = this.net.enumerate(this.id, did);
    const key = this.net.repoKey(did);
    if (!snap || !key || !verifySnapshot(snap, did, key)) return;
    const rev = snap.commit.rev;
    const vouch = w.commitAt(this.id, did, rev);
    if (vouch.status === "reconstructed") {
      this.mon.incomplete.delete(did);
      if (vouch.data !== snap.commit.data)
        this.trust.raise(`fork:${did}:${rev}`, "fork", `${did}'s PDS served a commit at revision ${rev} that differs from the one the relay published.`, did);
      return;
    }
    if (vouch.status === "unpublished") {
      this.mon.incomplete.delete(did);
      if (!this.unrelayedProofs.some((p) => p.did === did && p.served.rev === rev)) this.unrelayedProofs.push({ did, served: snap.commit, below: vouch.below, above: vouch.above });
      this.trust.raise(`unrelayed:${did}:${rev}`, "unrelayed-commit", `${did}'s PDS served a commit at revision ${rev} that the relay never published: it lies between two commits the relay published one after the other.`, did);
      return;
    }
    if (vouch.status === "unknown" && rev > (this.trust.state.views.get(did)?.rev ?? 0)) {
      this.mon.incomplete.add(did);
      this.decide(`INCOMPLETE ${did}@${rev}: the witness does not report this commit`);
      return;
    }
    this.mon.incomplete.delete(did);
  }

  /** Coverage age for the own account, in hours. */
  coverageAge(): number {
    const c = this.mon.coverage;
    if (!c) return Infinity;
    return c.base + Math.max(0, this.net.now() - c.mono);
  }

  /** Advance the monitoring frontier after processing everything the
   * witness reported, in an answer to a request sent at `sent` (the first
   * page's): the reported frontier age plus the time since then, in transit
   * included. Only better coverage counts: a quick answer with a stale
   * frontier, or a late answer whose frontier is older than the coverage
   * held, changes nothing. */
  private advance(frontierAge: number, sent: number): void {
    if (frontierAge + Math.max(0, this.net.now() - sent) < this.coverageAge()) this.mon.coverage = { base: frontierAge, mono: sent };
    this.segment();
  }

  /** Ground truth for the goal check: a new segment whenever coverage or
   * the own cursor changes. */
  private segment(): void {
    const now = this.net.now();
    const cursor = this.mon.cursors.get(this.did) ?? -1;
    const base = this.coverageAge();
    const last = this.segments[this.segments.length - 1];
    if (last && last.cursor === cursor && Math.abs(last.base + (now - last.world) - base) < 1e-9) return;
    this.segments.push({ world: now, base, cursor });
  }

  /** Save the coverage checkpoint (wall clock), for restarts and backups. */
  private checkpoint(): void {
    this.mon.checkpoint = { wall: this.localNow(), age: this.coverageAge() };
  }

  /** A restart: carry coverage by the wall-clock interval since the last
   * checkpoint; if that can't be established, coverage is unknown. */
  private restart(): void {
    const cp = this.mon.checkpoint;
    const d = cp ? this.localNow() - cp.wall : -1;
    this.mon.coverage = cp && d >= 0 && Number.isFinite(cp.age) ? { base: cp.age + d, mono: this.net.now() } : null;
    this.segment();
  }

  /** The liveness warning, or null: shown whenever coverage age exceeds 24
   * hours, naming what failed. It cannot be dismissed, and acknowledging a
   * gap does not affect it. */
  liveness(): string | null {
    if (!this.witnessed) return null;
    const age = this.coverageAge();
    if (age <= LIVENESS_LIMIT) return null;
    const cause = !this.mon.reachable ? "is unreachable"
      : this.mon.fault === "clock" ? "reports a clock fault: its relay's times are ahead of its clock"
      : this.mon.fault === "fetch" ? "is waiting on a fetch of your account's repo"
      : "is behind the relay";
    return `Your app's witness ${cause}: device changes on your account can't be checked.`;
  }

  /** Own-account gap warnings not yet acknowledged. */
  gapWarnings(): GapWarning[] {
    return this.mon.gaps.filter((g) => !g.acked);
  }

  /** Acknowledge one gap warning; it acknowledges only that gap. */
  acknowledgeGap(key: string): void {
    const g = this.mon.gaps.find((x) => x.key === key);
    if (g) g.acked = true;
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
    return [st.accepted.size, st.revoked.size, holds, keys, this.writes, st.alarms.length, st.notices.length, this.inviteOutbox.length, this.mon.gaps.length, [...this.mon.cursors.values()].join(",")].join("|");
  }
}

export function freshRng(label: string): Rng {
  return Rng.fromLabel(label);
}
