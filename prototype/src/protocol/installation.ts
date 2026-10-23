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
import { type Snapshot, type WriteOp, recordsIn, verifySnapshot } from "./repo";
import { type TrustState, REENROLL_HOLD, Trust, approvalPayload, cloneTrust, emptyTrust } from "./trust";
import {
  type Approval, type Binding, COL, type Configuration, type Did, type Envelope, type Evidence, type KeyRequest,
  type Membership, type SpaceKeyGrant, asCbor, bindingId, label, sameBinding, withoutProof,
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
  write(sessionId: string, ops: WriteOp[], space?: string): void;
  spaceWriters(space: string): Did[];
  host: HostApi;
}

export type Message =
  | { author: Did; rkey: string; text: string; device: string; at: number }
  | { author: Did; rkey: string; locked: true; at: number };

type SpaceLocal = {
  uri: string;
  host: HostView;
  key: Uint8Array | null;
  keyFrom: string | null;
  credentialExpiry: number;
  requested: string | null; // rkey of this device's key request
  issued: Set<string>; // recipient binding IDs this device granted to
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
    this.trust = new Trust(state, this.binding, () => this.localNow());
  }

  get did(): Did {
    return this.binding.account;
  }

  localNow(): number {
    return this.net.now() + this.clockOffset;
  }

  private write(ops: WriteOp[], space?: string): boolean {
    if (!this.sessionId) return false;
    try {
      this.net.write(this.sessionId, ops, space);
      this.writes++;
      return true;
    } catch {
      return false;
    }
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
    const id = bindingId(target.binding);
    this.trust.state.approvedByMe.add(id);
    this.trust.state.accepted.set(id, { binding: target.binding, evidence: `approved by ${label(this.binding)} (this device)` });
    return this.write([
      { action: "create", collection: COL.approval, rkey: ref(asCbor(approval)), value: { $type: COL.approval, value: asCbor(approval) } },
      target.deviceRecord(),
    ]);
  }

  /** Pairing copies pins from the approving installation. */
  pairFrom(approver: Installation): void {
    this.imports++;
    this.trust.importFrom(cloneTrust(approver.trust.state));
    this.trust.state.accepted.set(bindingId(this.binding), { binding: this.binding, evidence: "own" });
    this.trust.state.approvedByMe.add(bindingId(this.binding));
    // Own devices known at pairing are not news to this user.
    for (const [id, a] of this.trust.state.accepted) if (a.binding.account === this.did) this.trust.state.noticed.add(`added:${id}`);
  }

  exportState(): InstallationState {
    this.trust.tick();
    return { trust: cloneTrust(this.trust.state), spaces: new Map([...this.spaces].map(([k, s]) => [k, { ...s, issued: new Set(s.issued), outbox: [...s.outbox] }])) };
  }

  importState(s: InstallationState): void {
    this.imports++;
    this.trust.importFrom(cloneTrust(s.trust));
    for (const [uri, sp] of s.spaces) {
      const mine = this.spaces.get(uri);
      if (!mine) this.spaces.set(uri, { ...sp, issued: new Set(), outbox: [], requested: null });
      else if (!mine.key && sp.key) Object.assign(mine, { key: sp.key, keyFrom: "imported" });
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

  invite(space: string, account: Did): void {
    this.net.host.setMembership(this.did, space, account, true);
  }

  removeMember(space: string, account: Did): void {
    this.net.host.setMembership(this.did, space, account, false);
  }

  join(space: string): void {
    if (this.spaces.has(space)) return;
    this.spaces.set(space, {
      uri: space, key: null, keyFrom: null, credentialExpiry: -1, requested: null, issued: new Set(), outbox: [], sawOtherHolder: false,
      host: { config: null, firstKeyId: null, firstCommitment: null, memberships: new Map() },
    });
  }

  post(space: string, text: string): void {
    const sp = this.spaces.get(space);
    if (!sp) throw new Error("not joined");
    const rkey = randomId(this.rng);
    if (!sp.key) {
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
    for (const did of this.trackedAccounts()) this.observeAccount(did);
    for (const sp of this.spaces.values()) this.syncSpace(sp);
    return this.fingerprint() !== before;
  }

  trackedAccounts(): Did[] {
    const out = new Set<Did>([this.did]);
    for (const sp of this.spaces.values()) for (const d of this.net.host.knownAccounts(sp.uri)) out.add(d);
    return [...out];
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
    } else if (sp.host.firstKeyId !== cfg.keyId || ref(sp.host.firstCommitment!) !== ref(cfg.commitment)) {
      this.trust.raise(`host-integrity:${sp.uri}`, "host-integrity", `The host changed ${this.net.host.spaceName(sp.uri)}'s key commitment`);
      return;
    }
    if (!sp.host.config || cfg.revision >= sp.host.config.revision) sp.host.config = { ...cfg };
    for (const d of this.net.host.knownAccounts(sp.uri)) {
      const m = this.net.host.membership(sp.uri, d);
      const prev = sp.host.memberships.get(d);
      if (m && (!prev || m.revision > prev.revision)) {
        sp.host.memberships.set(d, m);
        if (prev && prev.eligible !== m.eligible)
          this.trust.notice(`member:${sp.uri}:${d}:${m.revision}`, "membership", `${d} was ${m.eligible ? "added to" : "removed from"} ${this.net.host.spaceName(sp.uri)}`);
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

    // Accept a grant addressed to this device.
    if (!sp.key) {
      for (const [, g, e] of grants) {
        if (g.recipient.account !== this.did || g.recipient.deviceId !== this.binding.device.deviceId) continue;
        const d = acceptGrant({ grant: g, evidence: e, space: sp.uri, own: this.binding, ownEnc: this.encKey, trust: this.trust, host: sp.host, mode: "current" });
        this.decide(`accept from ${label(g.issuer)}: ${d.result} ${d.reason}`);
        if (d.result === "OK" && d.key) {
          sp.key = d.key;
          sp.keyFrom = label(g.issuer);
          break;
        }
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
          this.trust.raise(`fork:${c.did}:${c.rev}`, "fork", `${c.did}'s PDS showed different histories: another member saw a different commit at revision ${c.rev}.`);
      }
    }

    // Audit grants to this account's bindings (audit.md#direct-sync).
    for (const [, g, e] of grants) {
      if (g.recipient.account !== this.did) continue;
      const rb = e?.blocks.find((b) => ref(b) === g.authorization.recipientBinding) as Binding | undefined;
      if (rb && !this.trust.state.accepted.has(bindingId(rb)))
        this.trust.raise(`grant-unapproved:${ref(asCbor(g))}`, "unapproved-grant",
          `A device you don't recognise (${label(rb)}) may have access to ${this.net.host.spaceName(sp.uri)}.`);
    }
    if ((sp.keyFrom && sp.keyFrom !== "generated") || grants.some(([, g]) => !(g.recipient.account === this.did && g.recipient.deviceId === this.binding.device.deviceId)))
      sp.sawOtherHolder = true;

    if (sp.key) {
      for (const d of sp.outbox.splice(0)) this.publishMessage(sp, d.rkey, d.text);
      if (sp.requested) {
        this.write([{ action: "delete", collection: COL.keyRequest, rkey: sp.requested }], sp.uri);
        sp.requested = null;
      }
      this.answerRequests(sp, requests, grants);
    } else if (!sp.requested && this.trust.isAccepted(this.binding)) {
      const unsigned = { version: 1 as const, space: sp.uri, recipient: this.binding, issuer: null };
      const req: KeyRequest = { ...unsigned, proof: sign(this.signKey.secretKey, keyRequestPayload(unsigned)) };
      const rkey = ref(asCbor(req));
      if (this.write([{ action: "create", collection: COL.keyRequest, rkey, value: { $type: COL.keyRequest, value: asCbor(req) } }], sp.uri))
        sp.requested = rkey;
    }
  }

  private answerRequests(sp: SpaceLocal, requests: [Did, string, KeyRequest][], grants: [Did, SpaceKeyGrant, Evidence | null][]): void {
    for (const [did, , req] of requests) {
      const r = req?.recipient;
      if (!r || r.account !== did || req.space !== sp.uri) continue;
      if (!verify(req.proof, keyRequestPayload(withoutProof(req)), r.device.authPubkey)) continue;
      const rid = bindingId(r);
      if (sameBinding(r, this.binding) || sp.issued.has(rid)) continue;
      if (grants.some(([, g]) => g.issuer.deviceId === this.binding.device.deviceId && g.recipient.deviceId === r.device.deviceId)) continue;
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
      // Publication: evidence first, then the grant (audit.md#publication).
      const er = ref(asCbor(evidence));
      if (!this.write([{ action: "create", collection: COL.evidence, rkey: er, value: { $type: COL.evidence, value: asCbor(evidence) } }], sp.uri)) continue;
      if (this.write([{ action: "create", collection: COL.grant, rkey: ref(asCbor(grant)), value: { $type: COL.grant, value: asCbor(grant) } }], sp.uri))
        sp.issued.add(rid);
    }
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
    const keys = [...this.spaces.values()].map((s) => `${s.uri}:${!!s.key}:${s.requested}:${s.issued.size}`).join(";");
    return [st.accepted.size, st.revoked.size, holds, keys, this.writes, st.alarms.length, st.notices.length].join("|");
  }
}

export function freshRng(label: string): Rng {
  return Rng.fromLabel(label);
}
