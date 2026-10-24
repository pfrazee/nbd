// Key grants (core.md#key-grants): AuthorizeExchange G1-G5, grant
// construction under nbd-hpke-v1, and AcceptGrant A1-A7. Evidence is
// simplified to the exact blocks the grant references plus the approvals and
// commits each side relied on.

import { type Cbor, cbor, ref } from "./encoding";
import {
  type KeyPair, type Rng, digest, encryptionKeyPair, fingerprint, hpkeOpenBase, hpkeSealBase, sign, verify,
} from "./crypto";
import type { Trust } from "./trust";
import {
  type Binding, type Configuration, type DeviceIdentity, type Evidence, type Membership, type SpaceKeyGrant,
  asCbor, bindingId, label, sameBinding, withoutProof,
} from "./types";

export type Result = "OK" | "INVALID" | "INCOMPLETE" | "BLOCKED";
export type Decision = { result: Result; reason: string };

const ok = (reason = "ok"): Decision => ({ result: "OK", reason });
const fail = (result: Result, reason: string): Decision => ({ result, reason });

/** What this installation retains about a space from authenticated host reads. */
export type HostView = {
  config: Configuration | null;
  firstKeyId: string | null;
  firstCommitment: Uint8Array | null;
  memberships: Map<string, Membership>;
};

export function commitment(space: string, keyId: string, key: Uint8Array): Uint8Array {
  return digest(cbor(["nbd/key", 1, space, keyId, key]));
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function identity(b: Binding): DeviceIdentity {
  return { account: b.account, deviceId: b.device.deviceId };
}

/** G1-G5. `other` is the binding the local installation verifies. */
export function authorizeExchange(
  trust: Trust, host: HostView, space: string, issuer: Binding, recipient: Binding, role: "issuer" | "recipient", own: Binding,
): Decision {
  // G1: host evidence.
  const c = host.config;
  if (!c) return fail("INCOMPLETE", "no authenticated configuration");
  if (c.space !== space || c.grantProfile !== "nbd-hpke-v1") return fail("INVALID", "configuration mismatch");
  const mi = host.memberships.get(issuer.account);
  const mr = host.memberships.get(recipient.account);
  if (!mi || !mr) return fail("INCOMPLETE", "membership decision unavailable");
  // G2/G3: local trust and eligibility.
  const local = role === "issuer" ? issuer : recipient;
  const other = role === "issuer" ? recipient : issuer;
  if (!sameBinding(local, own)) return fail("INVALID", "local installation does not match its role");
  if (!trust.isAccepted(own)) return fail("BLOCKED", "this device is revoked");
  if (!mi.eligible || !mr.eligible) return fail("BLOCKED", "an account is not a member");
  if (!trust.isAccepted(other)) {
    if (trust.state.revoked.has(bindingId(other))) return fail("BLOCKED", `${label(other)} is revoked`);
    if (trust.hold(other.account)?.candidate.includes(bindingId(other))) return fail("INCOMPLETE", `${label(other)} is held for re-enrollment`);
    return fail("INCOMPLETE", `${label(other)} is not accepted`);
  }
  // G4/G5: acceptance rests on this client's own trust state.
  return ok(`${label(other)} accepted (${trust.state.accepted.get(bindingId(other))!.evidence})`);
}

function grantHeader(g: Omit<SpaceKeyGrant, "encapsulation" | "ciphertext" | "proof">): Cbor {
  return asCbor(g);
}

export function buildGrant(opts: {
  space: string; key: Uint8Array; config: Configuration; issuer: Binding; issuerSign: KeyPair; recipient: Binding;
  issuerMembership: Membership; recipientMembership: Membership; extraBlocks: Cbor[]; rng: Rng;
}): { grant: SpaceKeyGrant; evidence: Evidence } {
  const { space, key, config, issuer, recipient } = opts;
  const evidence: Evidence = {
    version: 1, space,
    blocks: [asCbor(recipient), asCbor(issuer), asCbor(config), asCbor(opts.recipientMembership), asCbor(opts.issuerMembership), ...opts.extraBlocks],
  };
  const header = {
    version: 1 as const,
    space,
    keyId: config.keyId,
    recipient: identity(recipient),
    recipientKeyId: fingerprint("X25519", recipient.device.encryptPubkey),
    authorization: {
      recipientBinding: ref(asCbor(recipient)),
      issuerBinding: ref(asCbor(issuer)),
      configuration: ref(asCbor(config)),
      recipientMembership: ref(asCbor(opts.recipientMembership)),
      issuerMembership: ref(asCbor(opts.issuerMembership)),
      evidence: ref(asCbor(evidence)),
    },
    grantProfile: "nbd-hpke-v1" as const,
    issuer: identity(issuer),
    issuerKeyId: fingerprint("Ed25519", issuer.device.authPubkey),
  };
  const H = grantHeader(header);
  const info = cbor(["nbd/grant-info", 1, H]);
  const aad = cbor(["nbd/grant-aad", 1, H]);
  const sealed = hpkeSealBase(recipient.device.encryptPubkey, info, aad, key, encryptionKeyPair(opts.rng));
  const unsigned = { ...header, encapsulation: sealed.enc, ciphertext: sealed.ciphertext };
  const proof = sign(opts.issuerSign.secretKey, ["nbd/grant-signature", 1, asCbor(unsigned)]);
  return { grant: { ...unsigned, proof }, evidence };
}

function findBlock<T>(e: Evidence, r: string): T | null {
  return (e.blocks.find((b) => ref(b) === r) as T | undefined) ?? null;
}

/** A1-A7. Returns the key on OK. */
export function acceptGrant(opts: {
  grant: SpaceKeyGrant; evidence: Evidence | null; space: string; own: Binding; ownEnc: KeyPair; trust: Trust;
  host: HostView; mode: "current" | "archive";
}): Decision & { key?: Uint8Array; issuer?: Binding } {
  const { grant: g, evidence: e, own, trust, host } = opts;
  // A1: decode and match.
  if (g.version !== 1 || g.grantProfile !== "nbd-hpke-v1" || g.space !== opts.space) return fail("INVALID", "grant fields");
  if (g.recipient.account !== own.account || g.recipient.deviceId !== own.device.deviceId
    || g.recipientKeyId !== fingerprint("X25519", own.device.encryptPubkey)) return fail("INVALID", "not addressed to this device");
  // A2: evidence and signature.
  if (!e) return fail("INCOMPLETE", "evidence unavailable");
  if (ref(asCbor(e)) !== g.authorization.evidence || e.space !== opts.space) return fail("INVALID", "evidence does not match grant");
  const rb = findBlock<Binding>(e, g.authorization.recipientBinding);
  const ib = findBlock<Binding>(e, g.authorization.issuerBinding);
  const cfg = findBlock<Configuration>(e, g.authorization.configuration);
  const mr = findBlock<Membership>(e, g.authorization.recipientMembership);
  const mi = findBlock<Membership>(e, g.authorization.issuerMembership);
  if (!rb || !ib || !cfg || !mr || !mi) return fail("INCOMPLETE", "required evidence missing");
  if (!sameBinding(rb, own)) return fail("INVALID", "recipient binding mismatch");
  if (ib.account !== g.issuer.account || ib.device.deviceId !== g.issuer.deviceId
    || fingerprint("Ed25519", ib.device.authPubkey) !== g.issuerKeyId) return fail("INVALID", "issuer binding mismatch");
  if (!verify(g.proof, ["nbd/grant-signature", 1, asCbor(withoutProof(g))], ib.device.authPubkey)) return fail("INVALID", "bad issuer signature");
  // A3: key ID against the authenticated configuration.
  if (!host.config || host.config.keyId !== g.keyId || cfg.keyId !== g.keyId) return fail("INVALID", "key ID mismatch");
  // A4: recorded basis, then current authorization.
  if (!mr.eligible || mr.account !== own.account || !mi.eligible || mi.account !== ib.account) return fail("BLOCKED", "recorded membership does not authorize");
  if (opts.mode === "current") {
    const d = authorizeExchange(trust, host, opts.space, ib, own, "recipient", own);
    if (d.result !== "OK") return d;
  }
  // A5: issuer trust (archive may use a formerly accepted binding).
  const formerly = trust.state.accepted.has(bindingId(ib));
  if (opts.mode === "current" ? !trust.isAccepted(ib) : !formerly) return fail("BLOCKED", `issuer ${label(ib)} not accepted`);
  // A6: open and check the commitment.
  const { encapsulation, ciphertext, proof: _p, ...header } = g;
  let key: Uint8Array;
  try {
    key = hpkeOpenBase(opts.ownEnc, encapsulation, cbor(["nbd/grant-info", 1, asCbor(header)]),
      cbor(["nbd/grant-aad", 1, asCbor(header)]), ciphertext);
  } catch {
    return fail("INVALID", "HPKE open failed");
  }
  if (key.length !== 32 || !eq(commitment(opts.space, g.keyId, key), host.config.commitment)) return fail("INVALID", "key does not match commitment");
  // A7: the caller retains key, grant, evidence, and decision.
  return { ...ok(`from ${label(ib)}`), key, issuer: ib };
}

export function keyRequestPayload(r: object): unknown[] {
  return ["nbd/key-request", 1, asCbor(r)];
}
