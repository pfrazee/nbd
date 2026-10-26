// Protocol values (device-enrollment.md, core.md). Field names follow the
// specification; collection names live under com.example.nbd.

import { type Cbor, ref } from "./encoding";

export type Did = string;

/** Which grant rule installations follow: "inviters", the specified rule
 * with grant standing (device-enrollment.md#grant-standing) and invites
 * (core.md#invites), or "baseline", the rule from before it, kept for
 * comparison. */
export type Policy = "baseline" | "inviters";

export type Device = { deviceId: string; authPubkey: Uint8Array; encryptPubkey: Uint8Array };
export type Binding = { account: Did; device: Device };
export type DeviceIdentity = { account: Did; deviceId: string };

export type Approval = { version: 1; signer: Binding; target: Binding; proof: Uint8Array };

export type KeyRequest = {
  version: 1;
  space: string;
  recipient: Binding;
  issuer: DeviceIdentity | null;
  proof: Uint8Array;
};

export type Configuration = {
  version: 1;
  kind: "configuration";
  space: string;
  revision: number;
  grantProfile: "nbd-hpke-v1";
  keyId: string;
  commitment: Uint8Array;
  maxEncryptedBlobBytes: number;
};

export type Membership = {
  version: 1;
  kind: "membership";
  space: string;
  account: Did;
  revision: number;
  eligible: boolean;
};

export type SpaceKeyGrant = {
  version: 1;
  space: string;
  keyId: string;
  recipient: DeviceIdentity;
  recipientKeyId: string;
  authorization: {
    recipientBinding: string;
    issuerBinding: string;
    configuration: string;
    recipientMembership: string;
    issuerMembership: string;
    evidence: string;
  };
  grantProfile: "nbd-hpke-v1";
  encapsulation: Uint8Array;
  ciphertext: Uint8Array;
  issuer: DeviceIdentity;
  issuerKeyId: string;
  proof: Uint8Array;
};

/** An invite record in the inviting account's space repo
 * (core.md#invites). `authorizes`: the listed bindings
 * that were in the inviting device's first-contact lineage when it made the record, which
 * may grant in this space at once. A pending invite (`pending`, no bindings)
 * admits an account that has no devices yet; a capture record (`captures`:
 * the pending record's rkey) later authorizes the devices the inviting
 * device first met for it, in the pending invite's space. */
export type Invite = {
  version: 1;
  space: string;
  account: Did;
  bindings: Binding[];
  authorizes: Binding[];
  pending: boolean;
  captures: string | null;
  issuer: DeviceIdentity;
  proof: Uint8Array;
};

/** Simplified evidence: the manifest plus the exact blocks it names, so a
 * reader can resolve every reference without the source PDS (audit.md#evidence). */
export type Evidence = { version: 1; space: string; blocks: Cbor[] };

export type Envelope = {
  $type: "com.example.nbd.envelope";
  format: 1;
  keyId: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  blobs: Cbor[];
};

export const NS = "com.example.nbd";
export const COL = {
  device: `${NS}.device`,
  approval: `${NS}.approval`,
  grant: `${NS}.grant`,
  evidence: `${NS}.evidence`,
  keyRequest: `${NS}.keyRequest`,
  invite: `${NS}.invite`,
  message: "app.example.message",
} as const;

export function asCbor<T>(x: T): Cbor {
  return x as unknown as Cbor;
}

// Bindings are immutable once published, so IDs are cached per object.
const ids = new WeakMap<Binding, string>();

export function bindingId(b: Binding): string {
  let id = ids.get(b);
  if (id === undefined) {
    id = ref(["nbd/device-binding", 1, asCbor(b)]);
    ids.set(b, id);
  }
  return id;
}

export function sameBinding(a: Binding, b: Binding): boolean {
  return bindingId(a) === bindingId(b);
}

export function label(b: Binding | DeviceIdentity): string {
  const id = "device" in b ? b.device.deviceId : b.deviceId;
  return `${b.account}/${id.slice(0, 6)}`;
}

export function withoutProof<T extends { proof: Uint8Array }>(x: T): Omit<T, "proof"> {
  const { proof: _proof, ...rest } = x;
  return rest;
}
