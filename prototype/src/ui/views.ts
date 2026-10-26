// Read-only views over a World for the UI. Each installation's status is
// derived from its own trust state, so the inspector shows where
// installations disagree.

import type { Installation } from "../protocol/installation";
import { recordsIn } from "../protocol/repo";
import { REENROLL_HOLD, fmtHour } from "../protocol/trust";
import { type Binding, COL, bindingId } from "../protocol/types";
import type { World } from "../world/world";

export const short = (did: string) => did.replace("did:plc:", "");

/** Protocol notices name accounts by DID; show handles instead. */
export const readable = (text: string) => text.replace(/did:plc:/g, "");

export function clock(h: number): string {
  return fmtHour(h);
}

/** Every device binding ever published, in order of first appearance. */
export function allBindings(w: World): Binding[] {
  const out = new Map<string, Binding>();
  for (const pds of w.pdses.values())
    for (const repo of pds.repos.values()) {
      if (repo.name.includes("|")) continue;
      for (const snap of repo.history)
        for (const [, v] of recordsIn(snap, COL.device)) {
          const b = (v as { value: Binding }).value;
          out.set(bindingId(b), b);
        }
    }
  return [...out.values()];
}

/** Turn a protocol label (`did:plc:bob/1a2b3c`) into an installation ID. */
export function labelName(w: World, lbl: string | null): string {
  if (!lbl) return "";
  const m = /^did:plc:([^/]+)\/([0-9a-f]{6})$/.exec(lbl);
  if (!m) return lbl;
  for (const i of w.installations.values()) if (i.binding.device.deviceId.startsWith(m[2]) && i.did === `did:plc:${m[1]}`) return i.id;
  return `${m[1]}/${m[2]}`;
}

export function deviceName(w: World, b: Binding): string {
  for (const i of w.installations.values()) if (i.binding.device.deviceId === b.device.deviceId) return i.name;
  return b.device.deviceId.slice(0, 6);
}

export function present(w: World, b: Binding): boolean {
  const rec = w.pdsOf.get(b.account)?.repo(b.account).records.get(`${COL.device}/${b.device.deviceId}`) as { value?: Binding } | undefined;
  return !!rec?.value && bindingId(rec.value) === bindingId(b);
}

export type TrustStatus = "own" | "accepted" | "held" | "revoked" | "unlinked" | "unknown";

/** `spaceName` labels per-space grant standing under the inviters policy. */
export function trustStatus(viewer: Installation, b: Binding, spaceName: (uri: string) => string = (u) => u): { status: TrustStatus; detail: string } {
  const st = viewer.trust.state;
  const id = bindingId(b);
  if (id === bindingId(viewer.binding)) return { status: "own", detail: "this device" };
  if (st.revoked.has(id)) return { status: "revoked", detail: "removed" };
  const a = st.accepted.get(id);
  if (a && viewer.trust.policy === "inviters" && b.account !== viewer.did) {
    // Grant standing per joined space (device-enrollment.md#grant-standing).
    const spaces = [...viewer.spaces.keys()].map((s) => {
      const basis = viewer.trust.standingBasis(b, s);
      const left = viewer.trust.firstContactRemaining(b);
      return `${spaceName(s)}: ${basis ?? (left === null ? "no standing" : `first-contact hold, shares from ${clock(viewer.localNow() + left)}`)}`;
    });
    return { status: "accepted", detail: [a.evidence, ...spaces].join("; ") };
  }
  if (a) return { status: "accepted", detail: a.evidence };
  const h = st.holds.get(b.account);
  if (h?.candidate.includes(id)) {
    const left = viewer.holdRemaining(b.account) ?? REENROLL_HOLD;
    return { status: "held", detail: `shares from ${clock(viewer.localNow() + left)}` };
  }
  const view = st.views.get(b.account);
  if (view?.present.get(b.device.deviceId)) return { status: "unlinked", detail: "isn't linked to their other devices" };
  return { status: "unknown", detail: "not seen" };
}

export type SpaceStatus = { joined: boolean; invited: boolean; hasKey: boolean; keyFrom: string | null; sole: boolean; waiting: boolean };

export function spaceStatus(w: World, inst: Installation, uri: string): SpaceStatus {
  const sp = inst.spaces.get(uri);
  const m = w.host.membership(uri, inst.did);
  return {
    joined: !!sp,
    invited: !!m?.eligible,
    hasKey: !!sp?.key,
    keyFrom: sp?.keyFrom ?? null,
    sole: !!sp?.key && !sp.sawOtherHolder,
    waiting: !!sp && !sp.key,
  };
}

/** Spaces an installation can see: joined ones, plus ones its account is in. */
export function visibleSpaces(w: World, inst: Installation): string[] {
  return [...w.host.spaces.keys()].filter((uri) => inst.spaces.has(uri) || w.host.membership(uri, inst.did)?.eligible);
}

export function accounts(w: World): string[] {
  return [...w.registry.keys()];
}

export function installationsOf(w: World, did: string): Installation[] {
  return [...w.installations.values()].filter((i) => i.did === did);
}
