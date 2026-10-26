// Screen models: what an installation's screens show, derived from its real
// protocol state. Nothing here invents a hold, notice, or lock state.

import type { Installation } from "../protocol/installation";
import { recordsIn } from "../protocol/repo";
import type { Notice } from "../protocol/trust";
import { type Approval, type Binding, COL, type Invite, type KeyRequest, type SpaceKeyGrant, bindingId } from "../protocol/types";
import type { World } from "../world/world";
import { spaceStatus, trustStatus } from "../ui/views";

export const person = (did: string) => {
  const s = did.replace("did:plc:", "");
  return s.charAt(0).toUpperCase() + s.slice(1);
};

const DAYS = ["Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "Monday"];
/** World time 0 is a Tuesday morning, so a 72-hour hold ends on Friday. */
export const weekday = (h: number) => DAYS[Math.floor(h / 24) % 7];

/** The name a device reports for itself: the installation's name. */
export function deviceName(w: World, b: Binding | { device: { deviceId: string } } | undefined): string {
  if (!b) return "a device";
  for (const i of w.installations.values()) if (i.binding.device.deviceId === b.device.deviceId) return i.name;
  return "an unknown device";
}

export type Row = { uri: string; name: string; initials: string; preview: string; locked: boolean; invited: boolean; cta?: string };

const initials = (name: string) => name.split(/\s+/).map((p) => p[0]).join("").slice(0, 2).toUpperCase();

export function inbox(w: World, me: Installation): Row[] {
  const rows: Row[] = [];
  for (const uri of w.host.spaces.keys()) {
    const name = w.host.spaceName(uri);
    const sp = me.spaces.get(uri);
    if (!sp) {
      // A new device of the space's creator has nothing to accept, only a key to get.
      const own = w.host.admin(uri) === me.did;
      if (w.host.membership(uri, me.did)?.eligible)
        rows.push({ uri, name, initials: initials(name), preview: own ? "Open to get access" : `${person(w.host.admin(uri))} invited you`, locked: false, invited: true, cta: own ? "Open" : `Join ${name}` });
      continue;
    }
    const msgs = me.messages(uri);
    const last = msgs[msgs.length - 1];
    const preview = !sp.key ? "Getting access…" : last && "text" in last ? `${last.author === me.did ? "You" : person(last.author)}: ${last.text}` : "No messages yet";
    rows.push({ uri, name, initials: initials(name), preview, locked: !sp.key, invited: false });
  }
  return rows;
}

export type Bubble = { mine: boolean; author: string; text: string } | { line: string };

/** Messages interleaved with membership and reset lines, in time order. */
export function timeline(w: World, me: Installation, uri: string): Bubble[] {
  type Item = { at: number; b: Bubble };
  // Messages this device can't decrypt yet are not shown; the space shows
  // its locked state instead.
  const items: Item[] = me.messages(uri).flatMap((m) =>
    "text" in m ? [{ at: m.at, b: { mine: m.author === me.did, author: person(m.author), text: m.text } }] : []);
  const admin = w.host.admin(uri);
  const members = w.host.knownAccounts(uri);
  for (const n of me.trust.state.notices) {
    const at = n.at - me.clockOffset;
    if (n.kind === "membership" && n.account && n.text.endsWith(w.host.spaceName(uri))) {
      const who = n.account === me.did ? "you" : person(n.account);
      const by = admin === me.did ? "You" : person(admin);
      items.push({ at, b: { line: n.text.includes("added") ? `${by} added ${who}` : `${person(n.account)} was removed` } });
    }
    if (n.kind === "reset" && n.account && members.includes(n.account))
      items.push({ at, b: { line: `${person(n.account)} reset their devices. This device will share with their new device from ${weekday((n.until ?? 0) - me.clockOffset)}.` } });
  }
  return items.sort((a, b) => a.at - b.at).map((x) => x.b);
}

export function members(w: World, me: Installation, uri: string): string {
  const others = w.host.members(uri).filter((d) => d !== me.did).map(person);
  return [...others, "you"].join(", ");
}

/** The newest notice of a kind, if this installation has one. */
export function latestNotice(me: Installation, kind: string): Notice | undefined {
  return [...me.trust.state.notices].reverse().find((n) => n.kind === kind);
}

export function alarmsOf(me: Installation, kind?: string) {
  return me.trust.state.alarms.filter((a) => !kind || a.kind === kind);
}

export type DeviceRow = { name: string; status: string; detail: string; live: boolean; own: boolean; binding: Binding; linkedFrom?: string };

/** An account's devices as this installation sees them. */
export function devices(w: World, me: Installation, account: string): DeviceRow[] {
  return w.allBindings().filter((b) => b.account === account).flatMap((b) => {
    const t = trustStatus(me, b);
    if (t.status === "unknown") return [];
    const rec = w.pdsOf.get(account)!.repo(account).records.has(`${COL.device}/${b.device.deviceId}`);
    if (t.status === "revoked" && !rec) return [];
    return [{ name: deviceName(w, b), status: t.status, detail: t.detail, live: rec, own: bindingId(b) === bindingId(me.binding), binding: b, linkedFrom: linkedFrom(w, b) }];
  });
}

function spaceSnapshots(w: World, uri: string) {
  return w.spaceWriters(uri).map((did) => [did, w.pdsOf.get(did)!.repo(did, uri).latest()] as const);
}

/** Accounts with a key request no grant has answered yet. */
export function waiting(w: World, uri: string): string[] {
  const out = new Set<string>();
  const snaps = spaceSnapshots(w, uri);
  const granted = new Set(snaps.flatMap(([, s]) => recordsIn(s, COL.grant).map(([, v]) => (v as { value: SpaceKeyGrant }).value.recipient.deviceId)));
  for (const [did, s] of snaps)
    for (const [, v] of recordsIn(s, COL.keyRequest)) {
      const r = (v as { value: KeyRequest }).value;
      if (!granted.has(r.recipient.device.deviceId)) out.add(did);
    }
  return [...out];
}

export type AccessRow = { member: string; device: string; from: string; declined?: boolean };

/** Grants to each member's devices observed in the space, and devices this
 * installation declines as unlinked (audit.md#direct-sync). */
export function memberAccess(w: World, me: Installation, uri: string): AccessRow[] {
  // One row per device that received the key, listing every issuer.
  const byDevice = new Map<string, AccessRow & { issuers: string[] }>();
  for (const [, s] of spaceSnapshots(w, uri))
    for (const [, v] of recordsIn(s, COL.grant)) {
      const g = (v as { value: SpaceKeyGrant }).value;
      const row = byDevice.get(g.recipient.deviceId) ?? { member: person(g.recipient.account), device: deviceName(w, { device: { deviceId: g.recipient.deviceId } }), from: "", issuers: [] };
      row.issuers.push(`${person(g.issuer.account)}'s ${deviceName(w, { device: { deviceId: g.issuer.deviceId } })}`);
      byDevice.set(g.recipient.deviceId, row);
    }
  const rows: AccessRow[] = [...byDevice.values()].map(({ issuers, ...r }) => ({ ...r, from: issuers.join(", ") }));
  for (const d of w.host.members(uri))
    for (const r of devices(w, me, d)) if (r.status === "unlinked") rows.push({ member: person(d), device: r.name, from: "", declined: true });
  return rows;
}

/** Per-space status for a device that is recovering. */
export function recovery(w: World, me: Installation): { name: string; status: string }[] {
  return [...me.spaces.keys()].map((uri) => ({ name: w.host.spaceName(uri), status: me.spaces.get(uri)!.key ? "Unlocked" : "Waiting for members" }));
}

/** The device whose approval in the account's repo linked this one, if any. */
export function linkedFrom(w: World, b: Binding): string | undefined {
  const snap = w.pdsOf.get(b.account)!.repo(b.account).latest();
  if (!snap) return undefined;
  for (const [, v] of recordsIn(snap, COL.approval)) {
    const ap = (v as { value: Approval }).value;
    if (ap.target.device.deviceId === b.device.deviceId) return deviceName(w, ap.signer);
  }
  return undefined;
}

/** Whether this device is the only known holder of the space key (paranoid.md). */
export const soleHolder = (w: World, me: Installation, uri: string) => spaceStatus(w, me, uri).sole;

export type StartOverRow = { name: string; detail: string };

/** The devices a start-over installation lists for the user to check and
 * remove, with when each was added and what linked it. */
export function startOverList(w: World, me: Installation): StartOverRow[] {
  return [...(me.trust.state.startOver?.list?.values() ?? [])].map((b) => {
    const from = linkedFrom(w, b);
    return { name: deviceName(w, b), detail: `Added ${weekday(w.provenance.publishedAt.get(b.device.deviceId) ?? 0)}${from ? `, linked from ${from}` : ""}` };
  });
}

// ---- invites under grant standing (device-enrollment.md#grant-standing) ----------

/** Who invited each member of a space, from the invite records in its repos. */
export function inviters(w: World, uri: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const [did, s] of spaceSnapshots(w, uri))
    for (const [, v] of recordsIn(s, COL.invite)) {
      const r = (v as { value: Invite }).value;
      if (!r.captures && !out.has(r.account)) out.set(r.account, did);
    }
  return out;
}

/** The day this installation will share `uri`'s key with `account`, if it
 * is holding some of the account's live devices on first contact there. */
export function shareDay(me: Installation, uri: string, account: string): string | undefined {
  const left = me.trust.live(account).filter((b) => !me.trust.standing(b, uri))
    .map((b) => me.trust.firstContactRemaining(b)).filter((x): x is number => x !== null);
  if (!left.length) return undefined;
  return weekday(me.localNow() + Math.min(...left) - me.clockOffset);
}

export type MemberRow = { name: string; invitedBy?: string; shareFrom?: string };

/** A space's members as this installation sees them: who invited each, and
 * when this device will share with them if it is still waiting. */
export function memberList(w: World, me: Installation, uri: string): MemberRow[] {
  const by = inviters(w, uri);
  return w.host.members(uri).filter((d) => d !== me.did).map((d) => {
    const inviter = by.get(d);
    return { name: person(d), invitedBy: inviter && (inviter === me.did ? "you" : person(inviter)), shareFrom: me.spaces.get(uri)?.key ? shareDay(me, uri, d) : undefined };
  });
}

/** This installation's invites to a space that are saved but not yet
 * published, and the accounts it has a pending invite for there. */
export function inviteStatus(me: Installation, uri: string): { unsent: string[]; pending: string[] } {
  return {
    unsent: me.inviteOutbox.filter((e) => e.space === uri && !e.record.captures).map((e) => e.account),
    pending: [...me.trust.state.pending.values()].filter((p) => p.space === uri && !p.done).map((p) => p.account),
  };
}
