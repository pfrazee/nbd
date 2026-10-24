// The cast and shared setups for the figures: Alice (iPhone, iPad), Bob
// (Pixel), Carol, and Mum, in Book club and Family.

import type { World } from "../../world/world";
import { COPY, type Mode, START_OVER } from "../copy";
import { check } from "../../sim/scenario";
import type { FigureCtx, Panel } from "../figure";
import { Phone } from "../frames";
import { alarmsOf, members, startOverList, timeline } from "../model";
import { ScanConfirm, SpaceView, StartOverList } from "../screens";

type C = FigureCtx;
const T = COPY.relaxed;

export function people(w: World, c: C): void {
  const alice = w.account("alice");
  c.i.iphone = w.install(alice, "iPhone");
  c.i.ipad = w.install(alice, "iPad", { link: c.i.iphone });
  c.i.bob = w.install(w.account("bob", "pds.bob.example"), "Pixel");
  c.i.carol = w.install(w.account("carol"), "iPhone");
}

export function say(w: World, i: C["i"][string], space: string, text: string): void {
  w.advance(0.05);
  i.post(space, text);
  w.settle();
}

/** Alice (iPhone, iPad), Bob, and Carol in Book club; Alice and Mum in Family. */
export function bookClub(w: World, c: C): void {
  people(w, c);
  c.i.mum = w.install(w.account("mum"), "iPhone");
  c.space.club = c.i.iphone.createSpace("Book club");
  c.space.family = c.i.iphone.createSpace("Family");
  for (const d of [c.i.bob, c.i.carol]) c.i.iphone.invite(c.space.club, d.did);
  c.i.iphone.invite(c.space.family, c.i.mum.did);
  for (const i of [c.i.ipad, c.i.bob, c.i.carol]) i.join(c.space.club);
  c.i.ipad.join(c.space.family);
  c.i.mum.join(c.space.family);
  w.settle();
  say(w, c.i.mum, c.space.family, "see you Sunday!");
  say(w, c.i.iphone, c.space.club, "Next up: Middlemarch, chapters 1–10");
  say(w, c.i.carol, c.space.club, "ambitious!!");
  say(w, c.i.bob, c.space.club, "I'm in. Starting tonight 📚");
}

export const club = (w: World, c: C, me: C["i"][string], extra: Partial<Parameters<typeof SpaceView>[0]> = {}, space = c.space.club) => (
  <SpaceView title={w.host.spaceName(space)} subtitle={members(w, me, space)} bubbles={timeline(w, me, space)} composer={T.message} {...extra} />
);

export const scanConfirmFor = (mode: Mode, device: string, T = COPY[mode]) => (
  <Phone dark>
    <ScanConfirm title={T.linkConfirmTitle(device)} body={T.linkConfirmBody} warning={T.linkConfirmWarning} confirm={T.linkButton} cancel={T.cancel} />
  </Phone>
);

export function clubWithoutBob(w: World, c: C): void {
  people(w, c);
  c.space.club = c.i.iphone.createSpace("Book club");
  c.i.iphone.invite(c.space.club, c.i.carol.did);
  c.i.carol.join(c.space.club);
  c.i.ipad.join(c.space.club);
  w.settle();
  say(w, c.i.iphone, c.space.club, "Next up: Middlemarch, chapters 1–10");
  say(w, c.i.carol, c.space.club, "ambitious!!");
}

/** Losing every device: the old devices the new phone lists for Alice to
 * check, instead of an alarm for each (device-enrollment.md#total-device-loss). */
export const checkOldDevices = (at: number): Panel => ({
  label: "Check them", device: "Alice's new phone", at,
  view: (w, c) => <Phone><StartOverList {...START_OVER} rows={startOverList(w, c.i.fresh)} /></Phone>,
  caption: "She checks she **recognises every device**, then approves removing them all at her provider. **No alarm for each:** this phone can't tell her old devices from anyone else's.",
  expect: (w, c) => [
    check("The list is her iPhone and iPad", startOverList(w, c.i.fresh).map((r) => r.name).sort().join() === "iPad,iPhone"),
    check("The new phone raises no alarm for them", alarmsOf(c.i.fresh).length === 0),
  ],
});
