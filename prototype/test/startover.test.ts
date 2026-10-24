// Starting over after total device loss (device-enrollment.md#total-device-loss,
// audit.md#direct-sync): the new installation presents the account's other
// devices as a list to remove, not as alarms, and treats grants to them as
// history once removed; anything else it hasn't accepted still alarms.

import { bindingId } from "../src/protocol/types";
import { REENROLL_HOLD } from "../src/protocol/trust";
import { World } from "../src/world/world";

function lostEverything(seed: string) {
  const w = new World(seed);
  const iphone = w.install(w.account("alice"), "iPhone");
  const ipad = w.install(iphone.did, "iPad", { link: iphone });
  const bob = w.install(w.account("bob"), "Pixel");
  const space = iphone.createSpace("Book club");
  iphone.invite(space, bob.did);
  bob.join(space);
  ipad.join(space);
  w.settle();
  for (const i of [iphone, ipad]) w.setOnline(i, false);
  return { w, iphone, ipad, bob, space };
}

const kinds = (i: { trust: { state: { alarms: { kind: string }[] } } }) => i.trust.state.alarms.map((a) => a.kind);

describe("starting over", () => {
  it("lists the old devices instead of alarming, and keeps grants to them as history", () => {
    const { w, iphone, ipad, space } = lostEverything("so1");
    const fresh = w.install(iphone.did, "New iPhone", { startOver: true });
    const list = fresh.trust.state.startOver!.list!;
    expect([...list.keys()].sort()).toEqual([bindingId(iphone.binding), bindingId(ipad.binding)].sort());
    expect(kinds(fresh)).toEqual([]);

    w.finishStartOver(fresh);
    fresh.join(space);
    w.advance(REENROLL_HOLD + 1);
    expect(fresh.spaces.get(space)!.key).toBeTruthy();
    // The iPad's old grant is in Book club, but it is history, not a detection.
    expect(fresh.trust.startOverHistory(ipad.binding)).toBe(true);
    expect(kinds(fresh)).toEqual([]);
  });

  it("alarms on a device an attacker with the password adds during the hold", () => {
    const { w, iphone } = lostEverything("so2");
    const fresh = w.install(iphone.did, "New iPhone", { startOver: true });
    w.finishStartOver(fresh);
    w.install(iphone.did, "attacker");
    expect(kinds(fresh)).toContain("unapproved-own");
  });

  it("alarms on a device that appears before the removal but after the list was shown", () => {
    const { w, iphone } = lostEverything("so3");
    const fresh = w.install(iphone.did, "New iPhone", { startOver: true });
    w.install(iphone.did, "attacker");
    expect(kinds(fresh)).toContain("unapproved-own");
  });

  it("alarms when a removed device's record comes back", () => {
    const { w, iphone, ipad } = lostEverything("so4");
    const fresh = w.install(iphone.did, "New iPhone", { startOver: true });
    w.finishStartOver(fresh);
    expect(kinds(fresh)).toEqual([]);
    w.recreateRecord(ipad);
    expect(kinds(fresh)).toContain("unapproved-own");
  });

  it("alarms on a grant to a binding a malicious PDS substituted for members", () => {
    const { w, iphone, bob, space } = lostEverything("so5");
    // From the reset on, the PDS shows members its own device in place of
    // the account's real ones, so Bob holds and then accepts the substitute.
    const sub = w.substituteDevices(iphone.did, bob);
    sub.join(space);
    const fresh = w.install(iphone.did, "New iPhone", { startOver: true });
    w.finishStartOver(fresh);
    fresh.join(space);
    w.advance(REENROLL_HOLD + 1);
    expect(sub.spaces.get(space)!.key).toBeTruthy(); // the disclosure happened
    expect(kinds(fresh)).toContain("unapproved-grant"); // and the start-over device detects it
  });

  it("leaves an ordinary unlinked install alarming on every other device", () => {
    const { w, iphone } = lostEverything("so6");
    const unlinked = w.install(iphone.did, "Unlinked");
    expect(kinds(unlinked).filter((k) => k === "unapproved-own")).toHaveLength(2);
  });
});
