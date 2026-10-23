// The goal-level disclosure check must flag disclosures the goals forbid and
// accept the paths they permit, independent of the clients' own reasoning.

import { InvariantMonitor } from "../src/sim/invariants";
import { bindingId } from "../src/protocol/types";
import { World } from "../src/world/world";

function club(seed: string) {
  const w = new World(seed);
  const m = new InvariantMonitor(w);
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob"), "phone");
  const space = alice.createSpace("Club");
  alice.invite(space, bob.did);
  bob.join(space);
  w.settle();
  return { w, m, alice, bob, space };
}

const goal = (vs: string[]) => vs.filter((v) => v.startsWith("goal:"));

describe("disclosure check", () => {
  it("flags a client that shares with a takeover device before the hold", () => {
    const { w, m, alice, bob, space } = club("d1");
    m.before();
    const attacker = w.takeover(bob.did);
    attacker.join(space);
    // Simulate a client bug: Alice's app accepts the attacker's device at once.
    alice.trust.state.accepted.set(bindingId(attacker.binding), { binding: attacker.binding, evidence: "bug" });
    w.settle();
    expect(goal(m.after()).join()).toMatch(/alice\/phone granted to attacker device bob/);
  });

  it("permits disclosure after the hold elapses", () => {
    const { w, m, alice, bob, space } = club("d2");
    m.before();
    const attacker = w.takeover(bob.did);
    attacker.join(space);
    w.advance(72);
    expect(alice.trust.isAccepted(attacker.binding)).toBe(true);
    expect(goal(m.after())).toEqual([]);
  });

  it("permits the documented revoked-signer gap beside a live device", () => {
    const { w, m, alice, bob, space } = club("d3");
    const laptop = w.install(bob.did, "laptop", { link: bob });
    const stolen = w.stealKeys(laptop);
    w.removeDevice(laptop);
    m.before();
    const x = w.attackerDevice(bob.did, "x");
    x.join(space);
    w.approveWith(stolen, x, x.sessionId!);
    expect(alice.trust.isAccepted(x.binding)).toBe(true); // the gap is real
    expect(x.spaces.get(space)?.key).toBeTruthy();
    expect(goal(m.after())).toEqual([]);
    expect(bob.trust.state.notices.some((n) => n.kind === "own-added")).toBe(true); // and surfaced
  });

  it("flags the old hold bypass if it ever comes back", () => {
    const { w, m, alice, bob, space } = club("d4");
    const stolen = w.stealKeys(bob);
    m.before();
    const attacker = w.takeover(bob.did);
    attacker.join(space);
    w.approveWith(stolen, attacker, attacker.sessionId!);
    expect(alice.trust.isAccepted(attacker.binding)).toBe(false); // the fix holds
    // Reintroduce the bypass by hand: accept through the removed key's approval.
    alice.trust.state.accepted.set(bindingId(attacker.binding), { binding: attacker.binding, evidence: "approved by bob/phone" });
    w.settle();
    expect(goal(m.after()).join()).toMatch(/granted to attacker device/);
  });
});

describe("removed devices", () => {
  it("a returning contact never grants to a device removed while it was offline", () => {
    const { w, m, alice, bob, space } = club("d5");
    w.setOnline(alice, false);
    const laptop = w.install(bob.did, "laptop", { link: bob });
    w.setOnline(bob, false); // nobody else can answer the laptop's request
    laptop.join(space);
    w.settle();
    w.setOnline(laptop, false);
    w.removeDevice(laptop);
    m.before();
    w.setOnline(alice, true);
    expect(goal(m.after())).toEqual([]);
    expect(laptop.spaces.get(space)?.key).toBeFalsy();
  });
});
