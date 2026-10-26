// The inviters rule (device-enrollment.md#grant-standing, core.md#invites) as a world policy: grant
// standing, invite records, and first-contact holds, checked against the
// baseline. Scenarios 13-18 run in scenarios.test.ts; these cover the
// contrasts and the cases scenarios don't reach.

import { verify } from "../src/protocol/crypto";
import { cloneTrust, invitePayload } from "../src/protocol/trust";
import { type Invite, COL, type Policy, bindingId, withoutProof } from "../src/protocol/types";
import { recordsIn } from "../src/protocol/repo";
import { Run } from "../src/sim/scenario";
import { scenarios } from "../src/sim/scenarios";
import { InvariantMonitor } from "../src/sim/invariants";
import { World } from "../src/world/world";

const scenario = (id: string) => scenarios.find((s) => s.id === id)!;
const goal = (vs: string[]) => vs.filter((v) => v.startsWith("goal:"));

/** Alice and Bob share Book club; Alice invited Bob. */
function club(seed: string, policy: Policy = "inviters") {
  const w = new World(seed, { policy });
  const m = new InvariantMonitor(w);
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob", "pds.bob.example"), "phone");
  const space = alice.createSpace("Book club");
  alice.invite(space, bob.did);
  bob.join(space);
  w.settle();
  return { w, m, alice, bob, space };
}

describe("policy flag", () => {
  it("defaults to the baseline, which publishes no invite records", () => {
    const { w, alice, space } = club("p1", "baseline");
    expect(w.policy).toBe("baseline");
    expect(w.provenance.invites).toEqual([]);
    expect(recordsIn(w.pdsOf.get(alice.did)!.repo(alice.did, space).latest(), COL.invite)).toEqual([]);
    expect(alice.trust.state.fcHolds.size).toBe(0);
  });

  it("the newcomer scenario discloses under the baseline and holds under inviters", () => {
    const steps = (policy: Policy) => {
      const run = new Run(scenario("inviters-newcomer"), "newcomer", policy);
      for (let n = 0; n < 4; n++) run.step();
      return run;
    };
    const base = steps("baseline");
    expect(base.ctx.inst.attacker.spaces.get(base.ctx.space.club)?.keyFrom).toMatch(/^did:plc:dave/);
    const inv = steps("inviters");
    expect(inv.ctx.inst.attacker.spaces.get(inv.ctx.space.club)?.key).toBeFalsy();
  });
});

describe("invite records", () => {
  it("are signed by the inviting device, and none is made for a member", () => {
    const { w, alice, bob, space } = club("r1");
    expect(alice.invite(space, bob.did)).toBe(false); // a re-invite admits nothing
    const recs = recordsIn(w.pdsOf.get(alice.did)!.repo(alice.did, space).latest(), COL.invite)
      .map(([, v]) => (v as { value: Invite }).value);
    expect(recs.map((r) => [r.authorizes.length, r.pending, r.captures])).toEqual([[1, false, null]]);
    for (const r of recs) {
      expect(r.issuer).toEqual({ account: alice.did, deviceId: alice.binding.device.deviceId });
      expect(r.bindings.map((b) => b.device.deviceId)).toEqual([bob.binding.device.deviceId]);
      expect(verify(r.proof, invitePayload(withoutProof(r)), alice.binding.device.authPubkey)).toBe(true);
    }
  });

  it("carry the vouch to the inviter's other installations that never met the account", () => {
    const w = new World("r2", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const laptop = w.install(alice.did, "laptop", { link: alice });
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Book club");
    laptop.join(space);
    alice.invite(space, bob.did);
    w.settle();
    expect([...laptop.trust.state.accepted.values()].find((a) => a.binding.account === bob.did)?.evidence).toMatch(/^invited by/);
    expect(laptop.trust.standingBasis(bob.binding, space)).toBe("authorized");
    const garden = alice.createSpace("Garden");
    expect(laptop.trust.standing(bob.binding, garden)).toBe(false);
    // The vouch follows the account's later invites, from any own device.
    alice.invite(garden, bob.did);
    w.settle();
    expect(laptop.trust.standingBasis(bob.binding, garden)).toBe("authorized");
  });

  it("are not made for an account a host console already admitted", () => {
    const w = new World("r5", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Book club");
    w.host.setMembership(alice.did, space, bob.did, true); // no invite record
    bob.join(space);
    w.settle();
    expect(alice.trust.standing(bob.binding, space)).toBe(false);
    m.before();
    expect(alice.invite(space, bob.did)).toBe(false);
    w.settle();
    expect(m.after()).toEqual([]);
    expect(w.provenance.invites).toEqual([]);
    expect(alice.trust.standing(bob.binding, space)).toBe(false);
    expect(bob.spaces.get(space)?.key).toBeFalsy();
  });

  it("inviting again while an invite is unsent resumes it", () => {
    const w = new World("r7", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Book club");
    w.fault(alice, "reject", 2, COL.invite);
    expect(alice.invite(space, bob.did)).toBe(false);
    expect(alice.invite(space, bob.did)).toBe(false); // the resend fails too
    expect(alice.inviteOutbox.length).toBe(1);
    expect(alice.invite(space, bob.did)).toBe(true);
    expect(alice.inviteOutbox.length).toBe(0);
    const recs = recordsIn(w.pdsOf.get(alice.did)!.repo(alice.did, space).latest(), COL.invite)
      .map(([, v]) => (v as { value: Invite }).value);
    expect(recs.map((r) => r.authorizes.length)).toEqual([1]);
    expect(alice.trust.standingBasis(bob.binding, space)).toBe("authorized");
  });

  it("pending invites are captured only by the device that made them", () => {
    const w = new World("r6", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const did = w.account("bob");
    const space = alice.createSpace("Book club");
    expect(alice.invite(space, did)).toBe(true); // pending: Bob has no devices
    const tablet = w.install(alice.did, "tablet", { link: alice });
    tablet.join(space);
    w.setOnline(alice, false);
    m.before();
    const bob = w.install(did, "phone");
    bob.join(space);
    w.settle();
    expect(m.after()).toEqual([]);
    expect(tablet.trust.isAccepted(bob.binding)).toBe(true);
    expect(tablet.trust.standing(bob.binding, space)).toBe(false); // the tablet only holds
    expect(bob.spaces.get(space)?.key).toBeFalsy();
    m.before();
    w.setOnline(alice, true);
    expect(m.after()).toEqual([]);
    expect(alice.trust.standingBasis(bob.binding, space)).toBe("authorized");
    expect(bob.spaces.get(space)?.keyFrom).toMatch(/^did:plc:alice\/.*phone|^did:plc:alice/);
    // The tablet met Bob's phone as a fellow member, a first contact, so it
    // takes the phone's authorization of it.
    expect(tablet.trust.standingBasis(bob.binding, space)).toBe("authorized");
  });

  it("do not end a hold already running on an installation that pins the account", () => {
    // Alice's phone met Bob in Carol's Book club before the takeover. Her
    // tablet, linked earlier, never did, and first meets the attacker's
    // device by inviting Bob into Garden.
    const w = new World("r3", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const fresh = w.install(alice.did, "tablet", { link: alice });
    const bob = w.install(w.account("bob"), "phone");
    const carol = w.install(w.account("carol"), "phone");
    const club = carol.createSpace("Book club");
    carol.invite(club, bob.did);
    carol.invite(club, alice.did);
    alice.join(club);
    w.settle();
    expect(alice.trust.isAccepted(bob.binding)).toBe(true);
    const attacker = w.takeover(bob.did);
    const garden = fresh.createSpace("Garden");
    w.settle();
    expect(fresh.trust.knew(bob.did)).toBe(false);
    fresh.invite(garden, bob.did);
    w.settle();
    expect(fresh.trust.standingBasis(attacker.binding, garden)).toBe("authorized");
    // The phone pins Bob and holds his reset; neither the record nor an
    // import from the tablet may give it standing.
    expect(alice.trust.standing(attacker.binding, garden)).toBe(false);
    m.before();
    alice.importState(fresh.exportState());
    expect(m.after().filter((v) => /lineage|authoriz/.test(v))).toEqual([]);
    expect(alice.trust.state.lineage.has(bindingId(attacker.binding))).toBe(false);
    expect(alice.trust.standing(attacker.binding, garden)).toBe(false);
  });

  it("from an unaccepted own device are ignored", () => {
    const w = new World("r4", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const stranger = w.install(alice.did, "unlinked"); // never approved by the phone
    const bob = w.install(w.account("bob"), "phone");
    const space = stranger.createSpace("Garden");
    stranger.invite(space, bob.did);
    w.settle();
    expect(alice.trust.knew(bob.did)).toBe(false);
  });
});

describe("durable invites (Astra's fourth review)", () => {
  it("an abandoned pending invite captures nothing", () => {
    const w = new World("d1", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const did = w.account("bob");
    const space = alice.createSpace("Book club");
    w.fault(alice, "reject", 1, COL.invite);
    expect(alice.invite(space, did)).toBe(false); // pending, unsent
    w.host.setMembership(alice.did, space, did, true); // a host console admits Bob
    m.before();
    w.settle(); // the retry finds Bob a member and abandons the invite
    expect(alice.inviteOutbox.length).toBe(0);
    expect(alice.trust.state.pending.size).toBe(0);
    const bob = w.install(did, "phone");
    bob.join(space);
    w.settle();
    expect(m.after()).toEqual([]);
    expect(w.provenance.invites.some((f) => f.captures)).toBe(false);
    expect(alice.trust.standing(bob.binding, space)).toBe(false);
    expect(bob.spaces.get(space)?.key).toBeFalsy();
  });

  it("a second invite prepared before the first is published authorizes what the first vouched for", () => {
    const w = new World("d2", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const club = alice.createSpace("Book club");
    const garden = alice.createSpace("Garden");
    w.fault(alice, "reject", 1, COL.invite);
    m.before();
    expect(alice.invite(club, bob.did)).toBe(false);
    expect(alice.invite(garden, bob.did)).toBe(false); // queued behind the first, unsent
    expect(alice.inviteOutbox.map((e) => e.record.authorizes.length)).toEqual([1, 1]);
    w.settle();
    bob.join(club);
    bob.join(garden);
    w.settle();
    expect(m.after()).toEqual([]);
    for (const s of [club, garden]) {
      expect(alice.trust.standingBasis(bob.binding, s)).toBe("authorized");
      expect(bob.spaces.get(s)?.keyFrom).toMatch(/^did:plc:alice/);
    }
  });

  it("a retry publishes the exact bytes it saved", () => {
    const w = new World("d4", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Book club");
    w.fault(alice, "reject", 1, COL.invite);
    w.setOnline(alice, false); // no resend until she is back
    alice.invite(space, bob.did);
    const saved = alice.inviteOutbox[0].rkey;
    w.install(bob.did, "tablet", { link: bob }); // Bob's devices change meanwhile
    w.setOnline(alice, true);
    expect(alice.inviteOutbox.length).toBe(0);
    expect(w.provenance.invites.map((f) => f.rkey)).toEqual([saved]);
  });

  it("a replacement phone is authorized in the next space its owner is invited to", () => {
    const { w, m, alice, bob, space } = club("d3");
    const phone2 = w.install(bob.did, "new-phone", { link: bob });
    w.removeDevice(bob);
    const garden = alice.createSpace("Garden");
    m.before();
    alice.invite(garden, bob.did);
    phone2.join(garden);
    w.settle();
    expect(m.after()).toEqual([]);
    expect(w.provenance.invites.at(-1)?.authorizes).toEqual([phone2.binding.device.deviceId]);
    expect(alice.trust.standingBasis(phone2.binding, garden)).toBe("authorized");
    expect(phone2.spaces.get(garden)?.keyFrom).toMatch(/^did:plc:alice/);
    expect(alice.trust.standing(phone2.binding, space)).toBe(true); // linked by the authorized phone
  });
});

describe("state transfer (Astra's fifth review)", () => {
  it("a stale import doesn't reopen an abandoned pending invite", () => {
    const w = new World("t1", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const did = w.account("bob");
    const space = alice.createSpace("Book club");
    w.fault(alice, "reject", 1, COL.invite);
    alice.invite(space, did); // pending, unsent
    const stale = alice.exportState();
    w.host.setMembership(alice.did, space, did, true); // a host console admits Bob
    w.settle(); // the retry abandons the invite
    m.before();
    alice.importState(stale);
    expect(alice.trust.state.pending.size).toBe(0);
    const bob = w.install(did, "phone");
    bob.join(space);
    w.settle();
    expect(m.after()).toEqual([]);
    expect(w.provenance.invites.some((f) => f.captures)).toBe(false);
    expect(alice.trust.standing(bob.binding, space)).toBe(false);
  });

  it("a restored device doesn't capture the pending invite it made before", () => {
    const w = new World("t2", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const did = w.account("bob");
    const space = alice.createSpace("Book club");
    alice.invite(space, did); // pending, published
    w.backup(alice);
    const restored = w.restore(alice, 0);
    expect(restored.trust.state.pending.size).toBe(0);
    const bob = w.install(did, "phone");
    bob.join(space);
    w.settle();
    expect(w.provenance.invites.some((f) => f.captures)).toBe(false);
    expect(restored.trust.standing(bob.binding, space)).toBe(false);
  });

  it("a capture waits for its pending record to be published", () => {
    const w = new World("t3", { policy: "inviters" });
    const alice = w.install(w.account("alice"), "phone");
    const did = w.account("bob");
    const space = alice.createSpace("Book club");
    w.fault(alice, "reject", 3, COL.invite);
    alice.invite(space, did); // pending, unsent
    const bob = w.install(did, "phone"); // Alice's app captures; the capture queues
    expect(alice.inviteOutbox.map((e) => !!e.record.captures)).toEqual([false, true]);
    alice.inviteOutbox.reverse(); // even out of order, the capture may not go first
    w.faults.delete(alice.id);
    w.settle();
    expect(w.provenance.invites.some((f) => f.captures)).toBe(false);
    void bob;
  });

  it("another installation takes the authorization of a replacement it trusts through the same chain", () => {
    const { w, alice, bob, space } = club("t4");
    const laptop = w.install(alice.did, "laptop", { link: alice });
    laptop.join(space);
    w.settle();
    const phone2 = w.install(bob.did, "new-phone", { link: bob });
    w.removeDevice(bob);
    expect(laptop.trust.isAccepted(phone2.binding)).toBe(true);
    // The laptop is offline when the phone invites Bob to Garden.
    w.setOnline(laptop, false);
    const garden = alice.createSpace("Garden");
    alice.invite(garden, bob.did);
    w.settle();
    // An import from the phone carries the authorization: the laptop trusts
    // the replacement through an approval from the phone it holds as vouched.
    const copy = cloneTrust(laptop.trust.state);
    laptop.trust.importFrom(cloneTrust(alice.trust.state));
    expect(laptop.trust.standingBasis(phone2.binding, garden)).toBe("authorized");
    // So does reading the phone's invite record.
    laptop.trust.state = copy;
    w.setOnline(laptop, true);
    expect(laptop.trust.standingBasis(phone2.binding, garden)).toBe("authorized");
  });
});

describe("first-contact holds", () => {
  it("a device linked while its signer had standing keeps it after the signer is removed", () => {
    const { w, alice, bob, space } = club("h1");
    const carol = w.install(w.account("carol"), "phone");
    alice.invite(space, carol.did);
    carol.join(space);
    w.settle();
    w.advance(80); // Carol's hold for Bob's phone completes
    expect(carol.trust.standingBasis(bob.binding, space)).toBe("held");
    const laptop = w.install(bob.did, "laptop", { link: bob });
    w.removeDevice(bob);
    expect(carol.trust.standingBasis(laptop.binding, space)).toMatch(/^approved by .*\(held\)$/);
  });

  it("are credited by each installation's own clock, from when it first saw the device", () => {
    const { w, alice, bob, space } = club("h2");
    const carol = w.install(w.account("carol"), "phone");
    carol.clockOffset = 1000; // another clock domain entirely
    alice.invite(space, carol.did);
    carol.join(space);
    w.settle();
    w.advance(71);
    expect(carol.trust.standing(bob.binding, space)).toBe(false);
    w.advance(1);
    expect(carol.trust.standing(bob.binding, space)).toBe(true);
  });

  it("a lost local state starts the holds again", () => {
    const { w, alice, bob, space } = club("h3");
    const carol = w.install(w.account("carol"), "phone");
    alice.invite(space, carol.did);
    carol.join(space);
    w.settle();
    w.advance(80);
    expect(carol.trust.standing(bob.binding, space)).toBe(true);
    carol.resetLocalState();
    w.settle();
    expect(carol.trust.isAccepted(bob.binding)).toBe(true);
    expect(carol.trust.standing(bob.binding, space)).toBe(false);
  });
});

describe("goal check under inviters", () => {
  it("flags a newcomer that grants to a takeover device at once", () => {
    const { w, m, alice, bob, space } = club("g1");
    const attacker = w.takeover(bob.did);
    attacker.join(space);
    const dave = w.install(w.account("dave"), "phone");
    alice.invite(space, dave.did);
    // A client bug: Dave's app grants as the baseline does.
    (dave.trust as { policy: Policy }).policy = "baseline";
    m.before();
    dave.join(space);
    w.settle();
    expect(goal(m.after()).join()).toMatch(/dave\/phone granted to attacker device bob.* with no record authorizing it there/);
  });

  it("flags an inviter that authorizes a reset it was holding", () => {
    // Alice knew Bob before the takeover, so the attacker's device is a reset
    // she must hold; by mistake her app accepts and authorizes it in Garden.
    const w = new World("g2", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const carol = w.install(w.account("carol"), "phone");
    const club = carol.createSpace("Book club");
    carol.invite(club, bob.did);
    carol.invite(club, alice.did);
    alice.join(club);
    w.settle();
    const attacker = w.takeover(bob.did);
    expect(alice.trust.hold(bob.did)).toBeTruthy();
    const garden = alice.createSpace("Garden");
    alice.invite(garden, bob.did);
    expect(w.provenance.invites.at(-1)?.authorizes).toEqual([]); // a reset is never authorized
    // The bug:
    alice.trust.state.accepted.set(bindingId(attacker.binding), { binding: attacker.binding, evidence: "bug" });
    alice.trust.authorize(garden, attacker.binding);
    m.before();
    attacker.join(garden);
    w.settle();
    const vs = m.after();
    expect(goal(vs).join()).toMatch(/alice\/phone granted to attacker device bob/);
  });

  it("accepts the residual: an inviter who never met the account", () => {
    const w = new World("g3", { policy: "inviters" });
    const m = new InvariantMonitor(w);
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const attacker = w.takeover(bob.did);
    const space = alice.createSpace("Book club");
    m.before();
    alice.invite(space, bob.did);
    attacker.join(space);
    w.settle();
    expect(attacker.spaces.get(space)?.key).toBeTruthy();
    expect(m.after()).toEqual([]);
  });
});
