// Host integrity (core.md#trusted-host-state) and membership readmission.

import { Rng, randomId } from "../src/protocol/crypto";
import { World } from "../src/world/world";

function club(seed: string) {
  const w = new World(seed);
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob"), "phone");
  const space = alice.createSpace("Club");
  alice.invite(space, bob.did);
  bob.join(space);
  w.settle();
  return { w, alice, bob, space };
}

describe("host integrity", () => {
  it("rejects a changed key commitment, keeps the last valid configuration, and alarms", () => {
    const { w, alice, bob, space } = club("h1");
    const before = alice.spaces.get(space)!.host.config!;
    w.host.tamper(space, { keyId: randomId(Rng.fromLabel("evil")), commitment: new Uint8Array(32) });
    w.settle();
    for (const i of [alice, bob]) {
      expect(i.trust.state.alarms.some((a) => a.kind === "host-integrity")).toBe(true);
      expect(i.spaces.get(space)!.host.config).toEqual(before);
    }
    // A member who only ever saw the tampered configuration cannot validate
    // any grant: the host can deny service this way, but not substitute a key.
    const carol = w.install(w.account("carol"), "phone");
    alice.invite(space, carol.did);
    carol.join(space);
    w.settle();
    expect(carol.spaces.get(space)!.key).toBeFalsy(); // Carol only ever saw the tampered configuration
    expect(carol.lastDecisions.some((d) => d.includes("INVALID"))).toBe(true);
  });
});

describe("membership", () => {
  it("removal blocks new grants; readmission restores them without resetting device trust", () => {
    const { w, alice, bob, space } = club("m1");
    const pins = new Map(alice.trust.state.accepted);
    alice.removeMember(space, bob.did);
    const tablet = w.install(bob.did, "tablet", { link: bob });
    tablet.join(space);
    w.settle();
    expect(tablet.spaces.get(space)!.key).toBeFalsy();
    expect(bob.lastDecisions.some((d) => d.includes("BLOCKED"))).toBe(true); // Bob's phone may not grant either
    alice.invite(space, bob.did);
    w.settle();
    expect(tablet.spaces.get(space)!.key).toBeTruthy();
    for (const [id, a] of pins) expect(alice.trust.state.accepted.get(id)).toEqual(a);
    expect(alice.trust.state.notices.filter((n) => n.kind === "membership").map((n) => n.text.replace(/did:plc:/g, "")))
      .toEqual(["bob was added to Club", "bob was removed from Club", "bob was added to Club"]);
  });
});
