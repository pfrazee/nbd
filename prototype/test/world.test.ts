import { World } from "../src/world/world";

function club(w: World) {
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob"), "phone");
  const carol = w.install(w.account("carol"), "phone");
  const space = alice.createSpace("Book club");
  alice.invite(space, bob.did);
  alice.invite(space, carol.did);
  bob.join(space);
  carol.join(space);
  w.settle();
  return { alice, bob, carol, space };
}

describe("network lag", () => {
  it("a lagging contact misses a fast phone swap and holds", () => {
    const w = new World("lag");
    const { alice, bob, carol, space } = club(w);
    w.setLag(alice, 6);
    const fresh = w.install(bob.did, "new-phone", { link: bob });
    fresh.join(space);
    w.advance(1);
    w.removeDevice(bob);
    w.advance(6); // Alice now sees the repo as of an hour after the removal
    expect(carol.trust.isAccepted(fresh.binding)).toBe(true);
    expect(alice.trust.isAccepted(fresh.binding)).toBe(false);
    expect(alice.trust.hold(bob.did)).toBeTruthy();
  });

  it("delays what a lagging installation reads", () => {
    const w = new World("lag-read");
    const { alice, bob, space } = club(w);
    w.setLag(alice, 2);
    w.advance(1);
    bob.post(space, "hello");
    w.settle();
    const texts = () => alice.messages(space).flatMap((m) => ("text" in m ? [m.text] : []));
    expect(texts()).not.toContain("hello");
    w.advance(2);
    expect(texts()).toContain("hello");
  });
});

describe("hold imports", () => {
  it("an import never lends credit to a different candidate", () => {
    const w = new World("imports-merge");
    const { alice, bob, space } = club(w);
    const laptop = w.install(alice.did, "laptop", { link: alice });
    laptop.join(space); // installations track accounts they share a space with
    w.settle();
    w.setOnline(laptop, false);
    w.removeDevice(bob);
    const first = w.install(bob.did, "first"); // candidate seen by the phone only
    w.advance(60);
    w.backup(alice); // carries 60h of credit for {first}
    w.removeDevice(first);
    w.setOnline(laptop, true);
    w.install(bob.did, "second"); // the laptop's candidate is {second}
    expect(laptop.trust.hold(bob.did)).toBeTruthy();
    laptop.importState(w.backups[0].state);
    w.settle();
    expect(laptop.holdRemaining(bob.did)).toBeCloseTo(72, 0); // its own candidate, no borrowed credit
  });

  it("importing a live binding ends a hold", () => {
    const w = new World("imports-live");
    const { alice, bob, space } = club(w);
    const laptop = w.install(alice.did, "laptop", { link: alice });
    laptop.join(space); // installations track accounts they share a space with
    w.settle();
    w.setOnline(laptop, false);
    const tablet = w.install(bob.did, "tablet", { link: bob });
    w.removeDevice(bob); // the phone saw the link; the laptop did not
    w.setOnline(laptop, true);
    expect(laptop.trust.hold(bob.did)).toBeTruthy();
    expect(alice.trust.isAccepted(tablet.binding)).toBe(true);
    laptop.importState(alice.exportState());
    expect(laptop.trust.isAccepted(tablet.binding)).toBe(true);
    expect(laptop.trust.hold(bob.did)).toBeFalsy();
  });
});

describe("multiple spaces", () => {
  it("reuses device trust across spaces, and a reset is held in all of them", () => {
    const w = new World("spaces");
    const { alice, bob, space } = club(w);
    const pin = alice.trust.state.accepted.get([...alice.trust.state.accepted.keys()].find((id) => alice.trust.state.accepted.get(id)!.binding.account === bob.did)!)!;
    const garden = alice.createSpace("Garden");
    alice.invite(garden, bob.did);
    bob.join(garden);
    w.settle();
    expect(bob.spaces.get(garden)!.key).toBeTruthy();
    expect(pin.evidence).toBe("first use"); // no second first contact
    const attacker = w.takeover(bob.did);
    attacker.join(space);
    attacker.join(garden);
    w.advance(24);
    expect(attacker.spaces.get(space)!.key).toBeFalsy();
    expect(attacker.spaces.get(garden)!.key).toBeFalsy();
    expect(alice.trust.hold(bob.did)).toBeTruthy();
  });
});
