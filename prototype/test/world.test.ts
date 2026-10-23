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
