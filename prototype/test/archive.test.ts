// Archive-mode acceptance (audit.md#archived-grants) and key loss (core.md#key-loss).

import { World } from "../src/world/world";

const texts = (i: { messages(s: string): ({ text: string } | { locked: true })[] }, s: string) =>
  i.messages(s).flatMap((m) => ("text" in m ? [m.text] : []));

describe("archived grants", () => {
  it("read history from a revoked issuer's grant without restoring authority", () => {
    const w = new World("a1");
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Club");
    alice.post(space, "history");
    alice.invite(space, bob.did);
    bob.join(space);
    w.settle();
    const laptop = w.install(alice.did, "laptop", { link: alice });
    laptop.join(space);
    w.settle();
    w.setOnline(laptop, false);
    w.removeDevice(alice); // the issuer of Bob's grant is revoked
    bob.forgetKey(space);
    w.settle();
    const sp = bob.spaces.get(space)!;
    expect(sp.archived).toBe(true);
    expect(texts(bob, space)).toContain("history");
    expect(bob.lastDecisions.some((d) => d.includes("accept (current)") && d.includes("BLOCKED"))).toBe(true);

    // The archived key authorizes no posting and no issuance.
    bob.post(space, "draft");
    const tablet = w.install(bob.did, "tablet", { link: bob });
    tablet.join(space);
    w.settle();
    expect(texts(laptop, space)).not.toContain("draft");
    expect(tablet.spaces.get(space)!.key).toBeFalsy();

    // A current grant replaces it; then Bob posts and shares again.
    w.setOnline(laptop, true);
    expect(sp.archived).toBe(false);
    expect(texts(laptop, space)).toContain("draft");
    expect(tablet.spaces.get(space)!.key).toBeTruthy();
  });
});

describe("key loss", () => {
  it("losing every copy makes the space unreadable and unwritable", () => {
    const w = new World("k1");
    const alice = w.install(w.account("alice"), "phone");
    const bob = w.install(w.account("bob"), "phone");
    const space = alice.createSpace("Club");
    alice.post(space, "only alice had this");
    alice.forgetKey(space);
    alice.invite(space, bob.did);
    bob.join(space);
    w.advance(24);
    expect(alice.spaces.get(space)!.key).toBeFalsy();
    expect(bob.spaces.get(space)!.key).toBeFalsy();
    expect(texts(alice, space)).toEqual([]);
    bob.post(space, "kept as a draft");
    expect(bob.spaces.get(space)!.outbox.map((d) => d.text)).toEqual(["kept as a draft"]);
  });
});
