// Infrastructure the protocol depends on: shared application backends
// (core.md#ending-access), repo signing-key rotation, and PDS migration
// (device-enrollment.md#repo-observations, #revocation-authority).

import { decryptRecord } from "../src/protocol/content";
import { recordsIn } from "../src/protocol/repo";
import { COL, type Envelope } from "../src/protocol/types";
import { World } from "../src/world/world";

function club(seed: string) {
  const w = new World(seed);
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob"), "phone");
  const carol = w.install(w.account("carol"), "phone");
  const space = alice.createSpace("Club");
  for (const i of [bob, carol]) alice.invite(space, i.did);
  bob.join(space);
  carol.join(space);
  w.settle();
  return { w, alice, bob, carol, space };
}

const texts = (i: { messages(s: string): ({ text: string } | { locked: true })[] }, s: string) =>
  i.messages(s).flatMap((m) => ("text" in m ? [m.text] : []));
const alarms = (i: { trust: { state: { alarms: { kind: string }[] } } }) => i.trust.state.alarms.map((a) => a.kind);

describe("shared application backends", () => {
  it("a backend serving other members can pass ciphertext to a removed member who kept the key", () => {
    const { w, alice, bob, carol, space } = club("b1");
    alice.removeMember(space, carol.did);
    w.advance(1);
    alice.post(space, "after Carol left");
    w.settle();
    expect(texts(carol, space)).not.toContain("after Carol left"); // her own access has ended
    // A backend fetching with Bob's session, colluding with Carol:
    const exp = w.credential(bob.sessionId!, space)!;
    const snap = w.readSpace("backend", exp, alice.did, space)!;
    const leaked = recordsIn(snap, COL.message).map(([rkey, v]) => decryptRecord({
      key: carol.spaces.get(space)!.key!, envelope: (v as { envelope: Envelope }).envelope,
      space, author: alice.did, collection: COL.message, rkey,
    }) as { text: string });
    expect(leaked.map((c) => c.text)).toContain("after Carol left");
  });
});

describe("repo signing-key rotation", () => {
  it("keeps trust across rotation; commits under the old key just go unverified", () => {
    const { w, alice, bob, carol, space } = club("r1");
    w.setLag(carol, 6);
    w.rotateRepoKey(bob.did);
    const tablet = w.install(bob.did, "tablet", { link: bob });
    tablet.join(space);
    w.settle();
    expect(alice.trust.isAccepted(tablet.binding)).toBe(true);
    expect(tablet.spaces.get(space)!.key).toBeTruthy();
    // Carol is still served commits signed by the old key: she can't verify
    // them against Bob's current DID document, so she changes nothing.
    expect(carol.trust.isAccepted(bob.binding)).toBe(true);
    expect(carol.trust.isAccepted(tablet.binding)).toBe(false);
    w.advance(6);
    expect(carol.trust.isAccepted(tablet.binding)).toBe(true);
    for (const i of [alice, bob, carol]) expect(alarms(i)).toEqual([]);
  });
});

describe("PDS migration", () => {
  it("continues trust and revisions; a dropped device record revokes that device", () => {
    const { w, alice, bob, space } = club("g1");
    const tablet = w.install(bob.did, "tablet", { link: bob });
    tablet.join(space);
    w.settle();
    const revBefore = alice.trust.state.views.get(bob.did)!.rev;
    w.migrate(bob.did, "pds.new.example");
    expect(alice.trust.state.views.get(bob.did)!.rev).toBeGreaterThan(revBefore);
    expect(alice.trust.isAccepted(bob.binding) && alice.trust.isAccepted(tablet.binding)).toBe(true);
    expect(alice.trust.hold(bob.did)).toBeFalsy();
    // Bob keeps working after the move: a new device gets the key.
    const laptop = w.install(bob.did, "laptop", { link: bob });
    laptop.join(space);
    w.settle();
    expect(laptop.spaces.get(space)!.key).toBeTruthy();
    // A second move drops the tablet's record.
    w.migrate(bob.did, "pds.third.example", [tablet.binding.device.deviceId]);
    expect(alice.trust.isAccepted(tablet.binding)).toBe(false);
    expect(bob.trust.state.notices.some((n) => n.kind === "own-removed")).toBe(true);
    for (const i of [alice, bob]) expect(alarms(i).filter((k) => k !== "own-removed")).toEqual([]);
  });
});
