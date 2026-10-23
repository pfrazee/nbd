// The publication state machine (audit.md#publication) under write faults.

import { recordsIn } from "../src/protocol/repo";
import { COL } from "../src/protocol/types";
import { World } from "../src/world/world";

function setup(seed: string) {
  const w = new World(seed);
  const alice = w.install(w.account("alice"), "phone");
  const bob = w.install(w.account("bob"), "phone");
  const space = alice.createSpace("Club");
  alice.invite(space, bob.did);
  w.settle();
  const grants = () => recordsIn(w.pdsOf.get(alice.did)!.repo(alice.did, space).latest(), COL.grant);
  const issuance = () => [...alice.spaces.get(space)!.issuances.values()][0];
  return { w, alice, bob, space, grants, issuance };
}

describe("publication", () => {
  it("reconciles a lost acknowledgement by reading the repo back", () => {
    const { w, alice, bob, space, grants, issuance } = setup("p1");
    w.fault(alice, "lost-ack", 1, COL.grant);
    bob.join(space);
    w.settle();
    expect(issuance().history).toEqual(["prepared", "outcome-unknown: uploading the grant", "acknowledged: found in the repo"]);
    expect(grants().length).toBe(1);
    expect(bob.spaces.get(space)!.key).toBeTruthy();
  });

  it("retries a rejected grant with the same bytes at the same identity", () => {
    const { w, alice, bob, space, grants, issuance } = setup("p2");
    w.fault(alice, "reject", 3, COL.grant);
    bob.join(space);
    w.settle();
    expect(issuance().state).toBe("outcome-unknown");
    for (let i = 0; i < 3; i++) w.advance(1); // later syncs retry
    const iss = issuance();
    expect(iss.state).toBe("acknowledged");
    expect(grants().map(([k]) => k)).toEqual([iss.grantKey]);
    expect(bob.spaces.get(space)!.key).toBeTruthy();
  });

  it("stops when authority is lost before the grant goes out, and never resumes", () => {
    const { w, alice, bob, space, grants, issuance } = setup("p3");
    w.fault(alice, "reject", 99, COL.evidence);
    bob.join(space);
    w.settle();
    expect(issuance().state).toBe("prepared");
    alice.removeMember(space, bob.did);
    w.settle();
    expect(issuance().state).toBe("stopped");
    w.faults.clear();
    w.advance(1);
    expect(issuance().state).toBe("stopped");
    expect(grants().length).toBe(0);
    expect(bob.spaces.get(space)!.key).toBeFalsy();
  });

  it("stops when the recipient device is revoked mid-issuance, with no host change", () => {
    const { w, alice, bob, space, grants, issuance } = setup("p5");
    w.fault(alice, "reject", 99, COL.evidence);
    bob.join(space);
    w.settle();
    expect(issuance().state).toBe("prepared");
    w.install(bob.did, "tablet", { link: bob }); // keeps Bob's account live
    w.removeDevice(bob); // the recipient is revoked; membership is untouched
    w.faults.clear();
    w.advance(1);
    expect(issuance().history.at(-1)).toMatch(/^stopped: authorization lost/);
    expect(grants().filter(([, v]) => (v as { value: { recipient: { deviceId: string } } }).value.recipient.deviceId === bob.binding.device.deviceId)).toEqual([]);
  });

  it("stops on changed host evidence and prepares a new issuance", () => {
    const { w, alice, bob, space, grants, issuance } = setup("p4");
    w.fault(alice, "reject", 99, COL.evidence);
    bob.join(space);
    w.settle();
    const first = issuance();
    alice.removeMember(space, bob.did);
    alice.invite(space, bob.did); // readmitted: a newer membership revision
    w.faults.clear();
    w.settle();
    expect(first.state).toBe("stopped");
    expect(alice.spaces.get(space)!.stopped).toContain(first);
    const second = issuance();
    expect(second).not.toBe(first);
    expect(second.state).toBe("acknowledged");
    expect(grants().map(([k]) => k)).toEqual([second.grantKey]);
  });
});
