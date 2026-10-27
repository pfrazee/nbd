// The Relay-Witnessed Repos proposal (proposal-reliable-detection.md) as a
// world policy. Scenarios 27-35 run in scenarios.test.ts; these cover Astra's
// cases, each rule the mutations in mutate.mjs break, and the findings the
// prototype makes about the proposal (see README.md#relay-witnessed-repos).

import { bindingId } from "../src/protocol/types";
import { detectionViolations } from "../src/sim/detection";
import { InvariantMonitor } from "../src/sim/invariants";
import { Run } from "../src/sim/scenario";
import { scenarios } from "../src/sim/scenarios";
import { RELAY_REPLAY_WINDOW, WITNESS_RETENTION } from "../src/world/relay";
import { World } from "../src/world/world";
import type { Installation } from "../src/protocol/installation";

const scenario = (id: string) => scenarios.find((s) => s.id === id)!;
const about = (i: Installation, x: Installation) => i.trust.state.alarms.filter((a) => a.device === x.binding.device.deviceId);

/** Bob at a malicious PDS on Lantern; Carol on another app. */
function world(seed: string) {
  const w = new World(seed, { policy: "witness" });
  const m = new InvariantMonitor(w);
  const bobDid = w.account("bob", "pds.bob.example");
  const carolDid = w.account("carol");
  const bob = w.install(bobDid, "phone");
  const carol = w.install(carolDid, "phone", { app: "other" });
  return { w, m, bob, carol, bobDid, carolDid };
}

/** Carol creates Garden and invites Bob; `x` joins. */
function invite(w: World, carol: Installation, bobDid: string, x: Installation): string {
  const garden = carol.createSpace("Garden");
  carol.invite(garden, bobDid);
  x.join(garden);
  w.settle();
  return garden;
}

const violations = (m: InvariantMonitor) => m.violations.map((v) => v.text);

describe("decisions on witnessed state", () => {
  it("a validly signed commit the relay never published is never observed, and is INCOMPLETE (Astra)", () => {
    const { w, m, bob, carol, bobDid } = world("w1");
    m.before();
    const x = w.unrelayedImpostor(bobDid, [carol]);
    const garden = invite(w, carol, bobDid, x);
    m.after();
    expect(carol.trust.isAccepted(x.binding)).toBe(false);
    expect(carol.trust.state.candidatesSeen.has(bindingId(x.binding))).toBe(false);
    expect([...carol.trust.state.views.get(bobDid)!.present.keys()]).toEqual([bob.binding.device.deviceId]);
    expect(carol.mon.incomplete.has(bobDid)).toBe(true);
    expect(x.spaces.get(garden)?.key).toBeFalsy();
    expect(violations(m)).toEqual([]);
  });

  it("trusts only its application's witness, never one a PDS runs", () => {
    const { w, carol, bobDid } = world("w2");
    const x = w.unrelayedImpostor(bobDid, [carol]);
    // The PDS's own "witness" vouches for the unrelayed commit.
    const rogue = w.otherWitnesses(carol.id).find((o) => o.id === "witness.pds.bob.example")!;
    expect(rogue.latest(carol.id, bobDid)!.snap.records.has(`com.example.nbd.device/${x.binding.device.deviceId}`)).toBe(true);
    invite(w, carol, bobDid, x);
    expect(carol.trust.isAccepted(x.binding)).toBe(false);
  });

  it("a PDS-served commit that differs from the witnessed one at its revision raises a fork alarm", () => {
    const { w, bob, carol, bobDid } = world("w3");
    w.forkedImpostor(bobDid, [carol]);
    expect(bob.trust.state.alarms.some((a) => a.kind === "fork" && a.subject === bobDid)).toBe(true);
    expect(carol.trust.state.alarms.some((a) => a.kind === "fork")).toBe(false); // served the fork it was relayed
  });

  it("an account whose latest published commit is a gap can't be met: INCOMPLETE", () => {
    const { w, carol, bobDid } = world("w4");
    const stop = w.withholdFetch(bobDid, "other");
    w.pdsOf.get(bobDid)!.relayHooks.push((d) => (d === bobDid ? { kind: "sync" } : null));
    w.pdsOf.get(bobDid)!.repo(bobDid).commit();
    w.settle();
    const garden = carol.createSpace("Garden");
    carol.invite(garden, bobDid);
    expect(carol.trust.knew(bobDid)).toBe(false);
    expect(carol.mon.incomplete.has(bobDid)).toBe(true);
    stop();
  });
});

describe("reconstruction and gaps", () => {
  it("a replaced #sync root is a gap that a later resync doesn't erase (Astra)", () => {
    const { w, m, bob, bobDid } = world("w5");
    m.before();
    w.syncReplaced(bobDid);
    m.after();
    const hist = w.witnessOf("lantern").accounts.get(bobDid)!.history;
    expect(hist.filter((h) => h.kind === "gap").length).toBe(1);
    expect(hist.at(-1)!.kind).toBe("state");
    expect(bob.gapWarnings().length).toBe(1);
    // More resyncs and commits later: the gap stays, for this client and for
    // one that reads the history afresh.
    const tablet = w.install(bobDid, "tablet", { link: bob });
    w.advance(48);
    expect(bob.gapWarnings().length).toBe(1);
    expect(tablet.mon.gaps.length).toBe(1);
    expect(w.witnessOf("lantern").accounts.get(bobDid)!.history.some((h) => h.kind === "gap")).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  it("a #sync root served to one witness and withheld from another: a gap for one only", () => {
    const { w, bob, carol, bobDid } = world("w6");
    const x = w.publishSyncRoot(bobDid, ["witness.other"]);
    expect(bob.gapWarnings().length).toBe(1);
    invite(w, carol, bobDid, x);
    expect(carol.trust.isAccepted(x.binding)).toBe(true);
    const acc = w.provenance.accepts.find((a) => a.inst === carol.id && a.target === x.binding.device.deviceId)!;
    const g = bob.gapWarnings()[0];
    expect(g.fromSeq <= acc.seq! && acc.seq! <= g.toSeq).toBe(true);
  });

  it("operations that fail inversion are a gap", () => {
    const { w, bob, bobDid } = world("w7");
    const pds = w.pdsOf.get(bobDid)!;
    pds.relayHooks.push((d) => (d === bobDid ? { badOps: true } : null));
    w.install(bobDid, "tablet", { link: bob }); // approval + device record; ops omit the device
    expect(w.witnessOf("lantern").accounts.get(bobDid)!.history.at(-1)!).toMatchObject({ kind: "gap", reason: "operations fail inversion" });
    expect(bob.gapWarnings().length).toBe(1);
  });

  it("skipped relay sequence numbers within a continuous subscription are not gaps", () => {
    const { w, bob, bobDid } = world("w8");
    for (let n = 0; n < 6; n++) w.install(bobDid, `d${n}`, { link: bob });
    const seqs = w.relay!.events.map((e) => e.seq);
    expect(seqs.some((s, i) => i > 0 && s - seqs[i - 1] > 1)).toBe(true);
    expect(bob.mon.gaps).toEqual([]);
  });

  it("an outage beyond the relay's replay window is a stream gap in every account's history", () => {
    const { w, bob, carol, bobDid } = world("w9");
    w.setWitness("lantern", { connected: false });
    w.install(bobDid, "tablet", { link: bob });
    w.advance(RELAY_REPLAY_WINDOW + 1);
    expect(bob.liveness()).toMatch(/not live/);
    w.setWitness("lantern", { connected: true });
    expect(bob.gapWarnings().some((g) => /stream gap/.test(g.reason))).toBe(true);
    expect(bob.liveness()).toBeNull();
    // Carol's witness never broke: no gap for her.
    expect(carol.mon.auditGaps).toEqual([]);
  });
});

describe("watching the own account", () => {
  it("alarms on a device published and deleted while the phone was offline; latest-only watching misses it", () => {
    const { w, m, bob, carol, bobDid } = world("w10");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    step(() => w.setOnline(bob, false));
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    step(() => f.undo());
    step(() => w.setOnline(bob, true));
    expect(about(bob, f.sub).length).toBe(1);
    expect(violations(m)).toEqual([]);
  });

  it("a stale-cursor restore catches an add-and-delete (Astra)", () => {
    const run = new Run(scenario("witness-restore"));
    run.runAll();
    expect(about(run.ctx.inst.bobRestored, run.ctx.inst.impostor).length).toBe(1);
    expect(run.monitor.violations).toEqual([]);
  });

  it("a restore older than retention warns of a gap for that interval", () => {
    const run = new Run(scenario("witness-old-backup"));
    run.runAll();
    expect(run.ctx.inst.bobRestored.mon.gaps.map((g) => g.reason)).toEqual(["older than WITNESS_RETENTION"]);
  });

  it("a linked device resumes its approver's cursor", () => {
    const { w, bob, bobDid } = world("w11");
    const before = bob.mon.cursors.get(bobDid)!;
    const tablet = w.install(bobDid, "tablet", { link: bob });
    expect(tablet.mon.cursors.get(bobDid)!).toBeGreaterThan(before);
    expect(tablet.trust.state.notices.filter((n) => n.kind === "history-binding")).toEqual([]);
  });

  it("a fresh enrollment presents every binding that ever appeared, including deleted ones", () => {
    const w = new World("w12", { policy: "witness" });
    const bobDid = w.account("bob", "pds.bob.example");
    const carol = w.install(w.account("carol"), "phone", { app: "other" });
    // Bob has no device yet; his PDS publishes one, Carol meets it, it is deleted.
    const f = w.flashImpostor(bobDid);
    invite(w, carol, bobDid, f.sub);
    f.undo();
    w.advance(48);
    const bob = w.install(bobDid, "phone");
    expect(bob.trust.state.notices.some((n) => n.kind === "history-binding" && n.about?.device.deviceId === f.sub.binding.device.deviceId)).toBe(true);
  });
});

describe("pinned accounts", () => {
  it("process every witnessed commit: a delete and recreate is seen, not skipped (Astra)", () => {
    const { w, bob, carol, bobDid } = world("w13");
    const garden = carol.createSpace("Garden");
    carol.invite(garden, bobDid);
    bob.join(garden);
    w.settle();
    w.setOnline(carol, false);
    w.removeDevice(bob, { endSession: false });
    w.recreateRecord(bob);
    w.setOnline(carol, true);
    expect(carol.trust.state.revoked.has(bindingId(bob.binding))).toBe(true);
    expect(carol.trust.state.alarms.some((a) => a.kind === "resurrection")).toBe(true);
  });

  it("history older than retention is recorded as an audit gap, across which a delete and recreate is the baseline limit", () => {
    const { w, bob, carol, bobDid } = world("w14");
    const garden = carol.createSpace("Garden");
    carol.invite(garden, bobDid);
    bob.join(garden);
    w.settle();
    w.setOnline(carol, false);
    w.removeDevice(bob, { endSession: false });
    w.recreateRecord(bob);
    w.advance(WITNESS_RETENTION + 24);
    w.setOnline(carol, true);
    expect(carol.mon.auditGaps.some((g) => g.account === bobDid && /RETENTION/.test(g.reason))).toBe(true);
    expect(carol.trust.state.revoked.has(bindingId(bob.binding))).toBe(false);
  });
});

describe("liveness and deadline", () => {
  it("impostor accepted at hour 0, a check at 0.5 whose history ends at -0.5: warns before hour 24 (Astra's 25-hour case)", () => {
    const run = new Run(scenario("witness-liveness"));
    run.runAll();
    expect(run.monitor.violations).toEqual([]);
    expect(detectionViolations(run.world)).toEqual([]);
    const bob = run.ctx.inst.bobPhone;
    // The warning started at frontier + 24h: hour 23 relative to acceptance.
    const seg = bob.segments.find((s) => s.base > 0.9 && s.base < 1.1)!;
    expect(seg.world + 24 - seg.base).toBeLessThan(run.world.provenance.accepts.find((a) => a.target === run.ctx.inst.impostor.binding.device.deviceId)!.world + 24);
  });

  it("one unrecoverable gap doesn't make liveness fail forever (Astra)", () => {
    const { w, bob, bobDid } = world("w15");
    w.syncReplaced(bobDid);
    w.advance(48);
    expect(bob.gapWarnings().length).toBe(1);
    expect(bob.liveness()).toBeNull();
    expect(bob.coverageAge()).toBeLessThan(1);
  });

  it("acknowledging a gap suppresses neither a new gap nor liveness (Astra)", () => {
    const { w, bob, bobDid } = world("w16");
    w.syncReplaced(bobDid, "x1");
    bob.acknowledgeGap(bob.gapWarnings()[0].key);
    expect(bob.gapWarnings()).toEqual([]);
    w.syncReplaced(bobDid, "x2");
    expect(bob.gapWarnings().length).toBe(1);
    w.setWitness("lantern", { reachable: false });
    w.advance(25);
    expect(bob.liveness()).toMatch(/unreachable/);
    for (const g of bob.gapWarnings()) bob.acknowledgeGap(g.key);
    expect(bob.liveness()).toMatch(/unreachable/);
  });

  it("a quick answer with a stale frontier does not advance coverage", () => {
    const { w, bob } = world("w17");
    w.setWitness("lantern", { lag: 30 });
    w.advance(20);
    expect(bob.coverageAge()).toBeCloseTo(20);
    w.advance(5);
    expect(bob.liveness()).toMatch(/not live/);
  });

  it("across a restart, coverage carries by wall clock; a clock moved backward makes it unknown", () => {
    const { w, bob } = world("w18");
    w.setOnline(bob, false);
    w.advance(10);
    w.setWitness("lantern", { reachable: false });
    w.setOnline(bob, true);
    expect(bob.coverageAge()).toBeCloseTo(10);
    w.setOnline(bob, false);
    w.skew(bob, -5);
    w.setOnline(bob, true);
    expect(bob.coverageAge()).toBe(Infinity);
    expect(bob.liveness()).toMatch(/unreachable/);
    w.setWitness("lantern", { reachable: true });
    expect(bob.liveness()).toBeNull();
  });
});

describe("findings", () => {
  it("FINDING: an honest relay that delivers to Bob's witness late keeps it 'live' while it misses the deadline", () => {
    // Live is defined against what the relay has delivered, so a witness
    // whose events queue at the relay (a slow consumer) reports frontier age
    // 0 while it is a day behind the witness that Carol's app uses.
    const { w, m, bob, carol, bobDid } = world("f1");
    w.relayDelay("lantern", 30);
    const x = w.forkedImpostor(bobDid, [carol]);
    invite(w, carol, bobDid, x);
    m.before();
    w.advance(25);
    m.after();
    expect(carol.trust.isAccepted(x.binding)).toBe(true);
    expect(bob.liveness()).toBeNull();
    expect(about(bob, x)).toEqual([]);
    expect(violations(m).filter((v) => v.startsWith("detection goal"))).toHaveLength(1);
    w.advance(6);
    expect(about(bob, x).length).toBe(1); // it does alarm, at hour 30
  });

  it("FINDING: a fresh enrollment after retention presents nothing and warns of nothing", () => {
    // A brand-new account impersonated around a pending invite: if the user
    // first installs more than WITNESS_RETENTION later, the deleted impostor
    // is gone from the witness and fresh enrollment, which raises no
    // retention gap, says nothing.
    const w = new World("f2", { policy: "witness" });
    const bobDid = w.account("bob", "pds.bob.example");
    const carol = w.install(w.account("carol"), "phone", { app: "other" });
    const f = w.flashImpostor(bobDid);
    invite(w, carol, bobDid, f.sub);
    f.undo();
    w.advance(WITNESS_RETENTION + 24);
    const bob = w.install(bobDid, "phone");
    expect(bob.trust.state.notices.filter((n) => n.kind === "history-binding")).toEqual([]);
    expect(bob.mon.gaps).toEqual([]);
  });
});

describe("the detection check", () => {
  it("holds a device linked after the acceptance to nothing, and lets a restore count its predecessor's alarm", () => {
    const { w, m, bob, carol, bobDid } = world("g1");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    step(() => f.undo());
    expect(about(bob, f.sub).length).toBe(1);
    step(() => w.backup(bob));
    step(() => w.install(bobDid, "tablet", { link: bob }));
    step(() => w.restore(bob, 0));
    step(() => w.advance(30));
    expect(violations(m)).toEqual([]);
  });

  it("flags an installation that ran past the deadline without alarming or warning", () => {
    const { w, m, bob, carol, bobDid } = world("g2");
    // Bob's phone stops processing its own history: a broken client.
    (bob as unknown as { ownEntries: () => unknown[] }).ownEntries = () => [];
    const x = w.forkedImpostor(bobDid, [carol]);
    invite(w, carol, bobDid, x);
    m.before();
    w.advance(25);
    m.after();
    expect(violations(m).some((v) => v.startsWith("detection goal") && v.includes(bob.id))).toBe(true);
  });
});
