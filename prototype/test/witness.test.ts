// Witnessed history (device-enrollment.md, Witnessed history) as a
// world policy. Scenarios 27-36 run in scenarios.test.ts; these cover Astra's
// cases, each rule the mutations in mutate.mjs break, and the findings the
// prototype made about the draft rules (see README.md#witnessed-history).

import { COL, bindingId } from "../src/protocol/types";
import { detectionViolations } from "../src/sim/detection";
import { InvariantMonitor } from "../src/sim/invariants";
import { Run } from "../src/sim/scenario";
import { scenarios } from "../src/sim/scenarios";
import { type Repo, revAt } from "../src/world/pds";
import { FETCH_TIMEOUT, RELAY_REPLAY_WINDOW, REV_ALLOWANCE, WITNESS_RETENTION } from "../src/world/relay";
import { World } from "../src/world/world";
import type { Installation } from "../src/protocol/installation";
import type { HistoryEntry } from "../src/protocol/witness";

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
    expect(g.fromRev <= acc.rev! && acc.rev! <= g.toRev).toBe(true);
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
    expect(bob.liveness()).toMatch(/behind the relay/);
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
    expect(bob.liveness()).toMatch(/behind the relay/);
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

describe("the frontier, by relay event time", () => {
  it("an honest relay that delivers to Bob's witness 30h late: its events arrive old, so Bob's phone warns within 24h", () => {
    // Formerly a FINDING: liveness by received frames counted this witness as
    // current. The frontier is now the relay's own time on the newest event
    // the witness processed, so the backlog counts against it.
    const { w, m, bob, carol, bobDid } = world("f1");
    w.relayDelay("lantern", 30);
    const x = w.forkedImpostor(bobDid, [carol]);
    invite(w, carol, bobDid, x);
    m.before();
    w.advance(25);
    m.after();
    expect(carol.trust.isAccepted(x.binding)).toBe(true);
    expect(about(bob, x)).toEqual([]);
    expect(bob.liveness()).toMatch(/behind the relay/);
    expect(w.witnessOf("lantern").frontierAge(bobDid)).toBeGreaterThan(24);
    expect(w.witnessOf("other").frontierAge(bobDid)).toBeLessThan(1);
    expect(violations(m)).toEqual([]);
    w.advance(6);
    expect(about(bob, x).length).toBe(1); // the fork arrives, at hour 30
  });

  it("a frontier more than CLOCK_SKEW ahead of the witness's clock is a fault: the owner warns, until it is resolved", () => {
    const { w, bob, bobDid } = world("k1");
    const lantern = w.witnessOf("lantern");
    w.setWitness("lantern", { clockOffset: -0.5 }); // the witness's clock 30 minutes slow
    const r = lantern.history(bob.id, bobDid, null);
    expect(r.fault).toBe("clock");
    expect(r.frontierAge).toBe(Infinity);
    w.advance(23);
    expect(bob.liveness()).toBeNull(); // coverage runs from the last good report
    w.advance(2);
    expect(bob.liveness()).toMatch(/clock fault/);
    // Within CLOCK_SKEW (3 minutes) is no fault: frontier age clamps at zero.
    w.setWitness("lantern", { clockOffset: -0.05 });
    expect(lantern.history(bob.id, bobDid, null)).toMatchObject({ fault: null, frontierAge: 0 });
    expect(bob.liveness()).toBeNull();
  });

  it("a slow witness clock can't hide a backlog: ahead beyond CLOCK_SKEW counts as over any limit", () => {
    // The witness's clock is 40 hours slow and the relay delivers to it 30
    // hours late: its clock minus its frontier is negative. Clamped to zero,
    // that would hide the backlog past the deadline.
    const { w, m, bob, carol, bobDid } = world("k2");
    w.setWitness("lantern", { clockOffset: -40 });
    w.relayDelay("lantern", 30);
    const x = w.forkedImpostor(bobDid, [carol]);
    invite(w, carol, bobDid, x);
    m.before();
    w.advance(25);
    m.after();
    expect(about(bob, x)).toEqual([]);
    expect(bob.liveness()).toMatch(/clock fault/);
    expect(violations(m)).toEqual([]);
  });

  it("a commit awaiting a fetch holds that account's frontier at its time, and no other account's", () => {
    const { w, bob, bobDid } = world("p1");
    const alice = w.install(w.account("alice"), "phone"); // also on Lantern
    const lantern = w.witnessOf("lantern");
    const stop = w.withholdFetch(bobDid, "lantern");
    const pds = w.pdsOf.get(bobDid)!;
    pds.relayHooks.push((d) => (d === bobDid ? { kind: "sync" } : null));
    const rev = pds.repo(bobDid).commit().commit.rev;
    w.settle();
    w.advance(0.5);
    expect(lantern.history(bob.id, bobDid, null).fault).toBe("fetch");
    expect(lantern.frontierAge(bobDid)).toBeCloseTo(0.5);
    expect(lantern.frontierAge(alice.did)).toBeCloseTo(0);
    expect(bob.coverageAge()).toBeCloseTo(0.5);
    expect(alice.coverageAge()).toBeCloseTo(0);
    expect(bob.mon.cursors.get(bobDid)!).toBeLessThan(rev);
    // The fetch succeeds: the commit is reconstructed and the frontier catches up.
    stop();
    w.advance(0.25);
    expect(lantern.frontierAge(bobDid)).toBeCloseTo(0);
    expect(bob.mon.cursors.get(bobDid)).toBe(rev);
    expect(bob.gapWarnings()).toEqual([]);
    // A fetch that never succeeds is a gap after FETCH_TIMEOUT, and the
    // frontier moves past it. The gap runs from just after the last revision
    // recorded: a commit the relay dropped before it would lie in it.
    w.withholdFetch(bobDid, "lantern");
    const rev2 = pds.repo(bobDid).commit().commit.rev;
    w.settle();
    w.advance(1);
    expect(bob.gapWarnings().map((g) => [g.fromRev, g.toRev, g.reason])).toEqual([[rev + 1, rev2, "the repo was not served within FETCH_TIMEOUT"]]);
    expect(lantern.frontierAge(bobDid)).toBeCloseTo(0);
    expect(bob.liveness()).toBeNull();
  });

  it("a fresh enrollment after retention warns of a gap for the history the witness no longer holds", () => {
    // Formerly a FINDING: fresh enrollment raised no retention gap, so an
    // impostor captured by a pending invite more than WITNESS_RETENTION
    // before the first install went unseen.
    const w = new World("f2", { policy: "witness" });
    const bobDid = w.account("bob", "pds.bob.example");
    const carol = w.install(w.account("carol"), "phone", { app: "other" });
    const f = w.flashImpostor(bobDid);
    invite(w, carol, bobDid, f.sub);
    f.undo();
    w.advance(WITNESS_RETENTION + 24);
    const bob = w.install(bobDid, "phone");
    expect(bob.trust.state.notices.filter((n) => n.kind === "history-binding")).toEqual([]);
    expect(bob.gapWarnings().map((g) => [g.fromRev, g.reason])).toEqual([[1, "older than WITNESS_RETENTION"]]);
  });
});

describe("cursors are repo revisions", () => {
  /** Commits to Carol's repo, so that each witness's own numbering of its
   * entries runs well ahead of Bob's revisions. */
  const busy = (w: World, carol: Installation) => {
    for (let n = 0; n < 6; n++) w.install(carol.did, `d${n}`, { link: carol });
  };
  const revWith = (w: World, did: string, x: Installation) =>
    w.pdsOf.get(did)!.repo(did).history.find((s) => s.records.has(`com.example.nbd.device/${x.binding.device.deviceId}`))!.commit.rev;

  it("a restore onto another application's witness resumes from the backup's revision: it alarms on an impostor added and deleted since, and warns for history that witness lacks", () => {
    const { w, m, bob, carol, bobDid } = world("c1");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    busy(w, carol);
    step(() => w.backup(bob));
    step(() => w.setOnline(bob, false));
    // Before the new application's witness starts: it will lack this.
    const early = w.flashImpostor(bobDid, "early");
    step(() => early.undo());
    step(() => w.lateWitness("beacon"));
    const f = w.flashImpostor(bobDid, "late");
    step(() => invite(w, carol, bobDid, f.sub));
    step(() => f.undo());
    step(() => w.advance(72));
    let restored!: Installation;
    step(() => (restored = w.restore(bob, 0, "phone-restored", { app: "beacon" })));
    expect(about(restored, f.sub).length).toBe(1);
    const r = revWith(w, bobDid, early.sub);
    const g = restored.gapWarnings().find((x) => x.fromRev <= r && r <= x.toRev);
    expect(g?.reason).toMatch(/before this witness's history/);
    expect(g!.fromRev).toBe(bob.mon.cursors.get(bobDid)! + 1); // only what follows the backup's cursor
    expect(violations(m)).toEqual([]);
  });

  it("a device paired onto another application's witness resumes from its approver's revision", () => {
    const { w, m, bob, carol, bobDid } = world("c2");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    busy(w, carol);
    step(() => w.setWitness("lantern", { reachable: false }));
    const cursor = bob.mon.cursors.get(bobDid)!;
    const early = w.flashImpostor(bobDid, "early");
    step(() => early.undo());
    step(() => w.lateWitness("beacon"));
    const f = w.flashImpostor(bobDid, "late");
    step(() => invite(w, carol, bobDid, f.sub));
    step(() => f.undo());
    let laptop!: Installation;
    step(() => (laptop = w.install(bobDid, "laptop", { link: bob, app: "beacon" })));
    expect(bob.mon.cursors.get(bobDid)).toBe(cursor); // the phone saw none of it
    expect(about(laptop, f.sub).length).toBe(1);
    const r = revWith(w, bobDid, early.sub);
    expect(laptop.gapWarnings().some((x) => x.fromRev === cursor + 1 && r <= x.toRev)).toBe(true);
    expect(violations(m)).toEqual([]);
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

describe("unrelayed commits and revision checks", () => {
  /** Carol shares Garden with Bob, so she pins his account. */
  const pinned = (seed: string) => {
    const x = world(seed);
    const garden = x.carol.createSpace("Garden");
    x.carol.invite(garden, x.bobDid);
    x.bob.join(garden);
    x.w.settle();
    return { ...x, repo: x.w.pdsOf.get(x.bobDid)!.repo(x.bobDid) };
  };
  const kinds = (i: Installation) => i.trust.state.alarms.map((a) => a.kind).filter((k) => k === "unrelayed-commit" || k === "relay-integrity" || k === "fork");
  /** Commits of `did` its PDS made that the relay never published. */
  const unpublished = (w: World, did: string) => {
    const published = new Set(w.relay!.events.filter((e) => e.did === did).map((e) => e.commit.rev));
    return w.pdsOf.get(did)!.repo(did).history.map((s) => s.commit.rev).filter((r) => !published.has(r));
  };
  /** Bob's PDS commits an impostor it never sends the relay, then restores
   * his records; `next` makes the commit that follows. */
  const unrelayedThenCommit = (w: World, carol: Installation, bobDid: string, repo: ReturnType<typeof pinned>["repo"], next: () => void) => {
    const honest = new Map(repo.records);
    const x = w.unrelayedImpostor(bobDid, [carol]);
    const rx = repo.latest().commit.rev;
    expect(carol.mon.incomplete.has(bobDid)).toBe(true); // above the witness's latest: INCOMPLETE
    repo.records = honest;
    next();
    w.serveAt(bobDid, rx, [carol]);
    return { x, rx };
  };

  it("a PDS commit never relayed, between two commits reconstructed consecutively, raises an integrity alarm with both commits as proof", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u1");
    m.before();
    const { x, rx } = unrelayedThenCommit(w, carol, bobDid, repo, () => {
      w.advance(1);
      w.install(bobDid, "tablet", { link: bob });
    });
    m.after();
    expect(kinds(carol)).toEqual(["unrelayed-commit"]);
    const p = carol.unrelayedProofs[0];
    expect(p.served.rev).toBe(rx);
    expect(p.below < rx && rx < p.above).toBe(true);
    expect(carol.mon.incomplete.has(bobDid)).toBe(false);
    expect(carol.trust.isAccepted(x.binding)).toBe(false);
    expect(kinds(bob)).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("the same unrelayed commit inside a recorded gap raises no alarm", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u2");
    m.before();
    const pds = w.pdsOf.get(bobDid)!;
    const stop = w.withholdFetch(bobDid, "other");
    unrelayedThenCommit(w, carol, bobDid, repo, () => {
      // The next commit is a #sync whose fetch Carol's witness never gets:
      // after FETCH_TIMEOUT it is a gap reaching back past the unrelayed one.
      let once = true;
      pds.relayHooks.push((d) => (d === bobDid && once ? { kind: "sync" as const } : null));
      repo.commit();
      once = false;
      w.settle();
      w.advance(2);
    });
    stop();
    w.install(bobDid, "tablet", { link: bob });
    m.after();
    expect(w.witnessOf("other").accounts.get(bobDid)!.history.some((h) => h.kind === "gap")).toBe(true);
    expect(carol.mon.auditGaps.length).toBe(1);
    expect(kinds(carol)).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("an honest relay that drops a commit: the next commit fails against the witness's state, so the dropped one lies in a gap, and serving it raises no alarm", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u3");
    m.before();
    w.advance(1);
    w.relayDrops(bobDid);
    const tablet = w.install(bobDid, "tablet", { link: bob });
    w.advance(1);
    w.install(bobDid, "laptop", { link: bob });
    const [rx] = unpublished(w, bobDid);
    expect(rx).toBeDefined();
    const g = bob.gapWarnings().find((x) => x.fromRev <= rx && rx <= x.toRev);
    expect(g?.reason).toBe("operations fail inversion");
    expect(carol.mon.auditGaps.some((x) => x.fromRev <= rx && rx <= x.toRev)).toBe(true);
    // A PDS serving the dropped commit (to a lagging reader, say) is no fork.
    w.serveAt(bobDid, rx, [carol, bob]);
    m.after();
    expect(kinds(carol)).toEqual([]);
    expect(kinds(bob)).toEqual([]);
    // The commit after the gap is reconstructed again, by a fetch.
    m.before();
    w.advance(1);
    w.install(bobDid, "desktop", { link: bob });
    m.after();
    expect(w.witnessOf("other").accounts.get(bobDid)!.history.at(-1)).toMatchObject({ kind: "state", via: "sync", rev: repo.latest().commit.rev });
    expect(carol.trust.isAccepted(tablet.binding)).toBe(true);
    expect(kinds(carol)).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("a dropped commit that changes nothing: the next commit's since names it, not the witness's revision, so a gap lies before that commit, which is still reconstructed from its operations, and serving the dropped one raises no alarm", () => {
    // Formerly exempt by its unchanged data: the next commit's operations
    // still invert to the witness's state. `since` now breaks the pair.
    const { w, m, bob, carol, bobDid, repo } = pinned("u4");
    m.before();
    w.advance(1);
    w.relayDrops(bobDid);
    repo.commit();
    w.settle();
    w.advance(1);
    w.install(bobDid, "tablet", { link: bob });
    const [rx] = unpublished(w, bobDid);
    const evs = w.relay!.events.filter((e) => e.did === bobDid);
    const before = evs.filter((e) => e.commit.rev < rx).at(-1)!;
    const after = evs.find((e) => e.commit.rev > rx)!;
    expect(repo.atRev(rx)!.commit.data).toBe(before.commit.data); // it changed nothing
    expect(after.since).toBe(rx);
    expect(w.witnessOf("other").commitAt(carol.id, bobDid, rx)).toEqual({ status: "gap" });
    expect(w.witnessOf("other").accounts.get(bobDid)!.history.filter((h) => h.seq === after.seq)).toMatchObject([
      { kind: "gap", reason: `its since names revision ${rx}, not the previous revision ${before.commit.rev}`, fromRev: before.commit.rev + 1, toRev: after.commit.rev - 1 },
      { kind: "state", rev: after.commit.rev, via: "commit" },
    ]);
    w.serveAt(bobDid, rx, [carol]);
    m.after();
    expect(carol.mon.auditGaps.some((x) => x.fromRev <= rx && rx <= x.toRev)).toBe(true);
    expect(kinds(carol)).toEqual([]);
    expect(carol.mon.incomplete.has(bobDid)).toBe(false);
    expect(violations(m)).toEqual([]);
  });

  it("an honest PDS adds a record and deletes it, the relay drops both, and the next commit still inverts to the witness's root: since breaks the pair, so serving the add raises no alarm (Astra)", () => {
    // Root continuity alone counted the next commit as consecutive with the
    // witness's state, and the add, strictly between them, as unrelayed.
    const { w, m, bob, carol, bobDid, repo } = pinned("u10");
    m.before();
    w.advance(1);
    const below = repo.latest().commit.rev;
    w.relayDrops(bobDid, 2);
    repo.records.set(`${COL.message}/note`, { text: "draft" });
    const added = repo.commit().commit.rev;
    w.advance(0.01);
    repo.records.delete(`${COL.message}/note`);
    repo.commit();
    w.settle();
    w.advance(1);
    w.install(bobDid, "tablet", { link: bob });
    expect(unpublished(w, bobDid)).toContain(added);
    const after = w.relay!.events.find((e) => e.did === bobDid && e.commit.rev > added)!;
    expect(after.prevData).toBe(repo.atRev(below)!.commit.data); // the root still continues
    expect(after.since).not.toBe(below);
    expect(w.witnessOf("other").accounts.get(bobDid)!.history.filter((h) => h.seq === after.seq).map((h) => h.kind)).toEqual(["gap", "state"]);
    expect(w.witnessOf("other").commitAt(carol.id, bobDid, added)).toEqual({ status: "gap" });
    // A delayed response, say, serves Carol the add.
    w.serveAt(bobDid, added, [carol]);
    m.after();
    expect(kinds(carol)).toEqual([]);
    expect(carol.mon.auditGaps.some((x) => x.fromRev <= added && added <= x.toRev)).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  it("a malicious PDS hiding a commit and naming the last relayed revision as since still raises the alarm", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u11");
    m.before();
    const { rx } = unrelayedThenCommit(w, carol, bobDid, repo, () => {
      w.advance(1);
      w.install(bobDid, "tablet", { link: bob });
    });
    m.after();
    const evs = w.relay!.events.filter((e) => e.did === bobDid);
    const after = evs.find((e) => e.commit.rev > rx)!;
    expect(after.since).toBe(evs.filter((e) => e.commit.rev < rx).at(-1)!.commit.rev);
    expect(kinds(carol)).toEqual(["unrelayed-commit"]);
    expect(violations(m)).toEqual([]);
  });

  it("a malicious PDS that misstates since after hiding a commit breaks consecutiveness and avoids the alarm, but the hidden commit is never accepted (the documented cost)", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u12");
    m.before();
    const pds = w.pdsOf.get(bobDid)!;
    const { x, rx } = unrelayedThenCommit(w, carol, bobDid, repo, () => {
      let once = true;
      pds.relayHooks.push((d) => (d === bobDid && once ? ((once = false), { since: 12345 }) : null));
      w.advance(1);
      w.install(bobDid, "tablet", { link: bob });
    });
    m.after();
    expect(w.relay!.events.find((e) => e.did === bobDid && e.commit.rev > rx)!.since).toBe(12345);
    expect(w.witnessOf("other").commitAt(carol.id, bobDid, rx)).toEqual({ status: "gap" });
    expect(kinds(carol)).toEqual([]);
    expect(carol.trust.isAccepted(x.binding)).toBe(false);
    expect(carol.mon.auditGaps.some((g) => g.fromRev <= rx && rx <= g.toRev)).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  it("a dropped commit followed by a #sync: the #sync's commit is not consecutive with the one before, so no alarm", () => {
    // Formerly a FINDING: a #sync carries no operations, so nothing fails
    // against the witness's state and no gap is recorded; counting it as
    // consecutive made the dropped commit an integrity alarm.
    const { w, m, bob, carol, bobDid, repo } = pinned("u5");
    m.before();
    w.advance(1);
    w.relayDrops(bobDid);
    w.install(bobDid, "tablet", { link: bob });
    const pds = w.pdsOf.get(bobDid)!;
    let once = true;
    pds.relayHooks.push((d) => (d === bobDid && once ? { kind: "sync" as const } : null));
    repo.commit();
    once = false;
    w.settle();
    const [rx] = unpublished(w, bobDid);
    expect(w.witnessOf("other").commitAt(carol.id, bobDid, rx).status).toBe("unknown");
    w.serveAt(bobDid, rx, [carol]);
    m.after();
    expect(kinds(carol)).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("a revision more than REV_ALLOWANCE ahead of its relay time is a gap, without an alarm or a new latest revision; later commits are processed normally", () => {
    const { w, m, bob, carol, bobDid } = pinned("u6");
    m.before();
    w.advance(1);
    const rf = w.futureCommit(bobDid, 24);
    const lantern = w.witnessOf("lantern").accounts.get(bobDid)!;
    expect(lantern.lastRev).toBeLessThan(rf);
    expect(lantern.history.at(-1)).toMatchObject({ kind: "gap", rev: rf });
    w.advance(1);
    const tablet = w.install(bobDid, "tablet", { link: bob });
    w.advance(1);
    const laptop = w.install(bobDid, "laptop", { link: tablet });
    m.after();
    for (const app of ["lantern", "other"]) {
      const a = w.witnessOf(app).accounts.get(bobDid)!;
      expect(a.lastRev).toBeLessThan(rf);
      expect(a.integrity).toEqual([]);
      expect(a.history.at(-1)!.kind).toBe("state");
      expect(a.history.filter((h) => h.kind === "gap").length).toBe(1);
    }
    expect([...kinds(bob), ...kinds(carol), ...kinds(tablet)]).toEqual([]);
    expect(bob.gapWarnings().map((g) => g.reason)).toEqual(["its revision is more than REV_ALLOWANCE ahead of its relay time"]);
    expect(bob.gapWarnings()[0].toRev).toBeLessThan(rf);
    expect(carol.trust.isAccepted(laptop.binding)).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  it("a served head the witness did not accept for its revision is neither INCOMPLETE nor an alarm", () => {
    const { w, m, carol, bobDid, repo } = pinned("u9");
    m.before();
    w.advance(1);
    const rf = w.futureCommit(bobDid, 24);
    m.after();
    expect(repo.latest().commit.rev).toBe(rf); // what the PDS serves Carol
    expect(w.witnessOf("other").commitAt(carol.id, bobDid, rf).status).toBe("gap");
    expect(carol.mon.incomplete.has(bobDid)).toBe(false);
    expect(kinds(carol)).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("a revision within REV_ALLOWANCE is accepted into the history", () => {
    const { w, bob, bobDid } = pinned("u7");
    w.advance(1);
    const rf = w.futureCommit(bobDid, 4 / 60);
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    expect(a.history.at(-1)).toMatchObject({ kind: "state", rev: rf });
    expect(bob.gapWarnings()).toEqual([]);
    expect(rf).toBeGreaterThan(revAt(w.t));
  });

  it("a revision the relay publishes not above the account's previous one is a gap and an integrity alarm, even for a client already past it", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u8");
    m.before();
    w.advance(1);
    w.install(bobDid, "tablet", { link: bob });
    const last = repo.latest().commit.rev;
    expect(repo.atRev(last - 1)).toBeUndefined();
    w.uncheckedRelay(bobDid);
    w.commitAtRev(bobDid, last - 1);
    m.after();
    expect(carol.mon.cursors.get(bobDid)).toBe(last);
    for (const i of [bob, carol]) expect(kinds(i)).toEqual(["relay-integrity"]);
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    expect(a.history.at(-1)).toMatchObject({ kind: "gap", rev: last - 1 });
    expect(a.lastRev).toBe(last);
    // The next commit is reconstructed as one after a gap.
    w.advance(1);
    w.install(bobDid, "laptop", { link: bob });
    expect(a.history.at(-1)!.kind).toBe("state");
    expect(violations(m)).toEqual([]);
  });

  it("a #sync re-announcing exactly the commit the witness holds as the account's latest is ignored: no alarm, no gap, the state kept (Astra)", () => {
    // Formerly a gap and an integrity alarm: the sync specification lets a
    // `#sync` re-announce the current commit without changing its revision,
    // and an honest relay passes it on.
    const { w, m, bob, carol, bobDid, repo } = pinned("u9");
    m.before();
    const r = repo.latest().commit.rev;
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    const entries = a.history.length;
    w.replayRevision(bobDid, r); // the current commit, sent again as a #sync
    m.after();
    expect(w.relay!.events.at(-1)).toMatchObject({ kind: "sync", did: bobDid, commit: { rev: r } });
    expect(a.history.length).toBe(entries);
    expect(a.integrity).toEqual([]);
    for (const i of [bob, carol]) expect(kinds(i)).toEqual([]);
    expect(bob.gapWarnings()).toEqual([]);
    // The state is kept: the next commit is reconstructed from its operations.
    w.advance(1);
    w.install(bobDid, "tablet", { link: bob });
    expect(a.history.at(-1)).toMatchObject({ kind: "state", via: "commit" });
    expect(bob.gapWarnings()).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("a #sync carrying a different commit at the revision the witness holds still raises the alarm and a gap", () => {
    const { w, m, bob, carol, bobDid, repo } = pinned("u10");
    m.before();
    const r = repo.latest().commit.rev;
    const own = repo.latest().commit.data;
    w.uncheckedRelay(bobDid);
    const pds = w.pdsOf.get(bobDid)!;
    let once = true;
    pds.relayHooks.push((d) => (d === bobDid && once ? ((once = false), { kind: "sync" as const }) : null));
    w.impostorAtRev(bobDid, r);
    m.after();
    const e = w.relay!.events.at(-1)!;
    expect(e).toMatchObject({ kind: "sync", commit: { rev: r } });
    expect(e.commit.data).not.toBe(own);
    for (const i of [bob, carol]) expect(kinds(i)).toEqual(["relay-integrity"]);
    expect(w.witnessOf("lantern").accounts.get(bobDid)!.history.at(-1)).toMatchObject({ kind: "gap", fromRev: r, toRev: r });
    expect(violations(m)).toEqual([]);
  });

  it("a #sync re-announcing a commit the witness recorded as a gap (its fetch timed out) retries the fetch: no alarm, and the earlier gap stays", () => {
    // Formerly a FINDING (README finding 29): the witness held no commit at
    // the revision, so the exemption didn't apply and the rule called the
    // honest re-announcement non-increasing, an integrity alarm.
    const { w, m, bob, carol, bobDid, repo } = pinned("u12");
    m.before();
    const stop = w.withholdFetch(bobDid, "lantern");
    const pds = w.pdsOf.get(bobDid)!;
    let once = true;
    pds.relayHooks.push((d) => (d === bobDid && once ? ((once = false), { kind: "sync" as const }) : null));
    w.install(bobDid, "tablet", { link: bob }); // its commit, sent as a #sync, awaits a fetch
    const x = repo.latest().commit.rev;
    w.advance(FETCH_TIMEOUT + 1);
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    const gap = a.history.at(-1)!;
    expect(gap).toMatchObject({ kind: "gap", rev: x, reason: "the repo was not served within FETCH_TIMEOUT" });
    stop();
    w.replayRevision(bobDid, x); // the PDS re-announces it
    m.after();
    expect(w.relay!.events.at(-1)).toMatchObject({ kind: "sync", commit: { rev: x } });
    expect(a.history.at(-1)).toMatchObject({ kind: "state", rev: x, via: "sync" });
    expect(a.history).toContain(gap); // gaps are permanent
    expect(a.integrity).toEqual([]);
    for (const i of [bob, carol]) expect(kinds(i)).toEqual([]);
    expect(bob.gapWarnings().some((g) => g.reason === "the repo was not served within FETCH_TIMEOUT" && g.toRev === x)).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  it("a #sync re-announcing the commit held, sent while the witness is away past the replay window: the stream gap is still recorded", () => {
    const { w, bob, carol, bobDid, repo } = pinned("u11");
    const r = repo.latest().commit.rev;
    w.setWitness("lantern", { connected: false });
    w.replayRevision(bobDid, r); // an honest re-announcement, during the outage
    w.install(carol.did, "tablet", { link: carol }); // the rest of the network moves on
    w.advance(RELAY_REPLAY_WINDOW + 1);
    w.setWitness("lantern", { connected: true });
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    expect(a.history.at(-1)).toMatchObject({ kind: "state", rev: r, via: "resync" });
    expect(bob.gapWarnings().map((g) => [g.reason, g.fromRev])).toEqual([["stream gap: the relay refused to resume", r + 1]]);
  });
});

describe("stream gaps", () => {
  /** Bob's phone offline, so that only a gap can warn him, and his witness
   * disconnected; the relay stops checking his revisions. */
  const away = (seed: string) => {
    const x = world(seed);
    const step = (fn: () => void) => { x.m.before(); fn(); x.m.after(); };
    step(() => x.w.setOnline(x.bob, false));
    step(() => x.w.setWitness("lantern", { connected: false }));
    step(() => x.w.uncheckedRelay(x.bobDid));
    return { ...x, step, lantern: x.w.witnessOf("lantern"), repo: x.w.pdsOf.get(x.bobDid)!.repo(x.bobDid) };
  };
  const revWith = (repo: Repo, x: Installation) =>
    repo.history.find((s) => s.records.has(`com.example.nbd.device/${x.binding.device.deviceId}`))!.commit.rev;

  it("an impostor published and the original revision replayed while the witness is away past the replay window: resynchronized at the revision it held, still a gap covering the impostor, and Bob warns (Astra)", () => {
    // Formerly exempt: a witness resynchronized at the revision it already
    // held recorded no gap. A relay that passes on non-increasing revisions
    // lets the PDS publish an impostor and then the original revision again.
    const { w, m, bob, carol, bobDid, step, lantern, repo } = away("s1");
    const r = repo.latest().commit.rev;
    expect(lantern.accounts.get(bobDid)!.lastRev).toBe(r);
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    expect(carol.trust.isAccepted(f.sub.binding)).toBe(true);
    const ri = revWith(repo, f.sub);
    step(() => w.replayRevision(bobDid, r));
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.setWitness("lantern", { connected: true }));
    const a = lantern.accounts.get(bobDid)!;
    expect(a.history.at(-1)).toMatchObject({ kind: "state", rev: r, via: "resync" });
    const g = a.history.find((h) => h.kind === "gap" && h.stream)!;
    expect(g).toMatchObject({ fromRev: r + 1, toRev: revAt(w.t + REV_ALLOWANCE), resync: r });
    step(() => w.setOnline(bob, true));
    expect(bob.gapWarnings().map((x) => x.reason)).toEqual(["stream gap: the relay refused to resume"]);
    const warned = bob.gapWarnings()[0];
    expect(warned.fromRev <= ri && ri <= warned.toRev).toBe(true);
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    expect(about(bob, f.sub)).toEqual([]); // the witness never saw the impostor
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
    // A device linked later reads the history afresh: the gap, once.
    const tablet = w.install(bobDid, "tablet", { link: bob });
    w.advance(2);
    expect(tablet.mon.gaps.length).toBe(1);
    expect(bob.gapWarnings().length).toBe(1);
  });

  it("an impostor Bob's PDS published, then any commit below it: resynchronized below the impostor's revision, the gap still covers it", () => {
    // The minimal case for the interval: original r0, impostor r2 that Carol
    // accepts, then a commit at r0 < r < r2, all during an outage past the
    // replay window. Ending the gap at the revision resynchronized at, r,
    // would leave r2 outside it.
    const { w, m, bob, carol, bobDid, step, lantern, repo } = away("s2");
    const r0 = repo.latest().commit.rev;
    const honest = new Map(repo.records);
    step(() => w.advance(1));
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    const r2 = revWith(repo, f.sub);
    repo.records = honest;
    const r = r2 - 1;
    expect(r).toBeGreaterThan(r0);
    step(() => w.commitAtRev(bobDid, r));
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.setWitness("lantern", { connected: true }));
    expect(lantern.accounts.get(bobDid)!.history.at(-1)).toMatchObject({ kind: "state", rev: r, via: "resync" });
    step(() => w.setOnline(bob, true));
    const g = bob.gapWarnings()[0];
    expect(g.fromRev).toBe(r0 + 1);
    expect(g.toRev).toBeGreaterThan(r2);
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("a commit relayed after the resume with a revision inside the gap's interval is still read: a cursor moves past a stream gap only to where it resumed", () => {
    const { w, m, bob, carol, bobDid, step, lantern, repo } = away("s3");
    const r = repo.latest().commit.rev;
    step(() => w.setOnline(bob, true));
    step(() => w.install(carol.did, "tablet", { link: carol })); // the rest of the network moves on
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.setWitness("lantern", { connected: true }));
    const g = lantern.accounts.get(bobDid)!.history.find((h) => h.kind === "gap" && h.stream) as { toRev: number };
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    const f = w.flashImpostor(bobDid);
    const ri = revWith(repo, f.sub);
    expect(ri).toBeLessThanOrEqual(g.toRev); // inside the stream gap's interval
    expect(about(bob, f.sub).length).toBe(1);
    expect(violations(m)).toEqual([]);
  });

  it("an earlier revision replayed: resynchronized below the revision held, a gap and an integrity alarm", () => {
    const { w, m, bob, carol, bobDid, step, lantern, repo } = away("s4");
    const r0 = repo.latest().commit.rev;
    step(() => w.setWitness("lantern", { connected: true }));
    step(() => w.setOnline(bob, true));
    step(() => w.advance(1));
    step(() => w.install(bobDid, "tablet", { link: bob }));
    const r = repo.latest().commit.rev;
    expect(r).toBeGreaterThan(r0);
    step(() => w.setOnline(bob, false));
    step(() => w.setWitness("lantern", { connected: false }));
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    const ri = revWith(repo, f.sub);
    step(() => w.replayRevision(bobDid, r0));
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.setWitness("lantern", { connected: true }));
    expect(lantern.accounts.get(bobDid)!.lastRev).toBe(r);
    step(() => w.setOnline(bob, true));
    const g = bob.gapWarnings()[0];
    expect(g.fromRev).toBe(r + 1);
    expect(g.toRev).toBeGreaterThan(ri);
    expect(bob.trust.state.alarms.some((a) => a.kind === "relay-integrity")).toBe(true);
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("an honest relay's stream gap is reported even for an account resynchronized at the revision held", () => {
    const { w, bob, carol, bobDid } = world("s5");
    const r = w.pdsOf.get(bobDid)!.repo(bobDid).latest().commit.rev;
    w.setWitness("lantern", { connected: false });
    w.install(carol.did, "tablet", { link: carol }); // the rest of the network moves on
    w.advance(RELAY_REPLAY_WINDOW + 1);
    w.setWitness("lantern", { connected: true });
    expect(bob.gapWarnings().map((g) => [g.fromRev, g.toRev])).toEqual([[r + 1, revAt(w.t + REV_ALLOWANCE)]]);
    expect(bob.liveness()).toBeNull();
  });
});

describe("where a witness's history starts", () => {
  /** As for stream gaps: Bob's phone offline, his witness disconnected, the
   * relay no longer checking his revisions. */
  const away = (seed: string) => {
    const x = world(seed);
    const step = (fn: () => void) => { x.m.before(); fn(); x.m.after(); };
    step(() => x.w.setOnline(x.bob, false));
    step(() => x.w.setWitness("lantern", { connected: false }));
    step(() => x.w.uncheckedRelay(x.bobDid));
    return { ...x, step, repo: x.w.pdsOf.get(x.bobDid)!.repo(x.bobDid) };
  };
  const revWith = (repo: Repo, x: Installation) =>
    repo.history.find((s) => s.records.has(`com.example.nbd.device/${x.binding.device.deviceId}`))!.commit.rev;
  const startGap = (w: World, app: string, did: string) =>
    w.witnessOf(app).accounts.get(did)!.history.find((h) => h.kind === "gap" && h.start) as Extract<HistoryEntry, { kind: "gap" }>;

  it("an impostor published and the original revision replayed, then Bob's witness rebuilt past the replay window: the gap before its history reaches Bob's cursor at the starting revision, and Bob warns (Astra)", () => {
    // Formerly the gap ran only through the revision before the starting
    // one: Bob, already at that revision, resumed past the impostor with
    // fresh coverage and nothing raised.
    const { w, m, bob, carol, bobDid, step, repo } = away("h1");
    const r = repo.latest().commit.rev;
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    expect(carol.trust.isAccepted(f.sub.binding)).toBe(true);
    const ri = revWith(repo, f.sub);
    step(() => w.replayRevision(bobDid, r));
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    const rebuilt = w.t;
    step(() => w.rebuildWitness("lantern"));
    step(() => w.setOnline(bob, true));
    const a = w.witnessOf("lantern").accounts.get(bobDid)!;
    expect(a.history.at(-1)).toMatchObject({ kind: "state", rev: r, via: "resync" });
    expect(startGap(w, "lantern", bobDid)).toMatchObject({ fromRev: 1, toRev: revAt(rebuilt + REV_ALLOWANCE), resync: r });
    expect(bob.gapWarnings().map((x) => x.reason)).toEqual(["before this witness's history of the account starts"]);
    const g = bob.gapWarnings()[0];
    expect(g.fromRev).toBe(r + 1);
    expect(g.toRev).toBeGreaterThanOrEqual(ri);
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    expect(bob.liveness()).toBeNull(); // coverage is fresh: only the gap can warn
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("the same replay, then a restore onto a new application's witness: the gap reaches the backup's cursor at the starting revision, and the restored phone warns", () => {
    const { w, m, bob, carol, bobDid, step, repo } = away("h2");
    const r = repo.latest().commit.rev;
    step(() => w.backup(bob));
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    const ri = revWith(repo, f.sub);
    step(() => w.replayRevision(bobDid, r));
    step(() => w.advance(1));
    step(() => w.lateWitness("beacon"));
    let restored!: Installation;
    step(() => (restored = w.restore(bob, 0, "phone-restored", { app: "beacon" })));
    expect(startGap(w, "beacon", bobDid)).toMatchObject({ fromRev: 1, resync: r });
    expect(restored.mon.cursors.get(bobDid)).toBe(r);
    const g = restored.gapWarnings().find((x) => x.fromRev <= ri && ri <= x.toRev);
    expect(g?.reason).toBe("before this witness's history of the account starts");
    expect(g!.fromRev).toBe(r + 1);
    expect(about(restored, f.sub)).toEqual([]); // the new witness never saw the impostor
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("a commit relayed after the rebuild with a revision inside the gap's interval is still read: a cursor moves past the gap only to the starting revision", () => {
    const { w, m, bob, bobDid, step, repo } = away("h3");
    const r = repo.latest().commit.rev;
    step(() => w.setOnline(bob, true));
    step(() => w.rebuildWitness("lantern"));
    const g = startGap(w, "lantern", bobDid);
    expect(g.resync).toBe(r);
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    const f = w.flashImpostor(bobDid);
    const ri = revWith(repo, f.sub);
    expect(ri).toBeGreaterThan(r);
    expect(ri).toBeLessThanOrEqual(g.toRev); // inside the gap's interval
    expect(about(bob, f.sub).length).toBe(1);
    expect(violations(m)).toEqual([]);
  });

  it("an earlier revision replayed before the rebuild starts the witness below Bob's cursor, set before it started: an integrity alarm with the starting commit as proof, and a gap through the cursor that covers an impostor published between the two", () => {
    // Formerly a FINDING (README finding 26). Bob's cursor is r. His PDS
    // replays r0 < r through a relay that doesn't check revisions; his
    // witness is rebuilt and starts at r0, unable to know it ever held r.
    // The PDS then publishes an impostor at r0 < ri < r, which the rebuilt
    // witness reconstructs (it is above r0) and Carol, on the same
    // application, accepts. Bob reads from r, so he never reads the
    // impostor; the starting-commit check is what catches it.
    const { w, m, bob, bobDid, step, repo } = away("h4");
    const carol = w.install(w.account("carol2"), "phone"); // on Bob's application
    const r0 = repo.latest().commit.rev;
    step(() => w.setOnline(bob, true));
    step(() => w.setWitness("lantern", { connected: true }));
    step(() => w.advance(1));
    const tablet = w.install(bobDid, "tablet", { link: bob });
    const r = repo.latest().commit.rev;
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    step(() => w.setOnline(bob, false));
    step(() => w.setOnline(tablet, false));
    step(() => w.replayRevision(bobDid, r0));
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.rebuildWitness("lantern"));
    step(() => w.advance(1));
    const ri = Math.floor((r0 + r) / 2);
    const sub = w.impostorAtRev(bobDid, ri);
    step(() => invite(w, carol, bobDid, sub));
    expect(carol.trust.isAccepted(sub.binding)).toBe(true);
    expect(startGap(w, "lantern", bobDid).resync).toBe(r0);
    step(() => w.setOnline(bob, true));
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    expect(bob.trust.state.alarms.filter((a) => a.kind === "relay-integrity").length).toBe(1);
    expect(bob.startProofs).toMatchObject([{ did: bobDid, start: { rev: r0 }, cursor: r }]);
    expect(bob.gapWarnings().some((g) => g.fromRev <= ri && ri <= g.toRev)).toBe(true);
    step(() => w.advance(25));
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("an impostor republished below Bob's cursor, then his witness rebuilt at it: Bob alarms, with the starting commit as proof", () => {
    const { w, m, bob, carol, bobDid, step, repo } = away("h5");
    const r = repo.latest().commit.rev;
    const f = w.flashImpostor(bobDid);
    step(() => invite(w, carol, bobDid, f.sub));
    expect(carol.trust.isAccepted(f.sub.binding)).toBe(true);
    const ri = revWith(repo, f.sub);
    const low = r - 1;
    step(() => w.commitAtRev(bobDid, low)); // the impostor's records again, below Bob's cursor
    step(() => w.advance(RELAY_REPLAY_WINDOW + 1));
    step(() => w.rebuildWitness("lantern"));
    step(() => w.setOnline(bob, true));
    expect(startGap(w, "lantern", bobDid).resync).toBe(low);
    expect(bob.startProofs).toMatchObject([{ did: bobDid, start: { rev: low }, cursor: r }]);
    expect(bob.trust.state.alarms.some((a) => a.kind === "relay-integrity")).toBe(true);
    expect(bob.gapWarnings().some((g) => g.fromRev <= ri && ri <= g.toRev)).toBe(true);
    expect(violations(m)).toEqual([]);
    expect(detectionViolations(w)).toEqual([]);
  });

  it("a different commit published at Bob's cursor's revision, then his witness rebuilt at it: Bob alarms", () => {
    const { w, m, bob, bobDid, step, repo } = away("h6");
    const r = repo.latest().commit.rev;
    const own = repo.latest().commit.data;
    step(() => w.advance(1));
    step(() => void w.impostorAtRev(bobDid, r));
    step(() => w.rebuildWitness("lantern"));
    step(() => w.setOnline(bob, true));
    const s = startGap(w, "lantern", bobDid);
    expect(s.resync).toBe(r);
    expect(s.startCommit!.data).not.toBe(own);
    expect(bob.startProofs).toMatchObject([{ did: bobDid, start: { rev: r }, cursor: r }]);
    expect(bob.trust.state.alarms.some((a) => a.kind === "relay-integrity")).toBe(true);
    expect(bob.gapWarnings().some((g) => g.fromRev === r && g.toRev === r)).toBe(true);
    expect(violations(m)).toEqual([]);
  });

  /** Beacon starts following the relay, and in the same relay instant Bob
   * links a tablet, sequenced just after beacon's start; Bob backs up. */
  const sameInstant = (seed: string) => {
    const x = world(seed);
    const step = (fn: () => void) => { x.m.before(); fn(); x.m.after(); };
    step(() => x.w.advance(1));
    step(() => x.w.lateWitness("beacon"));
    step(() => void x.w.install(x.bobDid, "tablet", { link: x.bob }));
    const c = x.bob.mon.cursors.get(x.bobDid)!;
    const g = startGap(x.w, "beacon", x.bobDid);
    const set = x.w.relay!.events.find((e) => e.did === x.bobDid && e.commit.rev === c)!;
    expect(set.time).toBe(x.w.t); // the instant beacon started following
    expect(x.bob.mon.cursorSeqs.get(x.bobDid)).toBe(set.seq);
    expect(set.seq).toBeGreaterThan(g.followedAfter!); // sequenced after beacon's start
    expect(g.resync).toBeLessThan(c); // the cursor is above where beacon's history starts
    expect(g.toRev).toBeGreaterThanOrEqual(c); // and beacon serves it the gap
    step(() => x.w.backup(x.bob));
    step(() => x.w.advance(48)); // beacon follows the account a while
    return { ...x, step, c, g };
  };

  it("an honest restore onto another application's witness, with a cursor sequenced just after that witness started, in the same relay instant, raises no integrity alarm", () => {
    const { w, m, bob, bobDid, step, c } = sameInstant("h7");
    let restored!: Installation;
    step(() => (restored = w.restore(bob, 0, "phone-restored", { app: "beacon" })));
    expect(restored.mon.cursors.get(bobDid)).toBeGreaterThanOrEqual(c);
    expect(restored.startProofs).toEqual([]);
    expect(restored.trust.state.alarms.filter((a) => a.kind === "relay-integrity")).toEqual([]);
    // Only the gap before beacon's history, which reaches the cursor.
    expect(restored.gapWarnings().map((x) => x.reason)).toEqual(["before this witness's history of the account starts"]);
    expect(violations(m)).toEqual([]);
  });

  it("the same restore from a backup whose cursor carries no sequence number: the order can't be established, so a gap from the starting revision through the cursor, a warning and not an alarm", () => {
    const { w, m, bob, bobDid, step, c, g } = sameInstant("h9");
    w.backups[0].state.witness!.cursorSeqs.delete(bobDid); // saved before the rule
    let restored!: Installation;
    step(() => (restored = w.restore(bob, 0, "phone-restored", { app: "beacon" })));
    expect(restored.startProofs).toEqual([]);
    expect(restored.trust.state.alarms.filter((a) => a.kind === "relay-integrity")).toEqual([]);
    const order = restored.gapWarnings().filter((x) => x.key.includes(":start-order:"));
    expect(order.map((x) => [x.fromRev, x.toRev])).toEqual([[g.resync, c]]);
    expect(violations(m)).toEqual([]);
  });

  it("a cursor without a sequence number at the starting revision, with the same commit: the check wouldn't fire, so no gap for the unknown order", () => {
    const { w, m, bob, bobDid, step, repo } = away("h10");
    const r = repo.latest().commit.rev;
    step(() => w.setOnline(bob, true));
    bob.mon.cursorSeqs.delete(bobDid); // a cursor carried without one
    step(() => w.rebuildWitness("lantern"));
    expect(startGap(w, "lantern", bobDid).resync).toBe(r);
    expect(bob.mon.cursors.get(bobDid)).toBe(r);
    expect(bob.gapWarnings().filter((g) => g.key.includes(":start-order:"))).toEqual([]);
    expect(bob.trust.state.alarms.filter((a) => a.kind === "relay-integrity")).toEqual([]);
    expect(violations(m)).toEqual([]);
  });

  it("Bob's cursor set at the revision allowance's edge, an impostor published below it, and his witness rebuilt, all in one relay instant: sequence numbers order them, so Bob alarms (Astra)", () => {
    // Formerly the cursor's relay time was compared with the time the
    // witness started following; equal, the cursor counted as after the
    // start and the check was skipped. The gap before the rebuilt witness's
    // history ends at REV_ALLOWANCE past that time, which is Bob's cursor R,
    // so nothing reached it, and nothing warned after 25 hours.
    const { w, m, bob, bobDid } = world("h8");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    const carol = w.install(w.account("carol2"), "phone"); // on Bob's application
    step(() => w.uncheckedRelay(bobDid));
    step(() => w.advance(1));
    const t = w.t;
    const R = revAt(t + REV_ALLOWANCE); // the highest revision a witness accepts now
    step(() => w.commitAtRev(bobDid, R));
    expect(bob.mon.cursors.get(bobDid)).toBe(R);
    step(() => w.setOnline(bob, false));
    step(() => w.setWitness("lantern", { connected: false }));
    let sub!: Installation;
    step(() => (sub = w.impostorAtRev(bobDid, R - 1)));
    step(() => w.rebuildWitness("lantern"));
    step(() => invite(w, carol, bobDid, sub));
    expect(carol.trust.isAccepted(sub.binding)).toBe(true);
    expect(w.t).toBe(t);
    expect(w.relay!.events.filter((e) => e.did === bobDid && e.commit.rev >= R - 1).map((e) => e.time)).toEqual([t, t]);
    const g = startGap(w, "lantern", bobDid);
    expect(g).toMatchObject({ resync: R - 1, toRev: R });
    step(() => w.setOnline(bob, true));
    step(() => w.advance(25));
    expect(detectionViolations(w)).toEqual([]); // the goal check: Bob alarmed or warned in time
    expect(violations(m)).toEqual([]);
    expect(bob.trust.state.alarms.filter((a) => a.kind === "relay-integrity").length).toBe(1);
    expect(bob.startProofs).toMatchObject([{ did: bobDid, start: { rev: R - 1 }, cursor: R }]);
  });
});

describe("reference relay timestamps", () => {
  /** Bob's witness offline for 30 hours, then catching up through a relay
   * that sends it its backlog 28 hours late. */
  const outage = (seed: string, refresh: boolean) => {
    const x = world(seed);
    if (refresh) x.w.relayTimeOnDelivery();
    x.w.setWitness("lantern", { connected: false });
    x.w.advance(1);
    x.w.install(x.bobDid, "tablet", { link: x.bob });
    x.w.advance(29);
    x.w.relayDelay("lantern", 28);
    x.w.setWitness("lantern", { connected: true });
    return x;
  };

  it("a replayed event keeps the time the relay first sequenced it: a witness catching up after an outage has an old frontier", () => {
    const { w, bobDid } = outage("t1", false);
    const lantern = w.witnessOf("lantern");
    const sequenced = w.relay!.events.find((e) => e.did === bobDid && e.time > 0.5)!;
    const replayed = w.relay!.delivered(lantern.id, 0).find((e) => e.seq === sequenced.seq)!;
    expect(replayed.time).toBe(sequenced.time);
    expect(lantern.cursor).toBeGreaterThanOrEqual(sequenced.seq); // replayed and processed
    expect(lantern.frontierAge(bobDid)).toBeCloseTo(28);
  });

  it("not the reference relay: one that stamps events with the time it sends them makes the backlog look current, and Bob misses the deadline", () => {
    // Documented non-reference behavior (Relay.timeOnDelivery): the sync
    // specification allows it of an honest relay, and the rules forbid
    // it of the reference relay. The same backlog as above, and the f1
    // backlog, read as current.
    const { w, bobDid } = outage("t2", true);
    const lantern = w.witnessOf("lantern");
    const sequenced = w.relay!.events.find((e) => e.did === bobDid && e.time > 0.5)!;
    expect(w.relay!.delivered(lantern.id, 0).find((e) => e.seq === sequenced.seq)!.time).toBeGreaterThan(sequenced.time + 28);
    expect(lantern.frontierAge(bobDid)).toBeCloseTo(0);

    const x = world("t3");
    x.w.relayTimeOnDelivery();
    x.w.relayDelay("lantern", 30);
    const imp = x.w.forkedImpostor(x.bobDid, [x.carol]);
    invite(x.w, x.carol, x.bobDid, imp);
    x.w.advance(25);
    expect(x.carol.trust.isAccepted(imp.binding)).toBe(true);
    expect(about(x.bob, imp)).toEqual([]);
    expect(x.bob.liveness()).toBeNull();
    expect(detectionViolations(x.w).some((v) => v.text.includes(x.bob.id))).toBe(true);
  });
});

describe("time in transit", () => {
  it("an answer computed before an attack and delivered 20 hours later doesn't refresh coverage: Bob warns within 24h of the acceptance", () => {
    const { w, m, bob, carol, bobDid } = world("x1");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    step(() => w.witnessTransit(bob, 20)); // the request goes out now; its answer is computed now
    const t0 = w.t;
    step(() => w.advance(1));
    let x!: Installation;
    step(() => {
      x = w.forkedImpostor(bobDid, [carol]);
      invite(w, carol, bobDid, x);
    });
    expect(carol.trust.isAccepted(x.binding)).toBe(true);
    step(() => w.advance(19)); // the answer from t0 arrives, from before the attack
    expect(w.t).toBeCloseTo(t0 + 20);
    expect(about(bob, x)).toEqual([]);
    expect(bob.coverageAge()).toBeCloseTo(20);
    step(() => w.advance(4.5));
    expect(bob.liveness()).toMatch(/behind the relay/);
    expect(violations(m)).toEqual([]);
    step(() => w.advance(17));
    expect(about(bob, x).length).toBe(1); // the next answer, asked for an hour later at most
    expect(violations(m)).toEqual([]);
  });

  it("an answer in several pages ages from the first page's request", () => {
    const { w, bob, bobDid } = world("x2");
    const repo = w.pdsOf.get(bobDid)!.repo(bobDid);
    w.setOnline(bob, false);
    for (let n = 0; n < 3; n++) {
      w.advance(1);
      repo.commit();
    }
    w.advance(10);
    w.setWitness("lantern", { pageSize: 1 });
    w.witnessTransit(bob, 2);
    const cursor = bob.mon.cursors.get(bobDid)!;
    w.setOnline(bob, true); // the first page's request
    const t0 = w.t;
    w.advance(5);
    expect(bob.mon.cursors.get(bobDid)!).toBeGreaterThan(cursor); // two pages in
    expect(bob.coverageAge()).toBeGreaterThan(13);
    w.advance(1); // the third and last page arrives, asked for at t0 + 4
    expect(w.t).toBeCloseTo(t0 + 6);
    expect(bob.mon.cursors.get(bobDid)).toBe(repo.latest().commit.rev);
    expect(bob.coverageAge()).toBeCloseTo(6);
  });
});

describe("time in transit: paged answers, late answers, restarts", () => {
  it("a paged answer carries one frontier age, computed when the first page's request arrived", () => {
    const { w, bob, bobDid } = world("x3");
    const repo = w.pdsOf.get(bobDid)!.repo(bobDid);
    w.setOnline(bob, false);
    w.setWitness("lantern", { pageSize: 1, lag: 10 });
    for (let n = 0; n < 3; n++) {
      w.advance(1);
      repo.commit();
    }
    w.advance(10);
    w.witnessTransit(bob, 2);
    w.setOnline(bob, true); // the first page's request: frontier age 10
    expect(w.witnessOf("lantern").frontierAge(bobDid)).toBeCloseTo(10);
    w.setWitness("lantern", { lag: 0 }); // caught up before the later pages
    w.advance(6);
    expect(bob.mon.cursors.get(bobDid)).toBe(repo.latest().commit.rev);
    expect(bob.coverageAge()).toBeCloseTo(16);
  });

  it("a late answer whose frontier is older than the coverage held doesn't move coverage back", () => {
    const { w, bob } = world("x5");
    w.witnessTransit(bob, 2); // a request now, answered with frontier age 0
    w.setWitness("lantern", { clockOffset: 10 }); // the next answer's frontier age is 10
    w.advance(2);
    expect(bob.coverageAge()).toBeCloseTo(2);
    w.advance(2); // that answer arrives: 10 + 2 is older than the coverage held
    expect(bob.coverageAge()).toBeCloseTo(4);
  });

  it("an answer to a request sent before a restart is discarded: Bob warns within 24h of an acceptance it predates", () => {
    const { w, m, bob, carol, bobDid } = world("x4");
    const step = (fn: () => void) => { m.before(); fn(); m.after(); };
    step(() => w.witnessTransit(bob, 20)); // a request now, answered from before the attack
    step(() => w.advance(0.5));
    step(() => w.setOnline(bob, false));
    step(() => w.advance(0.5));
    let x!: Installation;
    step(() => {
      x = w.forkedImpostor(bobDid, [carol]);
      invite(w, carol, bobDid, x);
    });
    step(() => w.advance(19));
    step(() => w.setOnline(bob, true)); // a restart, as the old answer arrives
    expect(bob.coverageAge()).toBeGreaterThan(19);
    step(() => w.advance(4.5));
    expect(bob.liveness()).toMatch(/behind the relay/);
    expect(violations(m)).toEqual([]);
  });
});
