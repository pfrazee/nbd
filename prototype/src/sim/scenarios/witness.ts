// Scenarios for the Relay-Witnessed Repos proposal
// (proposal-reliable-detection.md), one per row of its "What it achieves"
// table, plus cases it keeps out of reach. Each runs under the "witness"
// policy; where the comparison means something, the same steps also run
// under the specified rule without witnessing ("inviters"), to show that it
// misses the case. Bob's PDS is the attacker throughout. Bob's phone uses
// the app Lantern, whose witness it trusts; Carol, the inviter, uses
// another app with its own witness.

import type { Installation } from "../../protocol/installation";
import { REENROLL_HOLD } from "../../protocol/trust";
import type { Policy } from "../../protocol/types";
import type { World } from "../../world/world";
import { WITNESS_RETENTION } from "../../world/relay";
import { detectionViolations } from "../detection";
import { type Check, type Scenario, type Step, check } from "../scenario";

const hasKey = (i: Installation, space: string) => !!i.spaces.get(space)?.key;
/** Alarms `i` raised about `x`'s device, and when (world time). */
const alarmsAbout = (i: Installation, x: Installation) => i.trust.state.alarms.filter((a) => a.device === x.binding.device.deviceId);
const anyAlarm = (i: Installation, kind: string) => i.trust.state.alarms.some((a) => a.kind === kind);
/** When `by` accepted `x` (world time), from the ground-truth log. */
const acceptedAt = (w: World, by: Installation, x: Installation) =>
  w.provenance.accepts.find((a) => a.inst === by.id && a.target === x.binding.device.deviceId);
/** The detection goal, judged for this account now. Under the witness
 * policy the invariant monitor runs it after every step; for the
 * comparison runs a scenario asks for it directly. */
const missed = (w: World, did: string) => detectionViolations(w).filter((v) => v.text.startsWith(did.slice(8) + "/"));

/** Bob (at his malicious PDS) and Carol each install. */
function setup(opts: { carolPds?: string } = {}): Step {
  return {
    title: "Bob and Carol install the app",
    narration: "Bob's phone runs Lantern and trusts Lantern's witness; Carol uses another app with its own witness. Both witnesses tail the reference relay. Bob's PDS is malicious: it can sign anything in Bob's repo and choose what to send the relay and what to serve each client. Under the specified rule without witnessing, clients read whatever the PDS serves them.",
    run: (w, c) => {
      c.did.bob = w.account("bob", "pds.bob.example");
      c.did.carol = w.account("carol", opts.carolPds ?? "pds.example");
      c.inst.bobPhone = w.install(c.did.bob, "phone");
      c.inst.carolPhone = w.install(c.did.carol, "phone", { app: "other" });
    },
    expect: (w, c) => [
      check("Carol has never met Bob", !c.inst.carolPhone.trust.knew(c.did.bob)),
      ...(w.policy === "witness" ? [check("Bob's phone is covered (coverage age under 24h)", c.inst.bobPhone.liveness() === null)] : []),
    ],
  };
}

/** Carol creates Garden and invites Bob; the impostor joins and Carol grants. */
function carolInvites(): Step {
  return {
    title: "Carol creates Garden and invites Bob",
    narration: "Carol's app meets Bob's account for the first time while inviting him, so it accepts the device it sees on first use and its invite authorizes that device in Garden. The impostor joins and Carol's app grants it the key at once: the inviter's disclosure, which no rule here prevents. Bob's phone never learns Garden exists.",
    run: (w, c) => {
      c.space.garden = c.inst.carolPhone.createSpace("Garden");
      c.inst.carolPhone.post(c.space.garden, "Plans for the garden party.");
      c.inst.carolPhone.invite(c.space.garden, c.did.bob);
      c.inst.impostor.join(c.space.garden);
      w.settle();
    },
    expect: (_w, c) => [
      check("Carol accepted the impostor as Bob's device", c.inst.carolPhone.trust.isAccepted(c.inst.impostor.binding)),
      check("The impostor holds Garden's key", hasKey(c.inst.impostor, c.space.garden)),
      check("Bob's phone is not in Garden", !c.inst.bobPhone.spaces.has(c.space.garden)),
    ],
  };
}

/** A day passes; Bob's phone either alarmed or warned in time, or not. */
function dayLater(what: string, opts: { gap?: boolean } = {}): Step {
  return {
    title: "25 hours later",
    narration: `Under the witness policy, ${what} Under the specified rule without witnessing, Bob's phone has seen nothing, and the detection goal check reports the miss.`,
    run: (w) => w.advance(25),
    expect: (w, c) => {
      const acc = acceptedAt(w, c.inst.carolPhone, c.inst.impostor);
      const out: Check[] = [];
      if (w.policy === "witness") {
        if (opts.gap) {
          const g = c.inst.bobPhone.mon.gaps.find((x) => acc?.rev != null && x.fromRev <= acc.rev && acc.rev <= x.toRev);
          out.push(check("Bob's phone warns of a gap covering the commit Carol relied on", !!g, g?.reason));
          out.push(check("…recorded within 24 hours of Carol's acceptance", !!g && !!acc && g.world - acc.world <= 24));
        } else {
          const a = alarmsAbout(c.inst.bobPhone, c.inst.impostor)[0];
          out.push(check("Bob's phone alarmed about the impostor", !!a, a?.text));
          out.push(check("…within 24 hours of Carol's acceptance", !!a && !!acc && (a.world ?? Infinity) - acc.world <= 24));
        }
        out.push(check("The detection goal holds for Bob", missed(w, c.did.bob).length === 0));
      } else {
        out.push(check("Bob's phone never alarmed about the impostor", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length === 0));
        out.push(check("The detection goal check reports the miss", missed(w, c.did.bob).length > 0, missed(w, c.did.bob)[0]?.text));
      }
      return out;
    },
  };
}

function variants(make: (policy: Policy) => Scenario): Scenario[] {
  return [make("witness"), make("inviters")];
}

const suffix = (p: Policy) => (p === "witness" ? "" : " (specified rule, no witness)");
const idOf = (base: string, p: Policy) => (p === "witness" ? base : `${base}-specified`);

/** Row 1-2: a forked impostor shown to the inviter, in a space Bob can't read. */
const forked = (policy: Policy, n: number, sharedPds: boolean): Scenario => ({
  id: idOf(sharedPds ? "witness-same-pds" : "witness-fork", policy),
  policy,
  title: `${n}. Witness: ${sharedPds ? "the inviter on the same PDS" : "a forked impostor in a space Bob can't read"}${suffix(policy)}`,
  summary: sharedPds
    ? "As before, but Carol's repo is on Bob's malicious PDS too, so the grant and invite records sit on a server the attacker controls. With witnessing it makes no difference: the alarm comes from Bob's public repo history."
    : "Bob's PDS sends the relay (and Carol) a fork of Bob's repo with an impostor as his only device, while serving Bob's phone the real repo. Carol invites Bob into a new space and grants the impostor. Without witnessing, Bob never finds out; with it, his phone alarms within minutes.",
  steps: [
    setup(sharedPds ? { carolPds: "pds.bob.example" } : {}),
    {
      title: "Bob's PDS forks his repo",
      narration: "To get an honest client to accept its device, the PDS must put it where that client reads. Without witnessing, it serves only Carol a forged repo. With witnessing, Carol accepts only what her app's witness reconstructed from the relay, so the PDS must send the relay the fork, and Bob's witness, tailing the same relay, reconstructs it too. Bob's phone processes the fork: its own record deleted, an unknown device present. It also sees the PDS serve it a different commit at the same revision: a fork alarm.",
      run: (w, c) => {
        c.inst.impostor = w.forkedImpostor(c.did.bob, [c.inst.carolPhone]);
      },
      expect: (w, c) => w.policy === "witness"
        ? [
          check("Bob's phone alarms: an unknown device on his account", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length > 0),
          check("Bob's phone alarms: this device was removed", anyAlarm(c.inst.bobPhone, "own-removed")),
          check("Bob's phone alarms: the PDS served a fork of the published commit", anyAlarm(c.inst.bobPhone, "fork")),
        ]
        : [check("Bob's phone sees nothing", c.inst.bobPhone.trust.state.alarms.length === 0)],
    },
    carolInvites(),
    dayLater("Bob's phone alarmed before Carol even invited him: the alarm comes from his public repo, whichever spaces were involved."),
  ],
});

/** Row 4: a device published briefly, then deleted, while Bob's phone is offline. */
const flash = (policy: Policy): Scenario => ({
  id: idOf("witness-flash", policy),
  policy,
  title: `29. Witness: a device published briefly, then deleted${suffix(policy)}`,
  summary: "While Bob's phone is offline, his PDS replaces his devices with an impostor in an ordinary commit, Carol meets and grants it, and the PDS restores Bob's devices. Bob's phone comes back to an unchanged-looking repo; with witnessing it replays every commit since its cursor and alarms.",
  steps: [
    setup(),
    {
      title: "Bob's phone goes offline; his PDS publishes an impostor",
      narration: "The commit deletes Bob's phone and adds the PDS's device. It is published to the relay like any other: honest clients only accept what was published.",
      run: (w, c) => {
        w.setOnline(c.inst.bobPhone, false);
        const f = w.flashImpostor(c.did.bob);
        c.inst.impostor = f.sub;
        undo.set(w, f.undo);
      },
    },
    carolInvites(),
    {
      title: "The PDS deletes the impostor and restores Bob's phone",
      narration: "Bob's repo now looks exactly as it did. Carol's app sees a reset of Bob's account and holds the restored phone, but the key is already out.",
      run: (w) => undo.get(w)!(),
      expect: (_w, c) => [check("The impostor's record is gone", !c.inst.carolPhone.trust.isAccepted(c.inst.impostor.binding))],
    },
    {
      title: "Bob's phone comes back online",
      narration: "Without witnessing, it reads the latest commit: nothing changed. With witnessing, it resumes its own account's history from its saved cursor and processes every reconstructed commit since, including the one that held the impostor.",
      run: (w, c) => w.setOnline(c.inst.bobPhone, true),
      expect: (w, c) => w.policy === "witness"
        ? [check("Bob's phone alarms about the impostor", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length > 0), check("…and about its own removal", anyAlarm(c.inst.bobPhone, "own-removed"))]
        : [check("Bob's phone sees nothing", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length === 0)],
    },
    dayLater("Bob's phone alarmed as soon as it ran again; it was not running during the impostor's window, so that is in time."),
  ],
});
const undo = new WeakMap<World, () => void>();
const mark = new WeakMap<World, number>();

/** Row 5: a #sync root broadcast with an impostor, replaced before Bob's witness fetched it. */
const syncRoot = (policy: Policy): Scenario => ({
  id: idOf("witness-sync-root", policy),
  policy,
  title: `30. Witness: a #sync root replaced before Bob's witness fetches it${suffix(policy)}`,
  summary: "Bob's PDS publishes a #sync event whose root has an impostor as Bob's only device, serves that root only to Carol's witness, and serves Bob's witness its replacement. Carol accepts the impostor; Bob's witness records a gap it can never fill, and Bob's phone warns. A later resync doesn't erase it.",
  steps: [
    setup(),
    {
      title: "Bob's PDS publishes a #sync root with an impostor",
      narration: "A #sync event carries only the commit, so a witness must fetch the repo and check it against that exact root. Carol's witness is served the root; Bob's witness is served the honest records at the next revision, which don't match, so it records a gap. Bob's phone is shown the old commit throughout.",
      run: (w, c) => {
        c.inst.impostor = w.publishSyncRoot(c.did.bob, w.policy === "witness" ? [w.witnessOf("other").id] : []);
      },
      expect: (w, c) => w.policy === "witness"
        ? [
          check("Bob's phone has a gap warning", c.inst.bobPhone.gapWarnings().length === 1, c.inst.bobPhone.gapWarnings()[0]?.reason),
          check("…but no alarm: a gap is not proof of an attack", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length === 0),
        ]
        : [],
    },
    carolInvites(),
    {
      title: "The PDS publishes the replacement root",
      narration: "Every witness reconstructs the new root. A later snapshot does not reconstruct the earlier one, so Bob's gap stays: gaps are permanent records.",
      run: (w, c) => w.replaceSyncRoot(c.did.bob),
      expect: (w, c) => w.policy === "witness"
        ? [
          check("Bob's witness reconstructed the replacement", w.witnessOf("lantern").accounts.get(c.did.bob)!.history.at(-1)!.kind === "state"),
          check("Bob's gap warning remains", c.inst.bobPhone.gapWarnings().length === 1),
        ]
        : [],
    },
    dayLater("Bob's phone warned of the gap as soon as its witness recorded it: a warning, since withholding looks like failure.", { gap: true }),
  ],
});

/** Row 6: a PDS hides a reset from its own user (non-goal 2). */
const hiddenReset = (policy: Policy): Scenario => ({
  id: idOf("witness-hidden-reset", policy),
  policy,
  title: `31. Witness: a PDS hides a reset from its user${suffix(policy)}`,
  summary: "Bob's PDS resets his account, publishing the deletions to members, while showing Bob's phone the old repo. Alice's app holds the new device for 72 hours. With witnessing, Bob's phone reads the published history and alarms while the hold still runs.",
  steps: [
    {
      title: "Alice and Bob share Book club",
      narration: "Alice invites Bob, meeting his phone on first use, and grants him the key.",
      run: (w, c) => {
        c.did.alice = w.account("alice");
        c.did.bob = w.account("bob", "pds.bob.example");
        c.inst.alicePhone = w.install(c.did.alice, "phone", { app: "other" });
        c.inst.bobPhone = w.install(c.did.bob, "phone");
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [check("Bob holds the key", hasKey(c.inst.bobPhone, c.space.club))],
    },
    {
      title: "Bob's PDS resets his account in secret",
      narration: "Members must see the reset for its device to ever get a key, so it is published; Alice's app holds the new device. Bob's phone is served the old commit. With witnessing, it reads its own account's published history instead, and sees its own record deleted.",
      run: (w, c) => {
        c.inst.impostor = w.hiddenReset(c.did.bob);
        c.inst.impostor.join(c.space.club);
        w.settle();
      },
      expect: (w, c) => [
        check("Alice holds the PDS's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        w.policy === "witness"
          ? check("Bob's phone alarms while the hold runs", anyAlarm(c.inst.bobPhone, "own-removed") && alarmsAbout(c.inst.bobPhone, c.inst.impostor).length > 0)
          : check("Bob's phone sees nothing", c.inst.bobPhone.trust.state.alarms.length === 0),
      ],
    },
    {
      title: `${REENROLL_HOLD} hours later`,
      narration: "Nobody acted on the alarm here, so the hold completes and Alice's app shares; the alarm came in time for Bob to warn Alice and remove the device. Without witnessing, Bob's phone finds out only from Alice's grant, after disclosure.",
      run: (w) => w.advance(REENROLL_HOLD),
      expect: (w, c) => {
        const acc = acceptedAt(w, c.inst.alicePhone, c.inst.impostor);
        const a = alarmsAbout(c.inst.bobPhone, c.inst.impostor)[0];
        return [
          check("Alice accepted the PDS's device", !!acc),
          w.policy === "witness"
            ? check("Bob's phone alarmed before Alice accepted", !!a && !!acc && (a.world ?? Infinity) <= acc.world)
            : check("Bob's phone alarmed only after disclosure, about Alice's grant", !a && anyAlarm(c.inst.bobPhone, "unapproved-grant")),
        ];
      },
    },
  ],
});

/** Row 7: an impostor added and deleted while Bob was offline, then restored from backup. */
const restored = (policy: Policy): Scenario => ({
  id: idOf("witness-restore", policy),
  policy,
  title: `32. Witness: an impostor while Bob's phone was lost, then a restore${suffix(policy)}`,
  summary: "Bob backs up his phone and then loses it. While he has no running device, his PDS briefly publishes an impostor that Carol accepts. Days later Bob restores the backup onto a new phone: with witnessing it resumes from the backup's cursor, replays, and alarms.",
  steps: [
    setup(),
    {
      title: "Bob backs up his phone; a day later he loses it",
      narration: "The backup carries his own account's audit cursor along with his trust state.",
      run: (w, c) => {
        w.backup(c.inst.bobPhone);
        w.advance(24);
        w.setOnline(c.inst.bobPhone, false);
      },
    },
    {
      title: "His PDS publishes an impostor",
      narration: "No installation of Bob's is running.",
      run: (w, c) => {
        const f = w.flashImpostor(c.did.bob);
        c.inst.impostor = f.sub;
        undo.set(w, f.undo);
      },
    },
    carolInvites(),
    {
      title: "The PDS deletes the impostor",
      narration: "Bob's repo looks as it did when he backed up.",
      run: (w) => undo.get(w)!(),
    },
    {
      title: "Five days pass",
      narration: "",
      run: (w) => w.advance(120),
    },
    {
      title: "Bob restores the backup onto a new phone",
      narration: "Restore resumes from the cursor in the backup, not from the moment of restoring. Without witnessing, the restored phone reads the latest commit and sees nothing.",
      run: (w, c) => {
        c.inst.bobRestored = w.restore(c.inst.bobPhone, 0);
      },
      expect: (w, c) => w.policy === "witness"
        ? [
          check("The restored phone alarms about the impostor", alarmsAbout(c.inst.bobRestored, c.inst.impostor).length > 0),
          check("No retention gap: the backup is within 90 days", c.inst.bobRestored.gapWarnings().length === 0),
          check("The detection goal holds for Bob", missed(w, c.did.bob).length === 0),
        ]
        : [
          check("The restored phone sees nothing", alarmsAbout(c.inst.bobRestored, c.inst.impostor).length === 0),
          check("The detection goal check reports the miss", missed(w, c.did.bob).length > 0),
        ],
    },
  ],
});

/** Liveness: the 24-hour deadline holds when the witness stops answering
 * (Astra's case: an impostor accepted at hour 0, a check at hour 0.5 whose
 * history ends at hour -0.5). */
const liveness: Scenario = {
  id: "witness-liveness",
  policy: "witness",
  title: "33. Witness: liveness, warned within 24 hours",
  summary: "Bob's witness runs an hour behind the relay. Carol accepts a forked impostor at hour 0; Bob's phone completes a check at hour 0.5 whose history ends at hour -0.5, and then its witness becomes unreachable. Coverage age runs from the frontier, not from when the check completed, so Bob's phone warns before hour 24, and the warning can't be dismissed.",
  steps: [
    setup(),
    {
      title: "Bob's witness falls an hour behind",
      narration: "It processes only events the relay delivered at least an hour ago, so it reports a frontier age of an hour. Two hours on, Bob's coverage age is an hour. Call this moment hour 0.",
      run: (w) => {
        w.setWitness("lantern", { lag: 1 });
        w.advance(2);
      },
      expect: (_w, c) => [check("Bob's coverage age is an hour", Math.abs(c.inst.bobPhone.coverageAge() - 1) < 0.01)],
    },
    {
      title: "Hour 0: Carol accepts a forked impostor",
      narration: "Bob's PDS forks his repo to the relay and Carol; Carol's witness is current, so her app accepts the impostor and grants. Bob's witness has not reached the fork yet.",
      run: (w, c) => {
        c.inst.impostor = w.forkedImpostor(c.did.bob, [c.inst.carolPhone]);
      },
    },
    carolInvites(),
    {
      title: "Hour 0.5: a check completes; then Bob's witness becomes unreachable",
      narration: "The check processed history only to hour -0.5, so Bob's coverage age is an hour, not zero. From here Bob's phone can check nothing.",
      run: (w) => {
        w.advance(0.5);
        w.setWitness("lantern", { reachable: false });
      },
      expect: (_w, c) => [
        check("Bob's coverage age is an hour", Math.abs(c.inst.bobPhone.coverageAge() - 1) < 0.01, String(c.inst.bobPhone.coverageAge())),
        check("Bob's phone has not seen the impostor", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length === 0),
      ],
    },
    {
      title: "Hour 23",
      narration: "Coverage age is 23.5 hours: no warning yet.",
      run: (w) => w.advance(22.5),
      expect: (_w, c) => [check("No liveness warning yet", c.inst.bobPhone.liveness() === null)],
    },
    {
      title: "Hour 23.6",
      narration: "Coverage age passes 24 hours before the 24-hour deadline from Carol's acceptance, so the warning shows, naming the cause. Acknowledging a gap would not touch it; it clears only when coverage returns.",
      run: (w) => w.advance(0.6),
      expect: (_w, c) => [
        check("Bob's phone shows the liveness warning", c.inst.bobPhone.liveness() !== null, c.inst.bobPhone.liveness() ?? undefined),
        check("…naming an unreachable witness", /unreachable/.test(c.inst.bobPhone.liveness() ?? "")),
      ],
    },
    {
      title: "Hour 25",
      narration: "The deadline has passed; the goal check confirms Bob's phone warned in time.",
      run: (w) => w.advance(1.4),
      expect: (w, c) => [check("The detection goal holds for Bob", missed(w, c.did.bob).length === 0)],
    },
    {
      title: "The witness comes back",
      narration: "Bob's phone catches up, processes the fork, and alarms; the liveness warning clears.",
      run: (w) => w.setWitness("lantern", { reachable: true, lag: 0 }),
      expect: (_w, c) => [
        check("The liveness warning cleared", c.inst.bobPhone.liveness() === null),
        check("Bob's phone alarms about the impostor", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length > 0),
      ],
    },
  ],
};

/** Out of reach: a dishonest witness colluding with the PDS. */
const colluding: Scenario = {
  id: "witness-out-of-reach",
  policy: "witness",
  title: "34. Witness: out of reach, a colluding witness",
  summary: "Bob's phone is offline while his PDS briefly publishes an impostor that Carol accepts. Bob's app's witness colludes and leaves those commits out of the history it reports, with no gap. Bob's phone comes back and sees nothing: a dishonest witness misleads its own clients, as dishonest application code could.",
  steps: [
    setup(),
    {
      title: "Bob's phone goes offline; his PDS publishes an impostor; Carol grants it",
      narration: "The same attack as the brief-device scenario.",
      run: (w, c) => {
        mark.set(w, w.relay!.headSeq());
        w.setOnline(c.inst.bobPhone, false);
        const f = w.flashImpostor(c.did.bob);
        c.inst.impostor = f.sub;
        undo.set(w, f.undo);
      },
    },
    carolInvites(),
    {
      title: "The PDS restores Bob's phone, and Bob's witness omits all of it",
      narration: "The witness reports neither the commits nor gaps for them. The detection goal assumes an honest witness, so the check does not apply to Bob here.",
      run: (w, c) => {
        undo.get(w)!();
        w.dishonestWitness("lantern", c.did.bob, mark.get(w)!);
        w.setOnline(c.inst.bobPhone, true);
      },
    },
    {
      title: "25 hours later",
      narration: "",
      run: (w) => w.advance(25),
      expect: (_w, c) => [
        check("Bob's phone never alarms about the impostor", alarmsAbout(c.inst.bobPhone, c.inst.impostor).length === 0),
        check("…nor warns of a gap", c.inst.bobPhone.gapWarnings().length === 0),
        check("…and its coverage is current", c.inst.bobPhone.liveness() === null),
      ],
    },
  ],
};

/** A restore from a backup older than retention warns for the interval. */
const oldBackup: Scenario = {
  id: "witness-old-backup",
  policy: "witness",
  title: "35. Witness: a backup older than retention",
  summary: `Bob restores a backup made ${WITNESS_RETENTION / 24 + 11} days earlier. His account's history after the backup's cursor is older than WITNESS_RETENTION and gone from the witness, so the restored phone warns of a gap for that interval and keeps its liveness warning separate.`,
  steps: [
    setup(),
    {
      title: "Bob backs up his phone, links two devices, then loses the phone",
      narration: "The backup's cursor is the revision of Bob's repo it had processed. Each link is a later commit to his repo.",
      run: (w, c) => {
        w.backup(c.inst.bobPhone);
        c.inst.bobTablet = w.install(c.did.bob, "tablet", { link: c.inst.bobPhone });
        c.inst.bobLaptop = w.install(c.did.bob, "laptop", { link: c.inst.bobPhone });
        w.setOnline(c.inst.bobPhone, false);
      },
    },
    {
      title: `${WITNESS_RETENTION / 24 + 11} days later, Bob restores the backup`,
      narration: "The restored phone asks its witness for history from the backup's cursor; the commits after it are older than the witness retains (it keeps only the latest state as a starting point). It records that interval of revisions as a gap and raises a warning for it. Acknowledging it acknowledges only that gap.",
      run: (w, c) => {
        w.advance(WITNESS_RETENTION + 264);
        c.inst.bobRestored = w.restore(c.inst.bobPhone, 0);
      },
      expect: (_w, c) => [
        check("A gap warning for the interval older than retention", c.inst.bobRestored.gapWarnings().some((g) => /RETENTION/.test(g.reason))),
        check("Coverage is current again", c.inst.bobRestored.liveness() === null),
      ],
    },
    {
      title: "Bob acknowledges the gap",
      narration: "Acknowledging one gap clears only its warning.",
      run: (_w, c) => {
        for (const g of c.inst.bobRestored.gapWarnings()) c.inst.bobRestored.acknowledgeGap(g.key);
      },
      expect: (_w, c) => [check("No unacknowledged gaps", c.inst.bobRestored.gapWarnings().length === 0), check("The gap is still on record", c.inst.bobRestored.mon.gaps.length === 1)],
    },
  ],
};

/** PDS-served commits the relay never published, and a PDS clock briefly
 * wrong (Decisions on witnessed state; Reference relay). */
const servedId = new WeakMap<World, number>();
const unrelayed: Scenario = {
  id: "witness-unrelayed",
  policy: "witness",
  title: "36. Witness: unrelayed commits, a dropped commit, and a revision from the future",
  summary: "Carol pins Bob's account. The relay drops one of Bob's commits under a rate limit, and his PDS serves it to Carol: it lies in a gap, so nothing alarms. Bob's PDS then signs an impostor it never relays, followed by an honest commit, and serves Carol the impostor: it lies between two commits the relay published one after the other, so Carol's app raises an integrity alarm. Finally the PDS's clock runs a day fast for one commit, which a relay that doesn't check revisions publishes: a gap, no alarm, and Bob's later commits are witnessed as usual.",
  steps: [
    setup(),
    {
      title: "Carol creates Garden and invites Bob's phone",
      narration: "Carol's app pins Bob's account, so it follows his history through its witness and checks each commit Bob's PDS serves it against that history.",
      run: (w, c) => {
        c.space.garden = c.inst.carolPhone.createSpace("Garden");
        c.inst.carolPhone.invite(c.space.garden, c.did.bob);
        c.inst.bobPhone.join(c.space.garden);
        w.settle();
      },
      expect: (_w, c) => [check("Carol accepted Bob's phone", c.inst.carolPhone.trust.isAccepted(c.inst.bobPhone.binding))],
    },
    {
      title: "The relay drops the commit that links Bob's tablet",
      narration: "An honest relay may drop commits under a rate limit. Bob's next commit, linking his laptop, names a previous revision and root that no witness holds, so each witness records a gap reaching back past the dropped commit. A later commit is reconstructed again by fetching the repo.",
      run: (w, c) => {
        w.advance(1);
        w.relayDrops(c.did.bob);
        c.inst.bobTablet = w.install(c.did.bob, "tablet", { link: c.inst.bobPhone });
        w.advance(1);
        c.inst.bobLaptop = w.install(c.did.bob, "laptop", { link: c.inst.bobPhone });
        w.advance(1);
        c.inst.bobDesktop = w.install(c.did.bob, "desktop", { link: c.inst.bobPhone });
      },
      expect: (_w, c) => [
        check("Bob's phone warns of a gap", c.inst.bobPhone.gapWarnings().length === 1),
        check("Carol's app records an audit gap for Bob's account", c.inst.carolPhone.mon.auditGaps.length === 1),
        check("Carol's app accepts the tablet once a later commit is witnessed", c.inst.carolPhone.trust.isAccepted(c.inst.bobTablet.binding)),
      ],
    },
    {
      title: "Bob's PDS serves Carol the dropped commit",
      narration: "Its revision lies inside the gap Carol's witness recorded: part of what the witness already reports it could not check. No alarm.",
      run: (w, c) => {
        const published = new Set(w.relay!.events.map((e) => `${e.did}:${e.commit.rev}`));
        const dropped = w.pdsOf.get(c.did.bob)!.repo(c.did.bob).history.find((s) => !published.has(`${c.did.bob}:${s.commit.rev}`))!;
        servedId.set(w, w.serveAt(c.did.bob, dropped.commit.rev, [c.inst.carolPhone]));
      },
      expect: (_w, c) => [check("Carol's app raises no alarm", !anyAlarm(c.inst.carolPhone, "unrelayed-commit"))],
    },
    {
      title: "Bob's PDS signs an impostor it never relays, then an honest commit",
      narration: "The PDS replaces Bob's devices with its own in a commit it never sends the relay, then restores them in the next commit, which it does relay. Served the impostor commit, Carol's app first finds it above anything the witness reports: INCOMPLETE. Once the honest commit is witnessed, the impostor's revision lies strictly between two commits Carol's witness reconstructed one after the other, with no gap between, so the relay published nothing there: an integrity alarm, with the PDS's signed commit as proof.",
      run: (w, c) => {
        w.adversary.remove(servedId.get(w)!);
        const repo = w.pdsOf.get(c.did.bob)!.repo(c.did.bob);
        const honest = new Map(repo.records);
        c.inst.impostor = w.unrelayedImpostor(c.did.bob, [c.inst.carolPhone]);
        const rev = repo.latest().commit.rev;
        repo.records = honest;
        w.advance(1);
        repo.commit();
        w.serveAt(c.did.bob, rev, [c.inst.carolPhone]);
      },
      expect: (_w, c) => [
        check("Carol's app raises an integrity alarm", anyAlarm(c.inst.carolPhone, "unrelayed-commit")),
        check("…and never accepts the impostor", !c.inst.carolPhone.trust.isAccepted(c.inst.impostor.binding)),
      ],
    },
    {
      title: "Bob's PDS clock runs a day fast for one commit",
      narration: "A relay that doesn't check revisions publishes a commit whose revision is a day ahead of the relay's time on its event. Each witness records it as a gap, without an alarm, since a PDS clock can simply be wrong, and doesn't raise the account's latest revision to it, so Bob's later commits, at honest revisions, are not mistaken for revisions going backward.",
      run: (w, c) => {
        w.futureCommit(c.did.bob, 24);
        w.advance(1);
        c.inst.bobWatch = w.install(c.did.bob, "watch", { link: c.inst.bobPhone });
      },
      expect: (_w, c) => [
        check("No relay-integrity alarm anywhere", ![c.inst.bobPhone, c.inst.carolPhone].some((i) => anyAlarm(i, "relay-integrity"))),
        check("Bob's phone warns of a gap for the commit", c.inst.bobPhone.gapWarnings().some((g) => /REV_ALLOWANCE/.test(g.reason))),
        check("Carol's app accepts Bob's watch", c.inst.carolPhone.trust.isAccepted(c.inst.bobWatch.binding)),
      ],
    },
  ],
};

export const witnessScenarios: Scenario[] = [
  ...variants((p) => forked(p, 27, false)),
  ...variants((p) => forked(p, 28, true)),
  ...variants(flash),
  ...variants(syncRoot),
  ...variants(hiddenReset),
  ...variants(restored),
  liveness,
  colluding,
  oldBackup,
  unrelayed,
];
