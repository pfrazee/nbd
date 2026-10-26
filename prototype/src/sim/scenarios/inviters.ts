// Scenarios for the inviters proposal (proposal-inviters.md), run under the
// "inviters" policy: only the member who invited an account may grant to its
// devices on first contact, and only in spaces they invited it to. Every
// other member holds first-contact devices for 72 hours of its own time.

import type { Installation } from "../../protocol/installation";
import { REENROLL_HOLD } from "../../protocol/trust";
import { COL } from "../../protocol/types";
import type { World } from "../../world/world";
import { type Ctx, type Scenario, type Step, check } from "../scenario";

const hasKey = (i: Installation, space: string) => !!i.spaces.get(space)?.key;
const keyFrom = (i: Installation, space: string) => i.spaces.get(space)?.keyFrom ?? "";
const standing = (i: Installation, of: Installation, space: string) => i.trust.standing(of.binding, space);
/** Hours left on `i`'s first-contact hold for `of`'s device. */
const left = (i: Installation, of: Installation) => i.trust.firstContactRemaining(of.binding) ?? NaN;
const near = (x: number, want: number) => Math.abs(x - want) < 0.5;
/** The latest invite record `by` published. */
const lastInvite = (w: World, by: Installation) => [...w.provenance.invites].reverse().find((v) => v.device === by.binding.device.deviceId);

function install(w: World, c: Ctx, ...names: string[]): void {
  for (const n of names) {
    c.did[n] = w.account(n, n === "bob" ? "pds.bob.example" : "pds.example");
    c.inst[`${n}Phone`] = w.install(c.did[n], "phone");
  }
}

/** Alice creates Book club and invites Bob, meeting him as she does. */
function bookClub(extra: string[] = []): Step[] {
  return [
    {
      title: "Alice and Bob install the app",
      narration: "Each first installation publishes its device record. This world follows the inviters rule: an app grants to a device on first contact only if it met that device while inviting its account to the space.",
      run: (w, c) => install(w, c, "alice", "bob", ...extra),
    },
    {
      title: "Alice creates Book club and invites Bob",
      narration: "Inviting Bob, Alice's app pins his phone on first use and publishes an invite record vouching for it in Book club. Her app grants to it as soon as Bob joins.",
      run: (w, c) => {
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        c.inst.alicePhone.post(c.space.club, "Welcome! First book is Middlemarch.");
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (w, c) => [
        check("Alice's invite vouched for Bob's phone", lastInvite(w, c.inst.alicePhone)?.devices.includes(c.inst.bobPhone.binding.device.deviceId) ?? false),
        check("Alice has standing for Bob's phone in Book club", standing(c.inst.alicePhone, c.inst.bobPhone, c.space.club)),
        check("Bob holds the key, from Alice", keyFrom(c.inst.bobPhone, c.space.club).startsWith("did:plc:alice")),
      ],
    },
  ];
}

const takeover: Step = {
  title: "An attacker takes over Bob's account",
  narration: "With Bob's password they delete his phone, enroll their own device, and request Book club's key. Alice knew Bob, so her app holds the new device for re-enrollment, as in the baseline.",
  run: (w, c) => {
    c.inst.attacker = w.takeover(c.did.bob);
    c.inst.attacker.join(c.space.club);
    w.settle();
  },
  expect: (_w, c) => [
    check("Alice holds the attacker's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
    check("The attacker has no key", !hasKey(c.inst.attacker, c.space.club)),
  ],
};

const newcomer: Scenario = {
  id: "inviters-newcomer",
  policy: "inviters",
  title: "13. Inviters: a newcomer after a takeover holds",
  summary: "Dave joins Book club after Bob's account was taken over and first meets the attacker's device. In the baseline his app would grant to it at once and undo Alice's hold; under the inviters rule it holds too.",
  steps: [
    ...bookClub(["dave"]),
    takeover,
    {
      title: "Alice invites Dave, who never met Bob",
      narration: "Alice vouches for Dave, so her app grants him the key. Dave's app pins every member on joining and meets the attacker's device as Bob's only device: an ordinary first contact. It accepts the device but has no grant standing for it, because Dave didn't invite Bob. Its first-contact hold runs 72 hours of Dave's own time.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.dave);
        c.inst.davePhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Dave holds the key, from Alice", keyFrom(c.inst.davePhone, c.space.club).startsWith("did:plc:alice")),
        check("Dave accepted the attacker's device on first use", c.inst.davePhone.trust.isAccepted(c.inst.attacker.binding)),
        check("Dave has no standing for it in Book club", !standing(c.inst.davePhone, c.inst.attacker, c.space.club)),
        check("Dave's app holds it for 72 hours", near(left(c.inst.davePhone, c.inst.attacker), REENROLL_HOLD)),
        check("The attacker has no key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
    {
      title: "A day later, Bob removes the attacker's device",
      narration: "Bob's phone alarmed when it was removed. He signs in at his provider and deletes the attacker's device. Every member's app revokes it; nobody granted.",
      run: (w, c) => {
        w.advance(24);
        w.removeDevice(c.inst.attacker);
      },
      expect: (_w, c) => [
        check("Dave revoked the attacker's device", !c.inst.davePhone.trust.isAccepted(c.inst.attacker.binding)),
        check("The attacker never got the key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
  ],
};

const crossSpace: Scenario = {
  id: "inviters-cross-space",
  policy: "inviters",
  title: "14. Inviters: a vouch covers only its own space",
  summary: "Dave, who never met Bob, invites the taken-over Bob into his own space and grants there at once: the remaining exposure. When Dave then joins Book club, where Bob was already a member, his app holds the same device there.",
  steps: [
    ...bookClub(["dave"]),
    takeover,
    {
      title: "Dave creates Garden and invites Bob",
      narration: "Dave's app meets Bob for the first time while inviting him, so the invite vouches for the attacker's device in Garden. The attacker gets Garden's key from Dave at once. Nothing distinguishes this from inviting an honest new contact, and the goal check accepts it as the inviter's first contact.",
      run: (w, c) => {
        c.space.garden = c.inst.davePhone.createSpace("Garden");
        c.inst.davePhone.invite(c.space.garden, c.did.bob);
        c.inst.attacker.join(c.space.garden);
        w.settle();
      },
      expect: (w, c) => [
        check("Dave's invite vouched for the attacker's device", lastInvite(w, c.inst.davePhone)?.devices.includes(c.inst.attacker.binding.device.deviceId) ?? false),
        check("The attacker holds Garden's key, from Dave", keyFrom(c.inst.attacker, c.space.garden).startsWith("did:plc:dave")),
      ],
    },
    {
      title: "Alice invites Dave to Book club",
      narration: "Dave's app already pins the attacker's device, but its vouch applies only in Garden. In Book club it has no standing, so Dave's app holds it there like any newcomer's would, and doesn't undo Alice's hold.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.dave);
        c.inst.davePhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Dave holds Book club's key", hasKey(c.inst.davePhone, c.space.club)),
        check("Dave has standing for the attacker's device in Garden", standing(c.inst.davePhone, c.inst.attacker, c.space.garden)),
        check("Dave has no standing for it in Book club", !standing(c.inst.davePhone, c.inst.attacker, c.space.club)),
        check("The attacker has no Book club key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
    {
      title: "71 hours after the takeover, Bob removes the attacker's device",
      narration: "Alice's re-enrollment hold and Dave's first-contact hold both still run, so Book club's key never reached the attacker. Garden's did, the moment Dave invited Bob.",
      run: (w, c) => {
        w.advance(71);
        w.removeDevice(c.inst.attacker);
      },
      expect: (_w, c) => [
        check("The attacker never got Book club's key", !hasKey(c.inst.attacker, c.space.club)),
        check("The attacker keeps Garden's key", hasKey(c.inst.attacker, c.space.garden)),
      ],
    },
  ],
};

let reinvited = false;
const known: Scenario = {
  id: "inviters-known",
  policy: "inviters",
  title: "15. Inviters: inviting a known account changes nothing",
  summary: "An invite vouches only for devices the inviter meets for the first time through an invite. Inviting an account the inviter already pins, even one it is still holding, vouches for nothing, and an account that is already a member can't be invited again.",
  steps: [
    ...bookClub(["carol"]),
    takeover,
    {
      title: "Alice creates Garden and invites Bob",
      narration: "Alice's app already pins Bob and is holding the attacker's device for re-enrollment. The invite record lists the Bob devices she currently accepts (none) and vouches for nothing. The attacker gets no Garden key.",
      run: (w, c) => {
        c.space.garden = c.inst.alicePhone.createSpace("Garden");
        c.inst.alicePhone.invite(c.space.garden, c.did.bob);
        c.inst.attacker.join(c.space.garden);
        w.settle();
      },
      expect: (w, c) => [
        check("The invite vouched for nothing", lastInvite(w, c.inst.alicePhone)?.devices.length === 0),
        check("Alice still holds the attacker's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        check("The attacker has no Garden key", !hasKey(c.inst.attacker, c.space.garden)),
      ],
    },
    {
      title: "Carol joins Book club, then invites Bob into her own space",
      narration: "Carol first meets the attacker's device on joining Book club and holds it there. When she then invites Bob into Pottery, her app already pins him: the invite is not her first contact, so she holds him in Pottery too.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.carol);
        c.inst.carolPhone.join(c.space.club);
        w.settle();
        c.space.pottery = c.inst.carolPhone.createSpace("Pottery");
        c.inst.carolPhone.invite(c.space.pottery, c.did.bob);
        c.inst.attacker.join(c.space.pottery);
        w.settle();
      },
      expect: (w, c) => [
        check("Carol accepted the attacker's device on joining Book club", c.inst.carolPhone.trust.isAccepted(c.inst.attacker.binding)),
        check("Carol's invite vouched for nothing", lastInvite(w, c.inst.carolPhone)?.devices.length === 0),
        check("Carol has no standing for it in Pottery", !standing(c.inst.carolPhone, c.inst.attacker, c.space.pottery)),
        check("The attacker has no Pottery key", !hasKey(c.inst.attacker, c.space.pottery)),
      ],
    },
    {
      title: "Alice tries to invite Bob to Book club again",
      narration: "An invite counts only if it admits the account, and Bob is already a member, so her app publishes nothing. A vouch can never be carried into a space whose members were already holding the account's devices.",
      run: (w, c) => {
        const before = w.provenance.invites.length;
        reinvited = c.inst.alicePhone.invite(c.space.club, c.did.bob) || w.provenance.invites.length !== before;
        w.settle();
      },
      expect: (_w, c) => [
        check("No invite record was made", !reinvited),
        check("The attacker has no Book club key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
    {
      title: "Two days later, Bob removes the attacker's device",
      narration: "No member's hold ended, so no space's key reached the attacker.",
      run: (w, c) => {
        w.advance(48);
        w.removeDevice(c.inst.attacker);
      },
      expect: (_w, c) => [
        check("The attacker never got a key", ![c.space.club, c.space.garden, c.space.pottery].some((s) => hasKey(c.inst.attacker, s))),
      ],
    },
  ],
};

const linkedPhone: Scenario = {
  id: "inviters-linked-phone",
  policy: "inviters",
  title: "16. Inviters: a phone linked during a hold",
  summary: "Carol's app is holding Bob's phone when he links a new one and removes the old. The new phone started its own first-contact hold when Carol's app accepted it, so it is not stranded when the old phone goes.",
  steps: [
    ...bookClub(["carol"]),
    {
      title: "Alice invites Carol",
      narration: "Carol's app meets Bob's phone on joining. Alice invited Bob, not Carol, so Carol's app holds his phone: it would not grant to it for 72 hours. Alice's app serves Bob in the meantime.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.carol);
        c.inst.carolPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Carol has no standing for Bob's phone", !standing(c.inst.carolPhone, c.inst.bobPhone, c.space.club)),
        check("Carol's app holds it for 72 hours", near(left(c.inst.carolPhone, c.inst.bobPhone), REENROLL_HOLD)),
      ],
    },
    {
      title: "A day later, Bob links a new phone",
      narration: "Carol's app accepts the new phone through the old phone's approval. It inherits the old phone's standing, which is none yet, and starts a hold of its own. Alice's vouch for the old phone passes to the new one, so the new phone gets the key at once.",
      run: (w, c) => {
        w.advance(24);
        c.inst.bobNew = w.install(c.did.bob, "new-phone", { link: c.inst.bobPhone });
        c.inst.bobNew.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Carol accepts the new phone", c.inst.carolPhone.trust.isAccepted(c.inst.bobNew.binding)),
        check("Alice has standing for it", standing(c.inst.alicePhone, c.inst.bobNew, c.space.club)),
        check("Carol does not, yet", !standing(c.inst.carolPhone, c.inst.bobNew, c.space.club)),
        check("Carol's app holds the new phone for 72 hours", near(left(c.inst.carolPhone, c.inst.bobNew), REENROLL_HOLD)),
        check("The new phone holds the key", hasKey(c.inst.bobNew, c.space.club)),
      ],
    },
    {
      title: "Bob removes the old phone right away",
      narration: "Carol's hold for the old phone stops at the 24 hours it earned. Had the new phone only inherited the old phone's standing, it would now never get any from Carol. Its own hold keeps running.",
      run: (w, c) => w.removeDevice(c.inst.bobPhone),
      expect: (_w, c) => [
        check("Carol revoked the old phone", !c.inst.carolPhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("The old phone's hold stopped at 24 hours", near(left(c.inst.carolPhone, c.inst.bobPhone), REENROLL_HOLD - 24)),
        check("The new phone's hold still runs", near(left(c.inst.carolPhone, c.inst.bobNew), REENROLL_HOLD)),
      ],
    },
    {
      title: "72 hours after the link",
      narration: "Carol's own clock completes the new phone's hold. Her app may now grant to it in every space.",
      run: (w) => w.advance(72),
      expect: (_w, c) => [
        check("Carol has standing for the new phone", standing(c.inst.carolPhone, c.inst.bobNew, c.space.club)),
        check("The old phone's hold is still frozen", near(left(c.inst.carolPhone, c.inst.bobPhone), REENROLL_HOLD - 24)),
      ],
    },
  ],
};

const offline: Scenario = {
  id: "inviters-offline",
  policy: "inviters",
  title: "17. Inviters: waiting on an offline inviter",
  summary: "Alice invites Bob and goes offline before he joins. Other members' apps hold Bob from when each first saw him, so nobody can promise when he gets the key.",
  steps: [
    {
      title: "Alice, Carol, and Dave share Book club",
      narration: "Alice invites Carol and Dave, vouching for both, and her app grants them the key. Then Dave's phone goes offline.",
      run: (w, c) => {
        install(w, c, "alice", "bob", "carol", "dave");
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        for (const n of ["carol", "dave"]) {
          c.inst.alicePhone.invite(c.space.club, c.did[n]);
          c.inst[`${n}Phone`].join(c.space.club);
        }
        w.settle();
        w.setOnline(c.inst.davePhone, false);
      },
      expect: (_w, c) => [check("Carol and Dave hold the key", hasKey(c.inst.carolPhone, c.space.club) && hasKey(c.inst.davePhone, c.space.club))],
    },
    {
      title: "Alice invites Bob, then her phone goes offline",
      narration: "Bob joins and asks for the key. Alice's app would grant at once, but it isn't running. Carol's app first saw Bob when he was admitted and holds his phone. Bob's app shows \"Waiting for Alice's device\" and no unlock time, because there is none it could know.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        w.setOnline(c.inst.alicePhone, false);
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Bob has no key", !hasKey(c.inst.bobPhone, c.space.club)),
        check("Carol accepted Bob's phone without standing", c.inst.carolPhone.trust.isAccepted(c.inst.bobPhone.binding) && !standing(c.inst.carolPhone, c.inst.bobPhone, c.space.club)),
        check("Carol's app holds it for 72 hours", near(left(c.inst.carolPhone, c.inst.bobPhone), REENROLL_HOLD)),
        check("Dave's app has not seen Bob", !c.inst.davePhone.trust.knew(c.did.bob)),
      ],
    },
    {
      title: "Two days later, Dave's phone comes back online",
      narration: "Dave's app meets Bob now and starts its own hold, which ends two days after Carol's. Each member's app can tell its own user when it will share; nobody can tell Bob.",
      run: (w, c) => {
        w.advance(48);
        w.setOnline(c.inst.davePhone, true);
      },
      expect: (_w, c) => [
        check("Bob still has no key", !hasKey(c.inst.bobPhone, c.space.club)),
        check("Dave's app holds Bob's phone for 72 hours", near(left(c.inst.davePhone, c.inst.bobPhone), REENROLL_HOLD)),
        check("Carol's has 24 hours left", near(left(c.inst.carolPhone, c.inst.bobPhone), 24)),
      ],
    },
    {
      title: "A day later, Carol's hold ends",
      narration: "Carol's app grants Bob the key. Dave's would have waited two more days.",
      run: (w) => w.advance(24),
      expect: (_w, c) => [
        check("Bob holds the key, from Carol", keyFrom(c.inst.bobPhone, c.space.club).startsWith("did:plc:carol")),
        check("Dave still has no standing for Bob's phone", !standing(c.inst.davePhone, c.inst.bobPhone, c.space.club)),
      ],
    },
  ],
};

const residual: Scenario = {
  id: "inviters-residual",
  policy: "inviters",
  title: "18. Inviters: inviting someone you've never met during their takeover",
  summary: "Alice has never met Bob. The day after his account is taken over, she invites him to Book club, and her app grants to the attacker's device at once. This is the exposure the rule leaves, and the goal check accepts it as the inviter's first contact.",
  steps: [
    {
      title: "Bob's account is taken over before Alice ever meets him",
      narration: "Bob's phone alarms. Nobody in NBD has met Bob yet.",
      run: (w, c) => {
        install(w, c, "alice", "bob", "carol");
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        c.inst.attacker = w.takeover(c.did.bob);
        w.advance(24);
      },
      expect: (_w, c) => [check("Bob's phone alarms", c.inst.bobPhone.trust.state.alarms.some((a) => a.kind === "own-removed"))],
    },
    {
      title: "Alice invites Bob",
      narration: "Her app meets the attacker's device as Bob's only device and vouches for it in Book club. When it asks, her app grants at once. Only verification at the invite would have caught this.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        c.inst.attacker.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice vouched for the attacker's device", c.inst.alicePhone.trust.standingBasis(c.inst.attacker.binding, c.space.club) === "authorized"),
        check("The attacker holds the key, from Alice", keyFrom(c.inst.attacker, c.space.club).startsWith("did:plc:alice")),
      ],
    },
    {
      title: "Carol joins later",
      narration: "Carol's app meets the attacker's device on joining and holds it. The exposure happened once, at the invite, not once per newcomer.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.carol);
        c.inst.carolPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Carol holds the key", hasKey(c.inst.carolPhone, c.space.club)),
        check("Carol has no standing for the attacker's device", !standing(c.inst.carolPhone, c.inst.attacker, c.space.club)),
      ],
    },
  ],
};

const retry: Scenario = {
  id: "inviters-retry",
  policy: "inviters",
  title: "19. Inviters: an invite that fails to send",
  summary: "Alice's first attempt to publish her invite of Bob fails after her app has already met him. The invite was saved with its vouch decision and signed bytes, so the retry still vouches, and Alice grants at once when Bob joins.",
  steps: [
    {
      title: "Alice and Bob install the app; Alice creates Book club",
      narration: "Alice's app has never met Bob.",
      run: (w, c) => {
        install(w, c, "alice", "bob");
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        w.settle();
      },
    },
    {
      title: "Alice invites Bob while her PDS rejects writes",
      narration: "Her app meets Bob's phone, decides the invite vouches for it, and saves the signed record before uploading. The upload fails. Bob is not admitted yet, and Alice's app has no standing for him: both start only once the record is published.",
      run: (w, c) => {
        w.fault(c.inst.alicePhone, "reject", 1, COL.invite);
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
      },
      expect: (w, c) => [
        check("Alice's app pinned Bob's phone", c.inst.alicePhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("The saved invite vouches for it", c.inst.alicePhone.inviteOutbox[0]?.record.authorizes.length === 1),
        check("Bob is not admitted yet", !w.host.membership(c.space.club, c.did.bob)?.eligible),
        check("Alice has no standing for Bob yet", !standing(c.inst.alicePhone, c.inst.bobPhone, c.space.club)),
      ],
    },
    {
      title: "Alice's app resends the same invite, and Bob joins",
      narration: "On its next sync her app resends the exact bytes. It never re-derives the record: a fresh one would see that she already pins Bob and vouch for nothing. Bob is admitted, and Alice's app grants to him at once.",
      run: (w, c) => {
        w.settle();
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (w, c) => [
        check("The published invite vouched for Bob's phone", lastInvite(w, c.inst.alicePhone)?.devices.includes(c.inst.bobPhone.binding.device.deviceId) ?? false),
        check("Alice has standing for Bob's phone", standing(c.inst.alicePhone, c.inst.bobPhone, c.space.club)),
        check("Bob holds the key, from Alice", keyFrom(c.inst.bobPhone, c.space.club).startsWith("did:plc:alice")),
      ],
    },
  ],
};

/** Alice and Carol share Book club; Bob has an account but no app yet. */
const beforeInstall: Step = {
  title: "Alice invites Bob, who hasn't installed the app",
  narration: "Bob's account has no devices, and Alice's app has never met him, so the invite is pending: a record with no devices that admits Bob. Alice's app remembers it and starts counting its seven-day window.",
  run: (w, c) => {
    install(w, c, "alice", "carol");
    c.did.bob = w.account("bob", "pds.bob.example");
    c.space.club = c.inst.alicePhone.createSpace("Book club");
    c.inst.alicePhone.invite(c.space.club, c.did.carol);
    c.inst.carolPhone.join(c.space.club);
    w.settle();
    c.inst.alicePhone.invite(c.space.club, c.did.bob);
    w.settle();
  },
  expect: (w, c) => [
    check("Bob is admitted", !!w.host.membership(c.space.club, c.did.bob)?.eligible),
    check("Alice's invite is pending", lastInvite(w, c.inst.alicePhone)?.pending === true),
  ],
};

const bobInstalls = (title: string, narration: string): Step => ({
  title,
  narration,
  run: (w, c) => {
    c.inst.bobPhone = w.install(c.did.bob, "phone");
    c.inst.bobPhone.join(c.space.club);
    w.settle();
  },
});

const pending: Scenario = {
  id: "inviters-pending",
  policy: "inviters",
  title: "20. Inviters: inviting someone before they install",
  summary: "Alice invites Bob before he has the app. When his phone appears, Alice's app meets it for the first time, captures the pending invite, and grants at once, as if Bob had been installed when she invited him.",
  steps: [
    beforeInstall,
    {
      ...bobInstalls("The next day, Bob installs the app and joins",
        "Alice's app meets Bob's phone on first use while its pending invite is unexpired: it vouches for the phone and publishes a capture record naming it. Her app grants at once. Carol's app met Bob as a fellow member and holds."),
      run: (w, c) => {
        w.advance(24);
        bobInstalls("", "").run(w, c);
      },
      expect: (w, c) => [
        check("Alice's app captured the pending invite", lastInvite(w, c.inst.alicePhone)?.captures !== null),
        check("Alice has standing for Bob's phone", c.inst.alicePhone.trust.standingBasis(c.inst.bobPhone.binding, c.space.club) === "authorized"),
        check("Bob holds the key, from Alice", keyFrom(c.inst.bobPhone, c.space.club).startsWith("did:plc:alice")),
        check("Carol has no standing for Bob's phone", !standing(c.inst.carolPhone, c.inst.bobPhone, c.space.club)),
      ],
    },
  ],
};

const pendingExpiry: Scenario = {
  id: "inviters-pending-expiry",
  policy: "inviters",
  title: "21. Inviters: a pending invite expires",
  summary: "Bob installs the app eight days after Alice invited him. Her pending invite has expired, so his phone is an ordinary first contact, and every member's app holds it.",
  steps: [
    beforeInstall,
    {
      ...bobInstalls("Eight days later, Bob installs the app and joins",
        "The invite still admits Bob, but its window has passed: Alice's app captures nothing and holds Bob's phone like everyone else's."),
      run: (w, c) => {
        w.advance(8 * 24);
        bobInstalls("", "").run(w, c);
      },
      expect: (w, c) => [
        check("Nothing was captured", lastInvite(w, c.inst.alicePhone)?.captures === null),
        check("Alice has no standing for Bob's phone", !standing(c.inst.alicePhone, c.inst.bobPhone, c.space.club)),
        check("Bob has no key", !hasKey(c.inst.bobPhone, c.space.club)),
      ],
    },
    {
      title: "72 hours later",
      narration: "Alice's and Carol's first-contact holds for Bob's phone end, and Bob gets the key.",
      run: (w) => w.advance(72),
      expect: (_w, c) => [check("Bob holds the key", hasKey(c.inst.bobPhone, c.space.club))],
    },
  ],
};

const pendingTakeover: Scenario = {
  id: "inviters-pending-takeover",
  policy: "inviters",
  title: "22. Inviters: a takeover in the pending window",
  summary: "Between Alice's pending invite and Bob installing, someone with Bob's password enrolls the account's first device. Alice's app captures it and grants to it. This is the remaining exposure, widened to the pending window, and the goal check accepts it.",
  steps: [
    beforeInstall,
    {
      title: "An attacker enrolls Bob's first device",
      narration: "Alice's app meets the attacker's device first, while the pending invite is unexpired, and vouches for it. Nothing distinguishes it from Bob installing.",
      run: (w, c) => {
        w.advance(12);
        c.inst.attacker = w.takeover(c.did.bob);
        c.inst.attacker.join(c.space.club);
        w.settle();
      },
      expect: (w, c) => [
        check("Alice's app captured the pending invite with the attacker's device", lastInvite(w, c.inst.alicePhone)?.devices.includes(c.inst.attacker.binding.device.deviceId) ?? false),
        check("The attacker holds the key, from Alice", keyFrom(c.inst.attacker, c.space.club).startsWith("did:plc:alice")),
        check("Carol has no standing for it", !standing(c.inst.carolPhone, c.inst.attacker, c.space.club)),
      ],
    },
    {
      title: "Bob installs the app",
      narration: "His phone is a second, unlinked device on his account. Members' apps decline it, and his phone alarms about the device it doesn't recognise: detection, after disclosure.",
      run: (w, c) => {
        c.inst.bobPhone = w.install(c.did.bob, "phone");
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice does not accept Bob's phone", !c.inst.alicePhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("Bob's phone alarms", c.inst.bobPhone.trust.state.alarms.some((a) => a.kind === "unapproved-own")),
      ],
    },
  ],
};

const secondSpace: Scenario = {
  id: "inviters-second-space",
  policy: "inviters",
  title: "23. Inviters: a new space with someone you invited",
  summary: "Alice first met Bob by inviting him to Book club. When she starts Garden and invites him, her vouch follows: she grants at once.",
  steps: [
    ...bookClub(),
    {
      title: "Alice creates Garden and invites Bob",
      narration: "The invite meets nobody new and vouches for nothing. But Alice's app first met Bob's phone through her own invite, so it has standing in every space her account admits Bob to, Garden included.",
      run: (w, c) => {
        c.space.garden = c.inst.alicePhone.createSpace("Garden");
        c.inst.alicePhone.invite(c.space.garden, c.did.bob);
        c.inst.bobPhone.join(c.space.garden);
        w.settle();
      },
      expect: (w, c) => [
        check("The Garden invite vouched for nothing new", lastInvite(w, c.inst.alicePhone)?.devices.length === 0),
        check("It authorizes Bob's phone, which Alice already vouched for", lastInvite(w, c.inst.alicePhone)?.authorizes.includes(c.inst.bobPhone.binding.device.deviceId) ?? false),
        check("Alice has standing for Bob's phone in Garden", c.inst.alicePhone.trust.standingBasis(c.inst.bobPhone.binding, c.space.garden) === "authorized"),
        check("Bob holds Garden's key, from Alice", keyFrom(c.inst.bobPhone, c.space.garden).startsWith("did:plc:alice")),
      ],
    },
  ],
};

const fellowMember: Scenario = {
  id: "inviters-fellow-member",
  policy: "inviters",
  title: "24. Inviters: a new space with someone you met as a member",
  summary: "Alice met Carol as a fellow member of Dave's space, not through an invite. When Alice starts Garden with Carol, her app waits out the rest of its first-contact hold for Carol's phone.",
  steps: [
    {
      title: "Dave invites Alice and Carol to Pottery",
      narration: "Alice's and Carol's apps meet each other on joining and start first-contact holds for each other.",
      run: (w, c) => {
        install(w, c, "alice", "carol", "dave");
        c.space.pottery = c.inst.davePhone.createSpace("Pottery");
        for (const n of ["alice", "carol"]) {
          c.inst.davePhone.invite(c.space.pottery, c.did[n]);
          c.inst[`${n}Phone`].join(c.space.pottery);
        }
        w.settle();
      },
      expect: (_w, c) => [check("Alice's app holds Carol's phone for 72 hours", near(left(c.inst.alicePhone, c.inst.carolPhone), REENROLL_HOLD))],
    },
    {
      title: "A day later, Alice creates Garden and invites Carol",
      narration: "Alice's app already pins Carol, so the invite vouches for nothing, and her hold keeps running: \"Your device will share with Carol from Day 4.\"",
      run: (w, c) => {
        w.advance(24);
        c.space.garden = c.inst.alicePhone.createSpace("Garden");
        c.inst.alicePhone.invite(c.space.garden, c.did.carol);
        c.inst.carolPhone.join(c.space.garden);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice has no standing for Carol's phone in Garden", !standing(c.inst.alicePhone, c.inst.carolPhone, c.space.garden)),
        check("Carol has no Garden key", !hasKey(c.inst.carolPhone, c.space.garden)),
        check("48 hours remain", near(left(c.inst.alicePhone, c.inst.carolPhone), 48)),
      ],
    },
    {
      title: "Two days later",
      narration: "Alice's hold for Carol's phone ends, and her app grants.",
      run: (w) => w.advance(48),
      expect: (_w, c) => [check("Carol holds Garden's key, from Alice", keyFrom(c.inst.carolPhone, c.space.garden).startsWith("did:plc:alice"))],
    },
  ],
};

const lateVouch: Scenario = {
  id: "inviters-late-vouch",
  policy: "inviters",
  title: "25. Inviters: a later vouch doesn't reach back",
  summary: "Alice's phone knew Bob and invited him to Book club without vouching. After Bob's account is taken over, her laptop, which never met Bob, vouches for the attacker's device by inviting him to Garden. That vouch authorizes Garden only, not the phone's earlier Book club invite (Astra's third review).",
  steps: [
    {
      title: "Alice links a laptop; Carol's Pottery introduces Alice's phone to Bob",
      narration: "The laptop was linked before the phone met Bob, and never joins Pottery, so it has never met Bob.",
      run: (w, c) => {
        install(w, c, "alice", "bob", "carol");
        c.inst.aliceLaptop = w.install(c.did.alice, "laptop", { link: c.inst.alicePhone });
        c.space.pottery = c.inst.carolPhone.createSpace("Pottery");
        for (const n of ["alice", "bob"]) {
          c.inst.carolPhone.invite(c.space.pottery, c.did[n]);
          c.inst[`${n}Phone`].join(c.space.pottery);
        }
        w.settle();
      },
      expect: (_w, c) => [check("The laptop has never met Bob", !c.inst.aliceLaptop.trust.knew(c.did.bob))],
    },
    {
      title: "Alice's phone invites Bob to Book club",
      narration: "Her phone already pins Bob from Pottery, so the invite lists his phone and authorizes nothing.",
      run: (w, c) => {
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        c.inst.bobPhone.join(c.space.club);
        w.settle();
      },
      expect: (w, c) => [check("The invite authorizes nothing", lastInvite(w, c.inst.alicePhone)?.authorizes.length === 0)],
    },
    {
      ...takeover,
      narration: "The attacker resets Bob's account and asks for Book club's key. Alice's phone knew Bob, so it holds for re-enrollment.",
    },
    {
      title: "Alice's laptop invites Bob to Garden, then joins Book club",
      narration: "The laptop meets the attacker's device for the first time through its own invite, so its Garden invite authorizes that device, and the attacker gets Garden's key at once: the remaining exposure. The laptop then joins Book club and gets its key from the phone. Its vouch never reaches back to the phone's earlier Book club invite, which authorized nothing, so the laptop holds there.",
      run: (w, c) => {
        c.space.garden = c.inst.aliceLaptop.createSpace("Garden");
        c.inst.aliceLaptop.invite(c.space.garden, c.did.bob);
        c.inst.attacker.join(c.space.garden);
        w.settle();
        c.inst.aliceLaptop.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("The attacker holds Garden's key, from the laptop", keyFrom(c.inst.attacker, c.space.garden).startsWith("did:plc:alice")),
        check("The laptop holds Book club's key", hasKey(c.inst.aliceLaptop, c.space.club)),
        check("The laptop has no standing for the attacker's device in Book club", !standing(c.inst.aliceLaptop, c.inst.attacker, c.space.club)),
        check("The attacker has no Book club key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
  ],
};

const expiredThenVouch: Scenario = {
  id: "inviters-expired-then-vouch",
  policy: "inviters",
  title: "26. Inviters: an expired pending invite stays expired",
  summary: "Alice's pending invite of Bob to Book club expires. Later, the first device on Bob's account is an attacker's, and Alice first meets it by inviting Bob to Garden. That invite authorizes Garden only: the expired invite authorized nothing, and a later vouch never extends it.",
  steps: [
    beforeInstall,
    {
      title: "Eight days later, an attacker enrolls Bob's first device while Alice's phone is offline",
      narration: "The pending invite has expired. Carol's app meets the attacker's device as a fellow member and holds it.",
      run: (w, c) => {
        w.advance(8 * 24);
        w.setOnline(c.inst.alicePhone, false);
        c.inst.attacker = w.takeover(c.did.bob);
        c.inst.attacker.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [check("Carol has no standing for the attacker's device", !standing(c.inst.carolPhone, c.inst.attacker, c.space.club))],
    },
    {
      title: "Alice creates Garden and invites Bob, then her phone comes online",
      narration: "Alice's phone meets the attacker's device for the first time through the Garden invite, which authorizes it there. Her expired Book club invite captures nothing, and Garden's authorization doesn't reach it: her phone holds in Book club.",
      run: (w, c) => {
        c.space.garden = c.inst.alicePhone.createSpace("Garden");
        c.inst.alicePhone.invite(c.space.garden, c.did.bob);
        c.inst.attacker.join(c.space.garden);
        w.setOnline(c.inst.alicePhone, true);
      },
      expect: (_w, c) => [
        check("Alice has standing for the attacker's device in Garden", standing(c.inst.alicePhone, c.inst.attacker, c.space.garden)),
        check("Alice has none in Book club", !standing(c.inst.alicePhone, c.inst.attacker, c.space.club)),
        check("The attacker has no Book club key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
  ],
};

export const inviterScenarios: Scenario[] = [newcomer, crossSpace, known, linkedPhone, offline, residual, retry, pending, pendingExpiry, pendingTakeover, secondSpace, fellowMember, lateVouch, expiredThenVouch];
