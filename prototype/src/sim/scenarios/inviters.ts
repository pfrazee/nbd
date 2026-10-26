// Scenarios for the inviters proposal (proposal-inviters.md), run under the
// "inviters" policy: only the member who invited an account may grant to its
// devices on first contact, and only in the space they invited it to. Every
// other member holds first-contact devices for 72 hours of its own time.

import type { Installation } from "../../protocol/installation";
import { REENROLL_HOLD } from "../../protocol/trust";
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

const known: Scenario = {
  id: "inviters-known",
  policy: "inviters",
  title: "15. Inviters: inviting a known account changes nothing",
  summary: "An invite vouches only for devices the inviter meets for the first time in making it. Inviting an account the inviter already pins, even one it is still holding, and inviting it again, change no standing.",
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
      title: "Alice invites Bob to Book club again",
      narration: "A second invite is not a first contact either. Nothing changes.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        w.settle();
      },
      expect: (w, c) => [
        check("The re-invite vouched for nothing", lastInvite(w, c.inst.alicePhone)?.devices.length === 0),
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
        check("Alice vouched for the attacker's device", c.inst.alicePhone.trust.standingBasis(c.inst.attacker.binding, c.space.club) === "vouched"),
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

export const inviterScenarios: Scenario[] = [newcomer, crossSpace, known, linkedPhone, offline, residual];
