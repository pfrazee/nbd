// Scenarios 1-5 from the prototype plan. Each step narrates what a reviewer
// should notice and checks it.

import type { Installation } from "../../protocol/installation";
import { bindingId } from "../../protocol/types";
import type { World } from "../../world/world";
import { type Ctx, type Scenario, type Step, check } from "../scenario";

const hasKey = (i: Installation, space: string) => !!i.spaces.get(space)?.key;
const texts = (i: Installation, space: string) => i.messages(space).flatMap((m) => ("text" in m ? [m.text] : []));
const notices = (i: Installation, kind: string) => i.trust.state.notices.filter((n) => n.kind === kind);
const alarms = (i: Installation, kind: string) => i.trust.state.alarms.filter((a) => a.kind === kind);

/** Alice creates Book club, posts, and admits Bob, who joins on his phone. */
function bookClub(extra: { carol?: boolean } = {}): Step[] {
  return [
    {
      title: "Alice and Bob install the app",
      narration: "Each first installation publishes its device record. Nobody verifies anything: first contact is trusted.",
      run: (w: World, c: Ctx) => {
        c.did.alice = w.account("alice");
        c.did.bob = w.account("bob", "pds.bob.example");
        c.inst.alicePhone = w.install(c.did.alice, "phone");
        c.inst.bobPhone = w.install(c.did.bob, "phone");
        if (extra.carol) {
          c.did.carol = w.account("carol");
          c.inst.carolPhone = w.install(c.did.carol, "phone");
        }
      },
    },
    {
      title: "Alice creates Book club and posts",
      narration: "The space key is generated on Alice's phone before creation; its commitment is fixed in the configuration. Until another device holds the key, Alice sees the sole-holder note.",
      run: (w, c) => {
        c.space.club = c.inst.alicePhone.createSpace("Book club");
        c.inst.alicePhone.post(c.space.club, "Welcome! First book is Middlemarch.");
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice holds the key", hasKey(c.inst.alicePhone, c.space.club)),
        check("Alice is the sole holder", !c.inst.alicePhone.spaces.get(c.space.club)!.sawOtherHolder),
      ],
    },
    {
      title: "Alice admits Bob, who joins",
      narration: "Bob's phone publishes a key request. Alice's phone pins Bob's device on first sight and grants; Bob pins Alice's device and accepts. One grant unlocks the history posted before he joined.",
      run: (w, c) => {
        c.inst.alicePhone.invite(c.space.club, c.did.bob);
        if (extra.carol) c.inst.alicePhone.invite(c.space.club, c.did.carol);
        c.inst.bobPhone.join(c.space.club);
        if (extra.carol) c.inst.carolPhone.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Bob holds the key", hasKey(c.inst.bobPhone, c.space.club)),
        check("Bob reads history from before he joined", texts(c.inst.bobPhone, c.space.club).includes("Welcome! First book is Middlemarch.")),
        check("Alice pinned Bob's phone on first use", c.inst.alicePhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("Alice is no longer the sole holder", c.inst.alicePhone.spaces.get(c.space.club)!.sawOtherHolder),
      ],
    },
  ];
}

const s1: Scenario = {
  id: "join",
  title: "1. Create, invite, join",
  summary: "First contact, a key request, one grant, and history from before joining.",
  steps: [
    ...bookClub(),
    {
      title: "Bob replies",
      narration: "Content is encrypted on Bob's phone under the space key; servers only store ciphertext.",
      run: (w, c) => {
        c.inst.bobPhone.post(c.space.club, "Count me in.");
        w.settle();
      },
      expect: (_w, c) => [check("Alice reads Bob's reply", texts(c.inst.alicePhone, c.space.club).includes("Count me in."))],
    },
  ],
};

const s2: Scenario = {
  id: "swap-seen",
  title: "2. Phone swap, seen before removal",
  summary: "Bob links a new phone from the old one and removes the old one later; Alice sees the link first, so there is no hold.",
  steps: [
    ...bookClub(),
    {
      title: "Bob links his new phone from the old one",
      narration: "The old phone signs an approval and publishes it with the new device's record in one commit. Alice's app accepts the new phone through that approval: no notice for other members.",
      run: (w, c) => {
        c.inst.bobNew = w.install(c.did.bob, "new-phone", { link: c.inst.bobPhone });
        c.inst.bobNew.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice accepts Bob's new phone", c.inst.alicePhone.trust.isAccepted(c.inst.bobNew.binding)),
        check("Bob's new phone holds the key", hasKey(c.inst.bobNew, c.space.club)),
      ],
    },
    {
      title: "Days later, Bob removes the old phone",
      narration: "He signs it out at his provider, then deletes its record. Alice had already accepted the new phone, so nothing changes for her.",
      run: (w, c) => {
        w.advance(48);
        w.removeDevice(c.inst.bobPhone);
      },
      expect: (_w, c) => [
        check("Alice still accepts the new phone", c.inst.alicePhone.trust.isAccepted(c.inst.bobNew.binding)),
        check("Alice has no hold for Bob", !c.inst.alicePhone.trust.hold(c.did.bob)),
        check("Alice saw no reset notice", notices(c.inst.alicePhone, "reset").length === 0),
        check("Bob's new phone noted the removal", notices(c.inst.bobNew, "own-removed").length === 1),
      ],
    },
  ],
};

const s3: Scenario = {
  id: "swap-missed",
  title: "3. Phone swap missed by an offline contact",
  summary: "Alice is offline while Bob links a new phone and removes the old one at once. Her app sees a reset and holds; Carol, who saw the link, shares normally.",
  steps: [
    ...bookClub({ carol: true }),
    {
      title: "Alice's phone goes offline",
      narration: "Her app stops syncing; it will only see Bob's repo as it is when she comes back.",
      run: (w, c) => w.setOnline(c.inst.alicePhone, false),
    },
    {
      title: "Bob links a new phone and immediately removes the old one",
      narration: "This is what the linking flow must not prompt. Carol's app sees the approval while the old phone is still present and accepts the new one.",
      run: (w, c) => {
        c.inst.bobNew = w.install(c.did.bob, "new-phone", { link: c.inst.bobPhone });
        c.inst.bobNew.join(c.space.club);
        w.settle();
        w.removeDevice(c.inst.bobPhone);
      },
      expect: (_w, c) => [
        check("Carol accepts Bob's new phone", c.inst.carolPhone.trust.isAccepted(c.inst.bobNew.binding)),
        check("Bob's new phone holds the key anyway", hasKey(c.inst.bobNew, c.space.club)),
      ],
    },
    {
      title: "Alice comes back online",
      narration: "Every Bob device she accepted is gone, and an approval signed by a removed device can't tell her when it was signed. Her app treats the new phone as a reset and holds it for 72 hours.",
      run: (w, c) => w.setOnline(c.inst.alicePhone, true),
      expect: (_w, c) => [
        check("Alice holds Bob's new phone", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        check("Alice sees a reset notice", notices(c.inst.alicePhone, "reset").length === 1),
        check("Alice does not accept it yet", !c.inst.alicePhone.trust.isAccepted(c.inst.bobNew.binding)),
      ],
    },
    {
      title: "72 hours later",
      narration: "Alice's own clock credits the hold; her app accepts the new phone.",
      run: (w) => w.advance(72),
      expect: (_w, c) => [check("Alice accepts Bob's new phone", c.inst.alicePhone.trust.isAccepted(c.inst.bobNew.binding))],
    },
  ],
};

const s4: Scenario = {
  id: "takeover",
  title: "4. Account takeover at an honest PDS",
  summary: "Someone phishes Bob's password, deletes his phone, and enrolls their own device. Alice's app holds it; Bob's phone alarms and he removes the attacker.",
  steps: [
    ...bookClub(),
    {
      title: "An attacker takes over Bob's account",
      narration: "With the password they can delete every device record and publish their own. They request Book club's key.",
      run: (w, c) => {
        c.inst.attacker = w.takeover(c.did.bob);
        c.inst.attacker.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice holds the attacker's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        check("Alice sees a reset notice", notices(c.inst.alicePhone, "reset").length === 1),
        check("The attacker has no key", !hasKey(c.inst.attacker, c.space.club)),
        check("Bob's phone alarms", alarms(c.inst.bobPhone, "own-removed").length === 1),
      ],
    },
    {
      title: "A day later, Bob removes the attacker's device",
      narration: "Prompted by the alarm, Bob signs in at his provider and deletes the device. Deleting the candidate cancels the hold.",
      run: (w, c) => {
        w.advance(24);
        w.removeDevice(c.inst.attacker);
      },
      expect: (_w, c) => [
        check("Alice's hold is cancelled", !c.inst.alicePhone.trust.hold(c.did.bob)),
        check("The attacker never got the key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
  ],
};

const s5: Scenario = {
  id: "old-key",
  title: "5. A removed device's key during a hold",
  summary: "The attacker also holds Bob's old laptop key. An approval signed with it no longer ends the hold.",
  steps: [
    ...bookClub(),
    {
      title: "Bob links a laptop, then retires it without wiping",
      narration: "He removes the laptop properly, but its keys survive on the disk he sold.",
      run: (w, c) => {
        c.inst.bobLaptop = w.install(c.did.bob, "laptop", { link: c.inst.bobPhone });
        w.advance(24);
        c.stolen.laptop = w.stealKeys(c.inst.bobLaptop);
        w.removeDevice(c.inst.bobLaptop);
      },
      expect: (_w, c) => [
        check("Alice had accepted the laptop", c.inst.alicePhone.trust.state.accepted.has(bindingId(c.inst.bobLaptop.binding))),
        check("Alice revoked it on removal", c.inst.alicePhone.trust.state.revoked.has(bindingId(c.inst.bobLaptop.binding))),
      ],
    },
    {
      title: "The attacker takes over and signs with the old laptop key",
      narration: "They delete Bob's phone, enroll their device, and publish an approval for it signed by the removed laptop. Before the fix, this ended the hold at once.",
      run: (w, c) => {
        c.inst.attacker = w.takeover(c.did.bob);
        c.inst.attacker.join(c.space.club);
        w.approveWith(c.stolen.laptop, c.inst.attacker, c.inst.attacker.sessionId!);
      },
      expect: (_w, c) => [
        check("Alice still holds the attacker's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        check("Alice does not accept it", !c.inst.alicePhone.trust.isAccepted(c.inst.attacker.binding)),
        check("The attacker has no key", !hasKey(c.inst.attacker, c.space.club)),
      ],
    },
    {
      title: "71 hours later",
      narration: "Still held. Bob's phone has been alarming since the takeover; this is his window.",
      run: (w) => w.advance(71),
      expect: (_w, c) => [check("Still held", !c.inst.alicePhone.trust.isAccepted(c.inst.attacker.binding))],
    },
  ],
};

const s6: Scenario = {
  id: "substitution",
  title: "6. First-contact substitution by a malicious PDS",
  summary: "Bob's PDS shows Carol, who has never met Bob, a device it controls instead of his. Carol shares the key with it; auditing reveals it only afterwards.",
  steps: [
    ...bookClub(),
    {
      title: "Carol is invited; Bob's PDS substitutes his devices for her",
      narration: "Carol's app meets Bob for the first time and trusts what his PDS shows: one device, the PDS's own. Alice already knew Bob and sees his real repo.",
      run: (w, c) => {
        c.did.carol = w.account("carol");
        c.inst.carolPhone = w.install(c.did.carol, "phone");
        c.inst.sub = w.substituteDevices(c.did.bob, c.inst.carolPhone);
        c.inst.alicePhone.invite(c.space.club, c.did.carol);
        c.inst.carolPhone.join(c.space.club);
        c.inst.sub.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Carol accepted the substitute as Bob", c.inst.carolPhone.trust.isAccepted(c.inst.sub.binding)),
        check("Carol never saw Bob's real phone", !c.inst.carolPhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("The substitute got the key, from Carol", hasKey(c.inst.sub, c.space.club)),
        check("Alice did not accept the substitute", !c.inst.alicePhone.trust.isAccepted(c.inst.sub.binding)),
      ],
    },
    {
      title: "Detection, after the fact",
      narration: "Bob's phone audits grants in other members' repos and finds one to a Bob device it never approved. Alice's app compares the commit in Carol's grant evidence with the one it verified for the same revision, and they differ. Neither undoes the disclosure.",
      run: (w) => w.settle(),
      expect: (_w, c) => [
        check("Bob's phone alarms about an unrecognised device with access", alarms(c.inst.bobPhone, "unapproved-grant").length > 0),
        check("Alice's app raises a fork alarm", alarms(c.inst.alicePhone, "fork").length > 0),
      ],
    },
  ],
};

const s7: Scenario = {
  id: "hidden-reset",
  title: "7. A malicious PDS hides a reset from the account's own devices",
  summary: "Bob's PDS resets his account but keeps showing his phone the old state, so his phone never alarms. Alice waits out the hold, then shares; only Bob's audit of her grant reveals it.",
  steps: [
    ...bookClub(),
    {
      title: "Bob's PDS resets his account in secret",
      narration: "It deletes Bob's phone and enrolls its own device, but serves Bob's phone the old commit. Alice's app sees the reset and holds; Bob's phone sees nothing wrong.",
      run: (w, c) => {
        c.inst.sub = w.hiddenReset(c.did.bob);
        c.inst.sub.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice holds the PDS's device", !!c.inst.alicePhone.trust.hold(c.did.bob)),
        check("Bob's phone does not alarm", c.inst.bobPhone.trust.state.alarms.length === 0),
      ],
    },
    {
      title: "72 hours later",
      narration: "Nobody stopped the hold, because Bob never learned of the reset. Alice's app shares with the new device. Bob's phone then finds Alice's grant to a Bob device it never approved: detection, after disclosure.",
      run: (w) => w.advance(72),
      expect: (_w, c) => [
        check("Alice accepts the PDS's device", c.inst.alicePhone.trust.isAccepted(c.inst.sub.binding)),
        check("The PDS's device holds the key", hasKey(c.inst.sub, c.space.club)),
        check("Bob's phone alarms about the grant", alarms(c.inst.bobPhone, "unapproved-grant").length > 0),
        check("Bob's phone still never saw itself removed", alarms(c.inst.bobPhone, "own-removed").length === 0),
      ],
    },
  ],
};

const s8: Scenario = {
  id: "fork",
  title: "8. Divergent histories",
  summary: "Bob's PDS shows Alice a history where his phone was deleted, while Carol sees it present. The fork surfaces when a grant's evidence carries Carol's commit to Alice.",
  steps: [
    ...bookClub({ carol: true }),
    {
      title: "Bob's PDS forks his history for Alice",
      narration: "Alice's app sees Bob's phone removed and revokes it; Carol's app sees it present. Each history has increasing revisions, so neither app can tell on its own.",
      run: (w, c) => w.hideDeviceFrom(c.inst.bobPhone.binding, c.inst.alicePhone),
      expect: (_w, c) => [
        check("Alice revoked Bob's phone", !c.inst.alicePhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("Carol still accepts Bob's phone", c.inst.carolPhone.trust.isAccepted(c.inst.bobPhone.binding)),
        check("No fork alarm yet", alarms(c.inst.alicePhone, "fork").length === 0),
      ],
    },
    {
      title: "Bob links a tablet; Carol shares with it",
      narration: "Carol's grant evidence includes the commit of Bob's repo she relied on. Alice's app verified a different commit at that revision: a fork alarm.",
      run: (w, c) => {
        c.inst.bobTablet = w.install(c.did.bob, "tablet", { link: c.inst.bobPhone });
        c.inst.bobTablet.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Bob's tablet holds the key", hasKey(c.inst.bobTablet, c.space.club)),
        check("Alice's app raises a fork alarm", alarms(c.inst.alicePhone, "fork").length > 0),
      ],
    },
  ],
};

const s9: Scenario = {
  id: "recovery",
  title: "9. Total device loss, and a stale backup during the hold",
  summary: "Bob loses his only phone and starts over. Alice's app holds his new phone; her own phone breaks mid-hold and she restores an old backup, whose stored time is not credited.",
  steps: [
    ...bookClub(),
    {
      title: "Bob loses his phone and installs on a new one",
      narration: "Without a backup or a surviving device there is nothing to link from. Until Bob removes the lost phone, Alice's app sees an unlinked device and shares nothing with it.",
      run: (w, c) => {
        w.setOnline(c.inst.bobPhone, false);
        c.inst.bobNew = w.install(c.did.bob, "new-phone");
        c.inst.bobNew.join(c.space.club);
        w.settle();
      },
      expect: (_w, c) => [
        check("Alice does not accept the unlinked phone", !c.inst.alicePhone.trust.isAccepted(c.inst.bobNew.binding)),
        check("Alice has no hold yet", !c.inst.alicePhone.trust.hold(c.did.bob)),
      ],
    },
    {
      title: "Bob removes the lost phone at his provider",
      narration: "Every device Alice knew is gone, so the new phone becomes a re-enrollment candidate: Alice's app holds it for 72 hours.",
      run: (w, c) => w.removeDevice(c.inst.bobPhone),
      expect: (_w, c) => [check("Alice holds Bob's new phone", !!c.inst.alicePhone.trust.hold(c.did.bob))],
    },
    {
      title: "Alice backs up her phone an hour in, then it breaks at hour 60",
      narration: "She restores the backup onto a replacement. Backups carry credited time, not start times, and time in storage is not credited: the restored phone has about 1 hour of credit, not 60.",
      run: (w, c) => {
        w.advance(1);
        w.backup(c.inst.alicePhone);
        w.advance(59);
        c.inst.aliceRestored = w.restore(c.inst.alicePhone, w.backups.length - 1);
      },
      expect: (_w, c) => [
        check("The restored phone still holds", !!c.inst.aliceRestored.trust.hold(c.did.bob)),
        check("About 71 hours remain on it", Math.abs((c.inst.aliceRestored.holdRemaining(c.did.bob) ?? 0) - 71) < 0.5),
      ],
    },
    {
      title: "Hour 72: the original phone would have shared by now",
      narration: "The restored phone keeps its own count. Bob still has no key from Alice.",
      run: (w) => w.advance(12),
      expect: (_w, c) => [
        check("Still held on the restored phone", !c.inst.aliceRestored.trust.isAccepted(c.inst.bobNew.binding)),
        check("Bob's new phone has no key", !hasKey(c.inst.bobNew, c.space.club)),
      ],
    },
    {
      title: "Hold complete on the restored phone",
      narration: "Alice's app shares with Bob's new phone, which reads the history again. Messages only the lost phone held would be gone.",
      run: (w) => w.advance(60),
      expect: (_w, c) => [
        check("Alice's restored phone accepts Bob's new phone", c.inst.aliceRestored.trust.isAccepted(c.inst.bobNew.binding)),
        check("Bob's new phone reads the history", texts(c.inst.bobNew, c.space.club).includes("Welcome! First book is Middlemarch.")),
      ],
    },
  ],
};

const s10: Scenario = {
  id: "removed-member",
  title: "10. A removed member keeps the key",
  summary: "Alice removes Carol. New grants stop and Carol's access ends with her credential, but she keeps the key and everything she already read.",
  steps: [
    ...bookClub({ carol: true }),
    {
      title: "Alice removes Carol and posts right away",
      narration: "Removal is not immediate: Carol's current credential still works for a few minutes, so she can read a message posted just after.",
      run: (w, c) => {
        c.inst.alicePhone.removeMember(c.space.club, c.did.carol);
        c.inst.alicePhone.post(c.space.club, "Planning Carol's surprise party.");
        w.settle();
      },
      expect: (_w, c) => [
        check("Bob sees that Carol was removed", notices(c.inst.bobPhone, "membership").some((n) => n.text.includes("removed"))),
        check("Carol still holds the key", hasKey(c.inst.carolPhone, c.space.club)),
        check("Carol can still read it, for now", texts(c.inst.carolPhone, c.space.club).includes("Planning Carol's surprise party.")),
      ],
    },
    {
      title: "An hour later",
      narration: "Carol's credential has expired and the host won't issue another, so she can't fetch new ciphertext. She keeps the key; nothing was rotated.",
      run: (w, c) => {
        w.advance(1);
        c.inst.alicePhone.post(c.space.club, "Party is Saturday.");
        w.settle();
      },
      expect: (_w, c) => [
        check("Carol cannot fetch the new message", !texts(c.inst.carolPhone, c.space.club).includes("Party is Saturday.")),
        check("Carol still holds the key", hasKey(c.inst.carolPhone, c.space.club)),
        check("Bob reads it", texts(c.inst.bobPhone, c.space.club).includes("Party is Saturday.")),
      ],
    },
  ],
};

export const scenarios: Scenario[] = [s1, s2, s3, s4, s5, s6, s7, s8, s9, s10];
