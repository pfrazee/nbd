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

export const scenarios: Scenario[] = [s1, s2, s3, s4, s5];
