// Figures for invites under grant standing (device-enrollment.md#grant-standing),
// in both presentations: inviting someone before they install, and a new
// space that waits for a first-contact hold.

import { check } from "../../sim/scenario";
import { PENDING_INVITE_TTL } from "../../protocol/trust";
import { COPY, type Mode, PARANOID } from "../copy";
import type { Figure } from "../figure";
import { Phone } from "../frames";
import { inviteStatus, memberList, shareDay, timeline, weekday } from "../model";
import { MemberList, NewSpaceForm, Sheet } from "../screens";
import { bobInstallsAndJoins, club, clubBeforeBobInstalls, gardenWithCarol, metInPottery } from "./cast";

export function invitingBeforeInstall(mode: Mode, number: number | string): Figure {
  const T = COPY[mode];
  const paranoid = mode === "paranoid";
  return {
    id: `${mode}-inviting-before-install`,
    mode,
    number,
    title: "Inviting someone who hasn't installed the app",
    description: "Alice invites Bob before he has Lantern. When his phone appears, Alice's app meets it for the first time and grants at once; other members wait.",
    setup: clubBeforeBobInstalls,
    steps: [
      (w, c) => { c.i.iphone.invite(c.space.club, c.did.bob); w.settle(); },
      (w, c) => { w.advance(1); bobInstallsAndJoins(w, c); },
    ],
    panels: [
      {
        label: "Invite Bob", device: "Alice's phone", at: 0,
        view: (w, c) => (
          <Phone>
            {club(w, c, c.i.iphone)}
            <Sheet>
              <h3>{paranoid ? "Add Bob to Book club?" : "Add to Book club"}</h3>
              {paranoid ? <p>{PARANOID.pendingWindow("Bob", weekday(PENDING_INVITE_TTL))}</p> : <div className="chips"><span className="chip">Bob</span></div>}
              <button className="primary">Add</button>
              <button className="plain">{T.cancel}</button>
            </Sheet>
          </Phone>
        ),
        caption: paranoid
          ? "Bob has no devices yet, so the invite is **pending**. The confirmation says what happens **if he joins after the pending window**."
          : "Bob has no devices yet. Alice's app **sends a pending invite**, which admits him at once.",
      },
      {
        label: "Bob is admitted", device: "Carol", at: 1,
        view: (w, c) => <Phone>{club(w, c, c.i.carol)}</Phone>,
        caption: "Members see **\"Alice added Bob\"** as for any invite.",
        expect: (w, c) => [
          check("Bob is a member", !!w.host.membership(c.space.club, c.did.bob)?.eligible),
          check("Alice's invite is pending", inviteStatus(c.i.iphone, c.space.club).pending.includes(c.did.bob)),
          check("Carol sees \"Alice added Bob\"", timeline(w, c.i.carol, c.space.club).some((b) => "line" in b && b.line === "Alice added Bob")),
        ],
      },
      {
        label: "Bob installs and joins", device: "Bob", at: 2,
        view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
        caption: "Alice's app **meets Bob's phone for the first time**, vouches for it, and grants at once, as if Bob had been installed when she invited him.",
        expect: (w, c) => [
          check("Alice's app captured the pending invite", w.provenance.invites.some((f) => f.captures && f.account === c.did.bob)),
          check("Bob holds the key, from Alice", c.i.bob.spaces.get(c.space.club)?.keyFrom?.startsWith("did:plc:alice") ?? false),
          check("He reads the history", timeline(w, c.i.bob, c.space.club).some((b) => "text" in b && b.text.startsWith("Next up"))),
        ],
      },
      {
        label: "Other members wait", device: "Carol", at: 2,
        view: (w, c) => (
          <Phone>
            <MemberList title="Members" rows={memberList(w, c.i.carol, c.space.club)} shareFrom={T.shareFrom} invitedBy={paranoid ? T.invitedBy : undefined} />
          </Phone>
        ),
        caption: paranoid
          ? "Carol's app first saw Bob's phone as a fellow member, so it **holds it for 3 days of its own time**. The member list says who invited whom."
          : "Carol's app first saw Bob's phone as a fellow member, so it **holds it for 3 days**. Carol needn't notice: Alice already shared.",
        expect: (_w, c) => [
          check("Carol has no grant standing for Bob's phone", !c.i.carol.trust.standing(c.i.bob.binding, c.space.club)),
          check("Carol's app shares from Friday", shareDay(c.i.carol, c.space.club, c.did.bob) === "Friday"),
        ],
      },
    ],
  };
}

export function newSpaceWaits(mode: Mode, number: number | string): Figure {
  const T = COPY[mode];
  const paranoid = mode === "paranoid";
  return {
    id: `${mode}-new-space-waits`,
    mode,
    number,
    title: "A new space that waits",
    description: "Alice met Carol yesterday as a fellow member of Dave's Pottery, not through an invite. Alice's new space with Carol waits out the rest of her app's 3-day hold.",
    setup: metInPottery,
    steps: [gardenWithCarol, (w) => w.advance(48)],
    panels: [
      {
        label: "New space", device: "Alice's phone", at: 0,
        view: () => <Phone><NewSpaceForm title="New space" name="Garden" members={["Carol"]} button="Create" /></Phone>,
        caption: "Alice starts Garden with Carol, **whom she met in Pottery yesterday**.",
      },
      {
        label: "Not instant", device: "Alice's phone", at: 1,
        view: (w, c) => <Phone>{club(w, c, c.i.iphone, { note: T.shareFrom("Carol", shareDay(c.i.iphone, c.space.garden, c.i.carol.did) ?? "") }, c.space.garden)}</Phone>,
        caption: "Alice's app is still holding Carol's phone from **first contact in Pottery**, and that invite didn't change it.",
        expect: (_w, c) => [
          check("Alice has no grant standing for Carol's phone", !c.i.iphone.trust.standing(c.i.carol.binding, c.space.garden)),
          check("Her app shares from Friday", shareDay(c.i.iphone, c.space.garden, c.i.carol.did) === "Friday"),
        ],
      },
      {
        label: "Carol waits", device: "Carol", at: 1,
        view: (w, c) => <Phone>{club(w, c, c.i.carol, { locked: paranoid ? T.waitingForInviter("Alice") : "Getting access…" }, c.space.garden)}</Phone>,
        caption: paranoid
          ? "**No unlock time** for Carol: only Alice's app can say when it will share. There's no \"let her in now\" button."
          : "**No unlock time,** and no \"let her in now\" button.",
        expect: (_w, c) => [check("Carol has no key", !c.i.carol.spaces.get(c.space.garden)?.key)],
      },
      {
        label: "Friday", device: "Carol", at: 2,
        view: (w, c) => <Phone>{club(w, c, c.i.carol, {}, c.space.garden)}</Phone>,
        caption: "Alice's hold ends and **her app grants**.",
        expect: (_w, c) => [check("Carol holds the key, from Alice", c.i.carol.spaces.get(c.space.garden)?.keyFrom?.startsWith("did:plc:alice") ?? false)],
      },
    ],
  };
}
