// Figures for ux-flows/relaxed.md, in the order of its sections.

import { check } from "../../sim/scenario";
import { bookClub, checkOldDevices, club, clubWithoutBob, people, say, scanConfirmFor } from "./cast";
import { invitingBeforeInstall, newSpaceAfterReset } from "./invites";
import { COPY } from "../copy";
import type { Figure } from "../figure";
import { Laptop, Phone, Tablet } from "../frames";
import { alarmsOf, deviceName, devices, inbox, latestNotice, memberAccess, recovery, timeline, waiting } from "../model";
import {
  Banner, DeviceList, FullAlarm, InfoScreen, Inbox, LinkThisDevice, LockScreen, MemberAccess, Menu, NewSpaceForm, NoticeBanner,
  Provider, Recovery, Sheet, Welcome,
} from "../screens";

const T = COPY.relaxed;
const scanConfirm = (device: string) => scanConfirmFor("relaxed", device);

// ---- 1. Creating a space ----------------------------------------------------

const creatingASpace: Figure = {
  id: "relaxed-creating-a-space",
  mode: "relaxed",
  number: 1,
  title: "Creating a space",
  description: "A name and optional members. No security choices, and no wait: the key is made on this device before the space exists.",
  setup: people,
  steps: [(w, c) => {
    c.space.club = c.i.iphone.createSpace("Book club");
    for (const d of [c.i.bob, c.i.carol]) c.i.iphone.invite(c.space.club, d.did);
    w.settle();
    say(w, c.i.iphone, c.space.club, "Welcome! First up: Middlemarch.");
  }],
  panels: [
    {
      label: "New space", device: "Alice's phone", at: 0,
      view: () => <Phone><NewSpaceForm title="New space" name="Book club" members={["Bob", "Carol"]} button="Create" /></Phone>,
      caption: "Name and optional members. **No security choices.**",
    },
    {
      label: "Space opens", device: "Alice's phone", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.iphone)}</Phone>,
      caption: "The key was generated before creation and its commitment fixed in the space's settings, so **posting starts at once**.",
      expect: (w, c) => [
        check("Alice holds the key at once", !!c.i.iphone.spaces.get(c.space.club)?.key),
        check("Her first message is readable", timeline(w, c.i.iphone, c.space.club).some((b) => "text" in b && b.text.startsWith("Welcome"))),
        check("Additions are visible", timeline(w, c.i.iphone, c.space.club).some((b) => "line" in b && b.line === "You added Bob")),
      ],
    },
    {
      label: "Space info", device: "Alice's phone", at: 1,
      view: (w, c) => (
        <Phone>
          <InfoScreen title="Book club" sections={[
            { heading: "Members", lines: w.host.members(c.space.club).map((d) => (d === c.i.iphone.did ? "You" : d.replace("did:plc:", "").replace(/^./, (x) => x.toUpperCase()))) },
            { heading: "History", lines: ["Everyone in this space can read its full history."] },
          ]} />
        </Phone>
      ),
      caption: "**Retained history is discoverable** in space info rather than explained at every invite.",
    },
  ],
};

// ---- 2. Adding a member -------------------------------------------------------

const addingAMember1: Figure = {
  id: "relaxed-adding-a-member-1",
  mode: "relaxed",
  number: 2,
  title: "Adding a member (1 of 2)",
  description: "Alice adds Bob with one tap. Every member sees the change; Bob sees an invitation, not a device list.",
  setup: clubWithoutBob,
  steps: [(w, c) => { c.i.iphone.invite(c.space.club, c.i.bob.did); w.settle(); }],
  panels: [
    {
      label: "Invite Bob", device: "Alice's phone", at: 0,
      view: (w, c) => (
        <Phone>
          {club(w, c, c.i.iphone)}
          <Sheet>
            <h3>Add to Book club</h3>
            <div className="chips"><span className="chip">Bob</span></div>
            <button className="primary">Add</button>
            <button className="plain">{T.cancel}</button>
          </Sheet>
        </Phone>
      ),
      caption: "One tap. **No history explanation;** space info carries it.",
    },
    {
      label: "Members see it", device: "Carol", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.carol)}</Phone>,
      caption: "Additions, removals, and readmissions are **always visible** to members.",
      expect: (w, c) => [check("Carol sees \"Alice added Bob\"", timeline(w, c.i.carol, c.space.club).some((b) => "line" in b && b.line === "Alice added Bob"))],
    },
    {
      label: "Bob is invited", device: "Bob", at: 1,
      view: (w, c) => <Phone><Inbox rows={inbox(w, c.i.bob)} /></Phone>,
      caption: "**Join Book club.** One tap, and no device list is shown.",
      expect: (w, c) => [
        check("Bob is a member", !!w.host.membership(c.space.club, c.i.bob.did)?.eligible),
        check("He has not joined yet", !c.i.bob.spaces.has(c.space.club)),
      ],
    },
  ],
};

const addingAMember2: Figure = {
  id: "relaxed-adding-a-member-2",
  mode: "relaxed",
  number: 2,
  title: "Adding a member (2 of 2)",
  description: "Bob joins. Members' devices grant him the key in the background; a device Bob never linked gets nothing.",
  setup: (w, c) => {
    clubWithoutBob(w, c);
    c.i.iphone.invite(c.space.club, c.i.bob.did);
    w.settle();
  },
  steps: [
    (w, c) => {
      for (const i of [c.i.iphone, c.i.ipad, c.i.carol]) w.setOnline(i, false);
      c.i.bob.join(c.space.club);
      w.settle();
    },
    (w, c) => { w.advance(0.2); w.setOnline(c.i.iphone, true); },
    (w, c) => { c.i.tablet = w.install(c.i.bob.did, "Bob's tablet"); },
  ],
  panels: [
    {
      label: "Getting access…", device: "Bob", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.bob, { locked: "Getting access…", composer: "Draft (sends when unlocked)" })}</Phone>,
      caption: "Members' devices usually grant within seconds, **in the background**. Bob can write drafts meanwhile.",
      expect: (_w, c) => [check("Bob has no key yet", !c.i.bob.spaces.get(c.space.club)?.key)],
    },
    {
      label: "If nothing arrives", device: "Alice's phone", at: 1,
      view: () => (
        <Phone dark>
          <LockScreen>
            <NoticeBanner title="Bob is waiting to join Book club" body="Open to share access." actions={[]} />
          </LockScreen>
        </Phone>
      ),
      caption: "Members get a nudge to open the space. **It carries no key material** and establishes no trust.",
      expect: (w, c) => [check("Bob's key request is pending", waiting(w, c.space.club).includes(c.i.bob.did))],
    },
    {
      label: "Unlock", device: "Bob", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "Alice's device, which met Bob's when she invited him, grants. Others pin it on first sight and quietly wait. **No badges, no verification prompts.** One grant unlocks the whole history.",
      expect: (w, c) => [
        check("Bob holds the key", !!c.i.bob.spaces.get(c.space.club)?.key),
        check("He reads history from before he joined", timeline(w, c.i.bob, c.space.club).some((b) => "text" in b && b.text.startsWith("Next up"))),
      ],
    },
    {
      label: "No link, no key", device: "Alice's phone", at: 3,
      view: (w, c) => {
        const all = devices(w, c.i.iphone, c.i.bob.did);
        const unlinked = all.filter((r) => r.status === "unlinked").length;
        return <Phone><DeviceList title="Bob's devices" rows={all.filter((r) => r.status !== "unlinked")} note={unlinked ? `${unlinked} device isn't linked.` : undefined} /></Phone>;
      },
      caption: "A Bob device that no Bob device linked receives no keys, **with no override**. His device list quietly says so.",
      expect: (w, c) => [
        check("Alice declines the unlinked tablet", devices(w, c.i.iphone, c.i.bob.did).some((r) => r.name === "Bob's tablet" && r.status === "unlinked")),
        check("The tablet gets no key", !c.i.tablet.spaces.get(c.space.club)?.key),
      ],
    },
  ],
};

// ---- 3. Adding a device, and replacing a phone ------------------------------------

const addingADevice: Figure = {
  id: "relaxed-adding-a-device",
  mode: "relaxed",
  number: 3,
  title: "Adding a device",
  description: "Alice links her laptop from her phone. One confirmation, one warning. Her other devices are told; other members are not.",
  setup: bookClub,
  steps: [(w, c) => { c.i.laptop = w.install(c.i.iphone.did, "Windows PC", { link: c.i.iphone }); }],
  panels: [
    {
      label: "Laptop shows a code", device: "Alice's laptop", at: 0,
      view: () => <Laptop><LinkThisDevice title={T.linkThisDevice} body={T.linkThisDeviceBody} /></Laptop>,
      caption: "The laptop is a fresh install. It shows a code; it asks nothing else.",
    },
    {
      label: "Scan + one confirmation", device: "Alice's phone", at: 0,
      view: () => scanConfirm("Windows PC"),
      caption: "The name comes from the laptop: **it proves nothing**. The ownership warning is what counters scan-my-code tricks. On confirm, the laptop can read every space; it asks for keys as Alice opens them, and her phone grants in the background.",
    },
    {
      label: "Her other devices hear", device: "Alice's iPad", at: 1,
      view: (w, c) => {
        const n = latestNotice(c.i.ipad, "own-added");
        return (
          <Tablet>
            {n && <NoticeBanner title={T.newDeviceTitle(deviceName(w, n.about))} body={T.newDeviceBody(deviceName(w, n.by))}
              actions={[{ label: T.removeIt, danger: true }, { label: T.itWasMe }]} />}
            <div className="under-banner"><Inbox rows={inbox(w, c.i.ipad)} /></div>
          </Tablet>
        );
      },
      caption: "**Required notice + removal action.** This is how Alice catches a compromised device quietly adding an attacker's. **Remove it** signs the device out at her provider first, then deletes it.",
      expect: (w, c) => {
        const n = latestNotice(c.i.ipad, "own-added");
        return [
          check("The iPad has a new-device notice", !!n),
          check("It names the laptop", deviceName(w, n?.about) === "Windows PC"),
          check("It names the approving phone", deviceName(w, n?.by) === "iPhone"),
        ];
      },
    },
    {
      label: "Other members", device: "Bob", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "**Nothing.** Same-account device additions never surface to other members: no line, no badge.",
      expect: (_w, c) => [
        check("Bob accepts the laptop silently", c.i.bob.trust.isAccepted(c.i.laptop.binding)),
        check("Bob got no notice about it", !c.i.bob.trust.state.notices.some((n) => n.kind === "own-added" || n.kind === "reset")),
      ],
    },
  ],
};

const replacingAPhone: Figure = {
  id: "relaxed-replacing-a-phone",
  mode: "relaxed",
  number: "3b",
  title: "Replacing a phone",
  description: "Alice links her new phone from the old one. The app never suggests removing the old phone: wiping it is enough.",
  setup: bookClub,
  steps: [(w, c) => {
    c.i.newPhone = w.install(c.i.iphone.did, "iPhone 17", { link: c.i.iphone });
    for (const s of [c.space.club, c.space.family]) c.i.newPhone.join(s);
    w.settle();
  }],
  panels: [
    {
      label: "Link it", device: "Alice's old phone", at: 0,
      view: () => scanConfirm("iPhone 17"),
      caption: "An ordinary link: the old phone confirms, with the same warning.",
    },
    {
      label: "Catching up", device: "Alice's new phone", at: 1,
      view: (w, c) => <Phone><Inbox rows={inbox(w, c.i.newPhone)} /></Phone>,
      caption: "It asks for keys as Alice opens spaces, and **her devices grant them**.",
      expect: (_w, c) => [check("The new phone holds both keys", [c.space.club, c.space.family].every((s) => !!c.i.newPhone.spaces.get(s)?.key))],
    },
    {
      label: "No prompt to remove", device: "Alice's old phone", at: 1,
      view: (w, c) => <Phone><DeviceList title="Your devices" rows={devices(w, c.i.iphone, c.i.iphone.did)} actions={[{ label: "Link a new device" }]} /></Phone>,
      caption: "**The app doesn't suggest removing the old phone.** Removing it right away would show a reset to members whose apps haven't caught up.",
    },
    {
      label: "Other members", device: "Bob", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "**Nothing,** and no hold anywhere: members accept the new phone through the link.",
      expect: (_w, c) => [
        check("Bob accepts the new phone", c.i.bob.trust.isAccepted(c.i.newPhone.binding)),
        check("Nobody holds", [c.i.bob, c.i.carol, c.i.mum].every((i) => !i.trust.hold(c.i.iphone.did))),
      ],
    },
  ],
};

// ---- 4. Losing every device ------------------------------------------------------

const losingEveryDevice: Figure = {
  id: "relaxed-losing-every-device",
  mode: "relaxed",
  number: 4,
  title: "Losing every device",
  description: "Alice loses her phone and iPad with no backup. She starts over: check her old devices and approve removing them at her provider, then wait while people who know her hold for 3 days.",
  setup: bookClub,
  steps: [
    (w, c) => {
      for (const i of [c.i.iphone, c.i.ipad]) w.setOnline(i, false);
      c.i.fresh = w.install(c.i.iphone.did, "New iPhone", { startOver: true });
      for (const s of [c.space.club, c.space.family]) c.i.fresh.join(s);
      w.settle();
    },
    (w, c) => { w.finishStartOver(c.i.fresh); },
  ],
  panels: [
    {
      label: "Restore or start over", device: "Alice's new phone", at: 0,
      view: () => (
        <Phone>
          <Welcome title="Welcome back" body="This device has no saved state." options={[
            { label: "Restore from backup", detail: "Your keys and spaces, right away." },
            { label: "Start over", detail: "Remove your old devices at your provider. People who know you will wait before sharing.", primary: true },
          ]} />
        </Phone>
      ),
      caption: "With no backup and no surviving device, **starting over is the only way in**.",
    },
    checkOldDevices(1),
    {
      label: "Waiting", device: "Alice's new phone", at: 2,
      view: (w, c) => (
        <Phone>
          <Recovery title="Getting your spaces back" body="People who already know you will wait at least 3 days before sharing with this device." spaces={recovery(w, c.i.fresh)} />
        </Phone>
      ),
      caption: "Each space shows its own status as members' apps catch up. **No promised time:** each member's app starts its own wait when it first sees the new phone.",
      expect: (_w, c) => [
        check("Both spaces are still locked", [c.space.club, c.space.family].every((s) => !c.i.fresh.spaces.get(s)?.key)),
        check("The new phone raises no alarm for her old devices", alarmsOf(c.i.fresh).length === 0),
      ],
    },
    {
      label: "Members", device: "Bob", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "**A quiet line,** with the time Bob's own app computed. Relaxed apps can't skip or shorten the wait.",
      expect: (w, c) => [
        check("Bob holds Alice's new phone", !!c.i.bob.trust.hold(c.i.iphone.did)),
        check("His timeline says so", timeline(w, c.i.bob, c.space.club).some((b) => "line" in b && b.line.includes("from Friday"))),
      ],
    },
  ],
};

// ---- 5. Creating a space from an existing space -----------------------------------------

export const creatingFromExisting: Figure = {
  id: "relaxed-creating-from-existing",
  mode: "relaxed",
  number: 5,
  title: "Creating a space from an existing space",
  description: "Members are copied; messages aren't. Each member joins with one tap, and trust carries over.",
  setup: bookClub,
  steps: [
    (w, c) => {
      c.space.next = c.i.iphone.createSpace("Book club 2");
      for (const d of [c.i.bob, c.i.carol]) c.i.iphone.invite(c.space.next, d.did);
      w.settle();
      say(w, c.i.iphone, c.space.next, "Season two starts here!");
    },
    (w, c) => { c.i.bob.join(c.space.next); w.settle(); },
  ],
  panels: [
    {
      label: "From the space menu", device: "Alice's phone", at: 0,
      view: (w, c) => <Phone>{club(w, c, c.i.iphone, { menu: <Menu items={[{ label: "Space info" }, { label: "Members" }, { label: "New space from Book club…", highlight: true }, { label: "Leave", danger: true }]} /> })}</Phone>,
      caption: "There's no parent and child: **each space is independent**.",
    },
    {
      label: "Members are copied", device: "Alice's phone", at: 0,
      view: () => <Phone><NewSpaceForm title="New space" name="Book club 2" members={["Bob", "Carol"]} note="Members are copied; messages aren't." button="Create" /></Phone>,
      caption: "Membership is prefilled for Alice to confirm. **Each admission is still a host decision.**",
    },
    {
      label: "One tap to join", device: "Bob", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.bob, {}, c.space.next)}</Phone>,
      caption: "**Existing pins carry over,** so Bob's device gets the new key as soon as it asks.",
      expect: (_w, c) => [check("Bob holds the new space's key", !!c.i.bob.spaces.get(c.space.next)?.key)],
    },
  ],
};

// ---- 6. Removing a member or device -------------------------------------------------------

export const removing: Figure = {
  id: "relaxed-removing",
  mode: "relaxed",
  number: 6,
  title: "Removing a member or device",
  description: "Removal stops new keys at once and existing access within minutes. The app never claims more.",
  setup: bookClub,
  steps: [
    (w, c) => { c.i.iphone.removeMember(c.space.club, c.i.carol.did); w.settle(); },
    (w, c) => { w.removeDevice(c.i.ipad); },
  ],
  panels: [
    {
      label: "Carol was removed", device: "Bob", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "New keys stop at once; **Carol's access ends within minutes**, when her credential expires.",
      expect: (w, c) => [check("Bob sees the removal", timeline(w, c.i.bob, c.space.club).some((b) => "line" in b && b.line === "Carol was removed"))],
    },
    {
      label: "Space info is honest", device: "Alice's phone", at: 1,
      view: () => (
        <Phone>
          <InfoScreen title="Book club" sections={[
            { heading: "Removed", lines: ["Carol"] },
            { lines: ["Carol's devices still hold this space's key. If she got new messages some other way, she could read them."] },
          ]} />
        </Phone>
      ),
      caption: "**Never claims Carol is locked out** of new messages: nothing is rotated.",
      expect: (_w, c) => [check("Carol still holds the key", !!c.i.carol.spaces.get(c.space.club)?.key)],
    },
    {
      label: "Lost device: sign out", device: "Alice's phone", at: 1,
      view: () => (
        <Phone>
          <Provider title="Sign out a device" intro="Apps signed in to your account. Signing one out stops it reading within minutes."
            rows={[{ label: "Lantern on iPad", detail: "Signed in since September", selected: true }, { label: "Lantern on iPhone", detail: "This device" }]} button="Sign out" />
        </Phone>
      ),
      caption: "**Sign-out comes first,** so the lost device can't write its record back.",
    },
    {
      label: "Then remove it", device: "Alice's phone", at: 2,
      view: (w, c) => <Phone><DeviceList title="Your devices" rows={devices(w, c.i.iphone, c.i.iphone.did)} note="iPad was removed. If someone may know your password, change it." /></Phone>,
      caption: "Deleting its record, after a provider approval, revokes it everywhere. **No move to a new space is suggested.**",
      expect: (_w, c) => [check("Bob revoked the iPad", !c.i.bob.trust.isAccepted(c.i.ipad.binding))],
    },
  ],
};

// ---- 7. Alarms ------------------------------------------------------------------------------

const alarms: Figure = {
  id: "relaxed-alarms",
  mode: "relaxed",
  number: 7,
  title: "Alarms",
  description: "Relaxed presentation quiets routine notices, never integrity alarms.",
  setup: bookClub,
  steps: [
    (w, c) => { w.attackerDevice(c.i.iphone.did, "Unknown device"); },
    (w, c) => { w.host.tamper(c.space.club, { commitment: new Uint8Array(32) }); w.settle(); },
  ],
  panels: [
    {
      label: "Unrecognised device", device: "Alice's phone", at: 1,
      view: () => (
        <Phone>
          <FullAlarm title="A device you don't recognise may have access to your spaces." body="None of your devices linked it. If you didn't add it, someone may be signed in to your account." action="Review devices" />
        </Phone>
      ),
      caption: "Raised when a device of Alice's account appears that **no device of hers approved**.",
      expect: (_w, c) => [check("Alice's phone raises the alarm", alarmsOf(c.i.iphone, "unapproved-own").length > 0)],
    },
    {
      label: "Review devices", device: "Alice's phone", at: 1,
      view: (w, c) => (
        <Phone>
          <DeviceList title="Your devices" mine rows={devices(w, c.i.iphone, c.i.iphone.did)} rowAction={(r) => (r.status === "unlinked" ? "Remove" : undefined)} />
        </Phone>
      ),
      caption: "**Remove** signs it out at her provider, then deletes it. Changing her password stops it coming back.",
    },
    {
      label: "Host integrity", device: "Alice's phone", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.iphone, { banner: <Banner text="This space's security settings changed unexpectedly." /> })}</Phone>,
      caption: "A space reporting **a different key commitment** than first seen. The app keeps the original and alarms.",
      expect: (_w, c) => [check("Alice's phone raises a host integrity alarm", alarmsOf(c.i.iphone, "host-integrity").length > 0)],
    },
  ],
};

// ---- 8. Settings ---------------------------------------------------------------------------------

const settings: Figure = {
  id: "relaxed-settings",
  mode: "relaxed",
  number: 8,
  title: "Settings",
  description: "Surfaces the specification requires to exist, but lets a relaxed app bury.",
  setup: (w, c) => {
    bookClub(w, c);
    c.i.tablet = w.install(c.i.bob.did, "Bob's tablet");
  },
  steps: [(w, c) => { c.i.carol.resetLocalState(); w.settle(); }],
  panels: [
    {
      label: "Devices & security", device: "Alice's phone", at: 0,
      view: (w, c) => <Phone><DeviceList title="Devices & security" rows={devices(w, c.i.iphone, c.i.iphone.did)} actions={[{ label: "Link a new device" }, { label: "I lost a device", danger: true }]} /></Phone>,
      caption: "Her devices, **Link a new device**, and **I lost a device**, which signs a device out at her provider, then removes it.",
    },
    {
      label: "Member access", device: "Alice's phone", at: 0,
      view: (w, c) => <Phone><MemberAccess title="Member access" rows={memberAccess(w, c.i.iphone, c.space.club)} /></Phone>,
      caption: "Deep in space settings: **which devices each member was given the key**, and by whom, plus devices declined as unlinked.",
      expect: (w, c) => [check("Bob's unlinked tablet is listed as declined", memberAccess(w, c.i.iphone, c.space.club).some((r) => r.declined && r.device === "Bob's tablet"))],
    },
    {
      label: "Lost local state", device: "Carol", at: 1,
      view: (w, c) => (
        <Phone>
          <Inbox rows={inbox(w, c.i.carol)} banner={<Banner tone="info" text="This device couldn't restore its saved security state and trusted everyone again." />} />
        </Phone>
      ),
      caption: "Reported by the app itself when it notices, **not hidden in settings**.",
      expect: (_w, c) => [check("Carol's device knows it lost its state", c.i.carol.lostState)],
    },
  ],
};

export const relaxedFigures: Figure[] = [
  creatingASpace, newSpaceAfterReset("relaxed", "1b"), addingAMember1, addingAMember2, invitingBeforeInstall("relaxed", "2b"), addingADevice, replacingAPhone, losingEveryDevice, creatingFromExisting, removing, alarms, settings,
];
