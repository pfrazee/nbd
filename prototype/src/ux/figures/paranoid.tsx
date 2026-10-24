// Figures for ux-flows/paranoid.md, in the order of its sections. The cast and
// setups are the Relaxed figures'; the copy and the security detail differ.

import { check } from "../../sim/scenario";
import type { World } from "../../world/world";
import { COPY, PARANOID } from "../copy";
import type { Figure, FigureCtx } from "../figure";
import { Laptop, Phone, Tablet } from "../frames";
import { alarmsOf, deviceName, devices, inbox, latestNotice, memberAccess, person, recovery, soleHolder, timeline, waiting } from "../model";
import type { DeviceRow } from "../model";
import {
  Availability, DeviceList, FullAlarm, InfoScreen, Inbox, LinkThisDevice, LockScreen, NewSpaceForm, NoticeBanner, Recovery, Sheet,
} from "../screens";
import { bookClub, checkOldDevices, club, clubWithoutBob, people, say, scanConfirmFor } from "./cast";
import { creatingFromExisting, removing } from "./relaxed";

const T = COPY.paranoid;
type C = FigureCtx;
const scanConfirm = (device: string) => scanConfirmFor("paranoid", device);

/** Device lists say how each device was added, with no badges (paranoid.md#ui-vocabulary). */
const added = (r: DeviceRow) =>
  r.status === "accepted" ? (r.linkedFrom ? `Linked from ${r.linkedFrom}` : "First seen")
    : r.status === "unlinked" ? "Not linked: no keys shared with it" : undefined;

const accountDevices = (w: World, me: C["i"][string], account: string) => {
  const rows = devices(w, me, account);
  return <DeviceList title={`${person(account)} · ${rows.length} devices`} rows={rows} detail={added} />;
};

// ---- 1. Creating a space ----------------------------------------------------

const creatingASpace: Figure = {
  id: "paranoid-creating-a-space",
  mode: "paranoid",
  number: 1,
  title: "Creating a space",
  description: "A name and optional members, with no security or device choices. Until another device holds the key, the space says so.",
  setup: people,
  steps: [
    (w, c) => {
      c.space.club = c.i.iphone.createSpace("Book club");
      for (const d of [c.i.bob, c.i.carol]) c.i.iphone.invite(c.space.club, d.did);
      w.settle();
      say(w, c.i.iphone, c.space.club, "Welcome! First up: Middlemarch.");
    },
    (w, c) => { c.i.ipad.join(c.space.club); w.settle(); },
  ],
  panels: [
    {
      label: "New space", device: "Alice's phone", at: 0,
      view: () => <Phone><NewSpaceForm title="New space" name="Book club" members={["Bob", "Carol"]} button="Create" /></Phone>,
      caption: "Name and optional members. **No device choice:** every device on the account can read every space it belongs to.",
    },
    {
      label: "Sole holder", device: "Alice's phone", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.iphone, { note: <>{PARANOID.soleHolder} <b>{PARANOID.addADevice}</b></> })}</Phone>,
      caption: "Posting starts at once. While **no other device has the key**, a quiet note says so and links to adding a device.",
      expect: (w, c) => [
        check("Alice holds the key at once", !!c.i.iphone.spaces.get(c.space.club)?.key),
        check("Her phone is the sole holder", soleHolder(w, c.i.iphone, c.space.club)),
      ],
    },
    {
      label: "Space info", device: "Alice's phone", at: 1,
      view: (w, c) => (
        <Phone>
          <InfoScreen title="Book club" sections={[
            { heading: "Members", lines: w.host.members(c.space.club).map((d) => (d === c.i.iphone.did ? "You" : person(d))) },
            { heading: "Devices", lines: [PARANOID.unverified] },
            { heading: "History", lines: ["Everyone in this space can read its full history."] },
          ]} />
        </Phone>
      ),
      caption: "**No verification.** Space info says changes are shown, not blocked, and that members read the full history.",
    },
    {
      label: "Note clears", device: "Alice's phone", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.iphone)}</Phone>,
      caption: "Once her iPad opens the space and **receives the key**, the note disappears.",
      expect: (w, c) => [
        check("The iPad holds the key", !!c.i.ipad.spaces.get(c.space.club)?.key),
        check("The phone is no longer the sole holder", !soleHolder(w, c.i.iphone, c.space.club)),
      ],
    },
  ],
};

// ---- 2. Adding a member -------------------------------------------------------

const addingAMember1: Figure = {
  id: "paranoid-adding-a-member-1",
  mode: "paranoid",
  number: 2,
  title: "Adding a member (1 of 2)",
  description: "Alice adds Bob. The confirmation says he'll read the history; every member sees the change; Bob joins with one tap.",
  setup: clubWithoutBob,
  steps: [(w, c) => { c.i.iphone.invite(c.space.club, c.i.bob.did); w.settle(); }],
  panels: [
    {
      label: "Invite Bob", device: "Alice's phone", at: 0,
      view: (w, c) => (
        <Phone>
          {club(w, c, c.i.iphone)}
          <Sheet>
            <h3>Add Bob to Book club?</h3>
            <p>{PARANOID.inviteHistory("Bob")}</p>
            <button className="primary">Add</button>
            <button className="plain">{T.cancel}</button>
          </Sheet>
        </Phone>
      ),
      caption: "The confirmation says **admission includes retained history**: a space has one key.",
    },
    {
      label: "Members see it", device: "Carol", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.carol)}</Phone>,
      caption: "**Every member sees** \"Alice added Bob\" in the timeline.",
      expect: (w, c) => [check("Carol sees \"Alice added Bob\"", timeline(w, c.i.carol, c.space.club).some((b) => "line" in b && b.line === "Alice added Bob"))],
    },
    {
      label: "Bob is invited", device: "Bob", at: 1,
      view: (w, c) => <Phone><Inbox rows={inbox(w, c.i.bob)} /></Phone>,
      caption: "**Join Book club.** One tap, no device list. His other devices ask for the key when he opens it there.",
      expect: (w, c) => [
        check("Bob is a member", !!w.host.membership(c.space.club, c.i.bob.did)?.eligible),
        check("He has not joined yet", !c.i.bob.spaces.has(c.space.club)),
      ],
    },
  ],
};

const addingAMember2: Figure = {
  id: "paranoid-adding-a-member-2",
  mode: "paranoid",
  number: 2,
  title: "Adding a member (2 of 2)",
  description: "Bob waits briefly for a member's device, then reads the whole history. Members see his devices; a device he never linked gets nothing, and his own app alarms.",
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
    (w, c) => { w.advance(0.2); w.setOnline(c.i.carol, true); },
    (w, c) => { c.i.tablet = w.install(c.i.bob.did, "Bob's tablet"); },
  ],
  panels: [
    {
      label: "Brief locked state", device: "Bob", at: 1,
      view: (w, c) => <Phone>{club(w, c, c.i.bob, { locked: PARANOID.waitingForDevice, composer: "Draft (sends when unlocked)" })}</Phone>,
      caption: "His app publishes a key request. Members' devices grant **in the background**, usually within seconds.",
      expect: (w, c) => [
        check("Bob has no key yet", !c.i.bob.spaces.get(c.space.club)?.key),
        check("His key request is pending", waiting(w, c.space.club).includes(c.i.bob.did)),
      ],
    },
    {
      label: "Unlock", device: "Bob", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "Carol's device pins Bob's on first sight and grants; Bob's pins Carol's. **One grant unlocks all history.**",
      expect: (w, c) => [
        check("Bob holds the key", !!c.i.bob.spaces.get(c.space.club)?.key),
        check("Carol pinned Bob's phone on first use", c.i.carol.trust.isAccepted(c.i.bob.binding)),
        check("He reads history from before he joined", timeline(w, c.i.bob, c.space.club).some((b) => "text" in b && b.text.startsWith("Next up"))),
      ],
    },
    {
      label: "Device lists", device: "Carol", at: 3,
      view: (w, c) => {
        const rows = devices(w, c.i.carol, c.i.bob.did);
        return <Phone><DeviceList title={`Bob · ${rows.length} devices`} rows={rows} detail={added} note={rows.some((r) => r.status === "unlinked") ? PARANOID.unlinkedNote("Bob") : undefined} /></Phone>;
      },
      caption: "**No badges, no Verify.** A Bob device no Bob device linked gets no keys, with no override, and the list says so.",
      expect: (w, c) => [
        check("Carol declines the unlinked tablet", devices(w, c.i.carol, c.i.bob.did).some((r) => r.name === "Bob's tablet" && r.status === "unlinked")),
        check("The tablet gets no key", !c.i.tablet.spaces.get(c.space.club)?.key),
      ],
    },
    {
      label: "Bob's alarm", device: "Bob", at: 3,
      view: () => (
        <Phone>
          <FullAlarm title={PARANOID.unrecognised("Book club")} body="None of your devices linked it. If you didn't add it, someone may be signed in to your account." action="Review devices" />
        </Phone>
      ),
      caption: "Bob's own app audits his account. **Alarms are the main defense** against substitution, so they're prominent.",
      expect: (_w, c) => [check("Bob's phone raises the alarm", alarmsOf(c.i.bob, "unapproved-own").length > 0)],
    },
  ],
};

// ---- 3. Adding a device, and replacing a phone ------------------------------------

const addingADevice: Figure = {
  id: "paranoid-adding-a-device",
  mode: "paranoid",
  number: 3,
  title: "Adding a device",
  description: "Alice links her laptop from her phone. Her other devices notify her; members accept the laptop through the link, with no timeline notice.",
  setup: bookClub,
  steps: [(w, c) => { c.i.laptop = w.install(c.i.iphone.did, "Alice's Laptop", { link: c.i.iphone }); }],
  panels: [
    {
      label: "Laptop shows a code", device: "Alice's laptop", at: 0,
      view: () => <Laptop><LinkThisDevice title={T.linkThisDevice} body={T.linkThisDeviceBody} /></Laptop>,
      caption: "Until it's linked, **members who know Alice won't share keys with it**, and the screen says so.",
    },
    {
      label: "Scan + confirm", device: "Alice's phone", at: 0,
      view: () => scanConfirm("Alice's Laptop"),
      caption: "The phone signs an approval. **No list of spaces:** the laptop can read them all. Pairing moves her pins across.",
    },
    {
      label: "Her other devices", device: "Alice's iPad", at: 1,
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
      caption: "One notice per device, none on the approving phone. **Remove it** signs the laptop out at her provider, then deletes it.",
      expect: (w, c) => {
        const n = latestNotice(c.i.ipad, "own-added");
        return [
          check("The iPad has a new-device notice", !!n),
          check("It names the laptop", deviceName(w, n?.about) === "Alice's Laptop"),
          check("It names the approving phone", deviceName(w, n?.by) === "iPhone"),
          check("The phone has no notice", !latestNotice(c.i.iphone, "own-added")),
        ];
      },
    },
    {
      label: "Other members", device: "Bob", at: 1,
      view: (w, c) => <Phone>{accountDevices(w, c.i.bob, c.i.iphone.did)}</Phone>,
      caption: "Approved by Alice's phone, so **Bob accepts it**. No timeline notice; her device list shows 3 devices.",
      expect: (w, c) => [
        check("Bob accepts the laptop", c.i.bob.trust.isAccepted(c.i.laptop.binding)),
        check("Bob got no notice about it", !c.i.bob.trust.state.notices.some((n) => n.kind === "own-added" || n.kind === "reset")),
        check("Bob lists 3 devices for Alice", devices(w, c.i.bob, c.i.iphone.did).length === 3),
      ],
    },
  ],
};

const replacingAPhone: Figure = {
  id: "paranoid-replacing-a-phone",
  mode: "paranoid",
  number: "3b",
  title: "Replacing a phone",
  description: "Alice links her new phone from the old one. The app doesn't offer to remove the old phone, and if she does, it suggests waiting a few days.",
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
      caption: "An ordinary link from the old phone, **with the same warning**.",
    },
    {
      label: "Catching up", device: "Alice's new phone", at: 1,
      view: (w, c) => <Phone><Inbox rows={inbox(w, c.i.newPhone)} /></Phone>,
      caption: "It asks for keys as Alice opens spaces, and **her devices grant them**.",
      expect: (_w, c) => [check("The new phone holds both keys", [c.space.club, c.space.family].every((s) => !!c.i.newPhone.spaces.get(s)?.key))],
    },
    {
      label: "If she removes it", device: "Alice's new phone", at: 1,
      view: (w, c) => (
        <Phone>
          <DeviceList title="Your devices" rows={devices(w, c.i.newPhone, c.i.iphone.did)} detail={added} rowAction={(r) => (r.name === "iPhone" ? "Remove" : undefined)}
            overlay={
              <Sheet>
                <h3>Remove iPhone now?</h3>
                <p>{PARANOID.replaceWait}</p>
                <button className="primary">Wait</button>
                <button className="plain danger">Remove anyway</button>
              </Sheet>
            } />
        </Phone>
      ),
      caption: "Wiping the old phone is enough. **Removing it at once would look like a reset** to members whose apps haven't caught up.",
    },
    {
      label: "Other members", device: "Bob", at: 1,
      view: (w, c) => <Phone>{accountDevices(w, c.i.bob, c.i.iphone.did)}</Phone>,
      caption: "**No hold anywhere:** members accept the new phone through the link.",
      expect: (_w, c) => [
        check("Bob accepts the new phone", c.i.bob.trust.isAccepted(c.i.newPhone.binding)),
        check("Nobody holds", [c.i.bob, c.i.carol, c.i.mum].every((i) => !i.trust.hold(c.i.iphone.did))),
      ],
    },
  ],
};

// ---- 4. Losing every device ------------------------------------------------------

const losingEveryDevice: Figure = {
  id: "paranoid-losing-every-device",
  mode: "paranoid",
  number: 4,
  title: "Losing every device",
  description: `Alice loses her phone and iPad with no backup and taps ${PARANOID.startOver}. She checks and removes her old devices; people who knew her wait at least 72 hours.`,
  setup: bookClub,
  steps: [
    (w, c) => {
      for (const i of [c.i.iphone, c.i.ipad]) w.setOnline(i, false);
      c.i.fresh = w.install(c.i.iphone.did, "New iPhone", { startOver: true });
      for (const s of [c.space.club, c.space.family]) c.i.fresh.join(s);
      w.settle();
    },
    (w, c) => { w.finishStartOver(c.i.fresh); },
    (w, c) => { w.setOnline(c.i.ipad, true); w.settle(); },
  ],
  panels: [
    checkOldDevices(1),
    {
      label: "Waiting", device: "Alice's new phone", at: 2,
      view: (w, c) => <Phone><Recovery title="Getting your spaces back" body={PARANOID.holdBody} spaces={recovery(w, c.i.fresh)} /></Phone>,
      caption: "Each space shows its own status. **No promised time:** each member's app starts its own wait, and one that never knew Alice may share at once.",
      expect: (_w, c) => [
        check("Both spaces are still locked", [c.space.club, c.space.family].every((s) => !c.i.fresh.spaces.get(s)?.key)),
        check("The new phone raises no alarm for her old devices", alarmsOf(c.i.fresh).length === 0),
      ],
    },
    {
      label: "Members", device: "Bob", at: 2,
      view: (w, c) => <Phone>{club(w, c, c.i.bob)}</Phone>,
      caption: "The line gives **the time Bob's own app computed**. His app can't shorten its own wait.",
      expect: (w, c) => [
        check("Bob holds Alice's new phone", !!c.i.bob.trust.hold(c.i.iphone.did)),
        check("His timeline says so", timeline(w, c.i.bob, c.space.club).some((b) => "line" in b && b.line.includes("from Friday"))),
      ],
    },
    {
      label: "If it wasn't Alice", device: "Alice's old iPad", at: 3,
      view: () => <Tablet><FullAlarm title={PARANOID.removedAlarm} body={PARANOID.removedAlarmBody} action="Review devices" /></Tablet>,
      caption: "A surviving old device **alarms as soon as it sees itself removed**. Removing the new device there cancels the hold.",
      expect: (_w, c) => [check("The iPad raises the alarm", alarmsOf(c.i.ipad, "own-removed").length > 0)],
    },
  ],
};

// ---- 5. Creating a space from an existing space, 6. Removing ------------------------------
// The same flows and copy as Relaxed.

const paranoidCreatingFromExisting: Figure = { ...creatingFromExisting, id: "paranoid-creating-from-existing", mode: "paranoid" };
const paranoidRemoving: Figure = { ...removing, id: "paranoid-removing", mode: "paranoid" };

// ---- 7. Keeping spaces available ------------------------------------------------------------

const keepingSpacesAvailable: Figure = {
  id: "paranoid-keeping-spaces-available",
  mode: "paranoid",
  number: 7,
  title: "Keeping spaces available",
  description: "Joining only works if someone grants. Three layers make that reliable: background issuing, a visible prompt, and always-on devices.",
  setup: (w, c) => {
    clubWithoutBob(w, c);
    c.i.mum = w.install(w.account("mum"), "iPhone");
    c.i.desktop = w.install(c.i.iphone.did, "Mac mini", { link: c.i.iphone });
    c.i.desktop.join(c.space.club);
    for (const d of [c.i.bob, c.i.mum]) c.i.iphone.invite(c.space.club, d.did);
    w.settle();
  },
  steps: [
    (w, c) => { c.i.bob.join(c.space.club); w.settle(); },
    (w, c) => {
      for (const i of [c.i.iphone, c.i.ipad, c.i.carol, c.i.bob, c.i.desktop]) w.setOnline(i, false);
      c.i.mum.join(c.space.club);
      w.settle();
    },
    (w, c) => { w.advance(0.5); w.setOnline(c.i.desktop, true); w.settle(); },
  ],
  panels: [
    {
      label: "Background issuing", device: "Carol's locked phone", at: 1,
      view: () => (
        <Phone dark>
          <LockScreen>
            <NoticeBanner title="Bob joined Book club" body="" actions={[]} />
          </LockScreen>
        </Phone>
      ),
      caption: "The notification's service extension grants: **no one opens the app**. Needs installation keys readable after first unlock.",
      expect: (_w, c) => [check("Bob holds the key", !!c.i.bob.spaces.get(c.space.club)?.key)],
    },
    {
      label: "Visible prompt", device: "Carol, if no grant lands", at: 2,
      view: (w, c) => (
        <Phone>
          <NoticeBanner title={PARANOID.waitingToJoin("Mum", "Book club")} body={PARANOID.openToShare} actions={[]} />
          <div className="under-banner"><Inbox rows={inbox(w, c.i.carol)} /></div>
        </Phone>
      ),
      caption: "After a short window with no grant, the requester's app asks members directly. **Opening the space is the whole job.**",
      expect: (w, c) => [
        check("Mum's key request is pending", waiting(w, c.space.club).includes(c.i.mum.did)),
        check("Mum has no key", !c.i.mum.spaces.get(c.space.club)?.key),
      ],
    },
    {
      label: "Always-on devices", device: "Alice's desktop · Settings", at: 3,
      view: () => (
        <Laptop>
          <Availability title="Availability" rows={[
            { label: PARANOID.keepAvailable, detail: PARANOID.keepAvailableBody, on: true },
            { label: "Haven agent", badge: "hosted", detail: "Operated by haven.example. It holds keys to your enabled spaces.", status: "Connected" },
          ]} />
        </Laptop>
      ),
      caption: "A desktop, home server, or hosted agent is **an ordinary linked device that's always running**. Hosted agents say who operates them.",
      expect: (w, c) => [
        check("Mum holds the key", !!c.i.mum.spaces.get(c.space.club)?.key),
        check("Alice's desktop granted it", memberAccess(w, c.i.desktop, c.space.club).some((r) => r.member === "Mum" && r.from.includes("Mac mini"))),
      ],
    },
  ],
};

export const paranoidFigures: Figure[] = [
  creatingASpace, addingAMember1, addingAMember2, addingADevice, replacingAPhone, losingEveryDevice, paranoidCreatingFromExisting, paranoidRemoving, keepingSpacesAvailable,
];
