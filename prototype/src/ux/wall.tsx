// The device wall: a clickable prototype over one live world. Every
// installation gets a framed device with its own navigation; everything it
// shows comes from its own protocol state, as in the figures. The controls
// under each device and in the top bar stand in for the world outside the
// app: going offline, the provider's removal page, new people and devices,
// and the passing of time.

import { type ReactNode, useReducer, useRef, useState } from "react";
import type { Installation } from "../protocol/installation";
import { COL } from "../protocol/types";
import { World } from "../world/world";
import { COPY, type Mode, START_OVER, TOFU } from "./copy";
import type { FigureCtx } from "./figure";
import { bookClub } from "./figures/cast";
import { Laptop, Phone, Tablet } from "./frames";
import { type DeviceRow, alarmsOf, deviceName, devices, inbox, memberAccess, members, person, soleHolder, startOverList, timeline } from "./model";
import { DeviceList, FullAlarm, InfoScreen, Inbox, MemberAccess, NoticeBanner, SpaceView, StartOverList } from "./screens";

type Nav = { screen: "inbox" } | { screen: "space"; uri: string } | { screen: "info"; uri: string } | { screen: "access"; uri: string } | { screen: "devices"; account: string };
/** How many alarms and notices each device has already shown. */
type Seen = { alarms: number; notices: number };

function newWorld(): World {
  const w = new World("wall");
  bookClub(w, { i: {}, space: {} } as FigureCtx);
  return w;
}

const live = (w: World, i: Installation) =>
  w.pdsOf.get(i.did)!.repo(i.did).records.has(`${COL.device}/${i.binding.device.deviceId}`);

function Frame({ name, children }: { name: string; children: ReactNode }) {
  if (/laptop|desktop|pc|mac/i.test(name)) return <Laptop>{children}</Laptop>;
  if (/ipad|tablet/i.test(name)) return <Tablet>{children}</Tablet>;
  return <Phone>{children}</Phone>;
}

export function Wall() {
  const world = useRef<World>(newWorld());
  const [, bump] = useReducer((n: number) => n + 1, 0);
  const [mode, setMode] = useState<Mode>("relaxed");
  const [nav, setNav] = useState<Record<string, Nav>>({});
  const [seen, setSeen] = useState<Record<string, Seen>>({});
  const w = world.current;
  // For poking at the live world from the console while developing.
  if (import.meta.env.DEV) (window as unknown as { nbdWorld: World }).nbdWorld = w;

  /** Run a world action, let every online device sync, and redraw. */
  const act = (fn: (w: World) => void) => {
    try {
      fn(w);
      w.settle();
    } catch (e) {
      alert((e as Error).message);
    }
    bump();
  };
  const go = (id: string, n: Nav) => setNav((x) => ({ ...x, [id]: n }));

  const accounts = [...new Set([...w.installations.values()].map((i) => i.did))];

  return (
    <div className="wall">
      <header className="wall-bar">
        <b>Lantern</b>
        <span className="seg">
          {(["relaxed", "tofu"] as const).map((m) => (
            <button key={m} className={mode === m ? "on" : ""} onClick={() => setMode(m)}>{m === "tofu" ? "TOFU" : "Relaxed"}</button>
          ))}
        </span>
        <button onClick={() => act((w) => { const name = prompt("New person's name")?.trim().toLowerCase(); if (name) w.install(w.account(name), "iPhone"); })}>Add person</button>
        <button onClick={() => act((w) => w.advance(24))}>Wait a day</button>
        <button onClick={() => { world.current = newWorld(); setNav({}); setSeen({}); bump(); }}>Reset</button>
        <span className="clock">Day {Math.floor(w.now() / 24) + 1}, {String(Math.floor(w.now() % 24)).padStart(2, "0")}:00</span>
        <a href="?figures">Figures</a>
      </header>
      <div className="wall-grid">
        {accounts.map((did) => (
          <section key={did} className="wall-account">
            <h2>{person(did)}<button onClick={() => act((w) => w.install(did, "New iPhone", { startOver: true }))}>Start over on a new phone</button><button onClick={() => act((w) => w.install(did, prompt("Name of the unlinked device", "Unknown device")?.trim() || "Unknown device"))}>Add unlinked device</button></h2>
            <div className="wall-devices">
              {[...w.installations.values()].filter((i) => i.did === did).map((i) => (
                <Device key={i.id} w={w} me={i} mode={mode} nav={nav[i.id] ?? { screen: "inbox" }} go={(n) => go(i.id, n)}
                  seen={seen[i.id] ?? { alarms: 0, notices: 0 }} see={(s) => setSeen((x) => ({ ...x, [i.id]: s }))} act={act} />
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

function Device({ w, me, mode, nav, go, seen, see, act }: {
  w: World; me: Installation; mode: Mode; nav: Nav; go: (n: Nav) => void; seen: Seen; see: (s: Seen) => void; act: (fn: (w: World) => void) => void;
}) {
  const T = COPY[mode];
  const isLive = live(w, me);
  const alarms = alarmsOf(me);
  const notices = me.trust.state.notices.filter((n) => n.kind === "own-added");
  const ownDevices = () => go({ screen: "devices", account: me.did });
  const added = (r: DeviceRow) => (mode === "tofu" && r.status === "accepted" ? (r.linkedFrom ? `Linked from ${r.linkedFrom}` : "First seen") : undefined);

  let screen: ReactNode;
  const startingOver = me.trust.state.startOver && !me.trust.state.startOver.done;
  if (startingOver) {
    screen = (
      <StartOverList {...START_OVER} rows={startOverList(w, me)} onConfirm={() => act((w) => w.finishStartOver(me))}
        onStillHave={() => alert("Link this phone from the device you still have instead: it needs no wait.")}
        onUnrecognised={() => alert("Your account may have been compromised. Change your password and sign out other sessions at your provider, then remove them.")} />
    );
  } else if (alarms.length > seen.alarms) {
    const a = alarms[alarms.length - 1];
    const dismiss = () => see({ ...seen, alarms: alarms.length });
    screen = <FullAlarm title={alarmTitle(a.kind)} body={alarmBody(a.kind) ?? a.text} action="Review devices" onAction={() => { dismiss(); ownDevices(); }} onDismiss={dismiss} />;
  } else if (nav.screen === "space") {
    const uri = nav.uri;
    const sp = me.spaces.get(uri);
    screen = (
      <SpaceView title={w.host.spaceName(uri)} subtitle={members(w, me, uri)} bubbles={timeline(w, me, uri)} composer={sp?.key ? T.message : "Draft (sends when unlocked)"}
        locked={sp?.key ? undefined : mode === "tofu" ? TOFU.waitingForDevice : "Getting access…"}
        note={mode === "tofu" && soleHolder(w, me, uri) ? <>{TOFU.soleHolder} <b onClick={ownDevices}>{TOFU.addADevice}</b></> : undefined}
        onBack={() => go({ screen: "inbox" })} onMore={() => go({ screen: "info", uri })}
        onSend={sp?.key ? (text) => act(() => { w.advance(0.05); me.post(uri, text); }) : undefined} />
    );
  } else if (nav.screen === "info") {
    const uri = nav.uri;
    const admin = w.host.admin(uri) === me.did;
    const memberList = w.host.members(uri);
    const others = [...new Set([...w.installations.values()].map((i) => i.did))].filter((d) => !memberList.includes(d));
    screen = (
      <InfoScreen title={w.host.spaceName(uri)} onBack={() => go({ screen: "space", uri })} sections={[
        { heading: "Members", lines: memberList.map((d) => (
          <span className="wall-line">{d === me.did ? "You" : person(d)}
            {d !== me.did && <a onClick={() => go({ screen: "devices", account: d })}>Devices</a>}
            {admin && d !== me.did && <a className="danger" onClick={() => act(() => me.removeMember(uri, d))}>Remove</a>}
          </span>
        )) },
        ...(admin && others.length ? [{ heading: "Add", lines: others.map((d) => <span className="wall-line">{person(d)}<a onClick={() => act(() => me.invite(uri, d))}>Add</a></span>) }] : []),
        ...(mode === "tofu" ? [{ heading: "Devices", lines: [TOFU.unverified] }] : []),
        { heading: "History", lines: ["Everyone in this space can read its full history."] },
        { lines: [<a onClick={() => go({ screen: "access", uri })}>Member access</a>] },
      ]} />
    );
  } else if (nav.screen === "access") {
    screen = <MemberAccess title="Member access" rows={memberAccess(w, me, nav.uri)} onBack={() => go({ screen: "info", uri: nav.uri })} />;
  } else if (nav.screen === "devices") {
    const mine = nav.account === me.did;
    const rows = devices(w, me, nav.account);
    screen = (
      <DeviceList title={mine ? "Your devices" : `${person(nav.account)} · ${rows.length} devices`} rows={rows} mine={mine} detail={added}
        note={!mine && rows.some((r) => r.status === "unlinked") ? (mode === "tofu" ? TOFU.unlinkedNote(person(nav.account)) : "1 device isn't linked.") : undefined}
        onBack={() => go({ screen: "inbox" })}
        rowAction={(r) => (mine && !r.own && r.live ? "Remove" : undefined)}
        onRowAction={(r) => act((w) => w.removeDevice(r.binding))}
        actions={mine ? [{
          label: "Link a new device",
          onClick: () => act((w) => { const name = prompt("Name of the new device", "Laptop")?.trim(); if (name) w.install(me.did, name, { link: me }); }),
        }] : []} />
    );
  } else {
    const n = notices.length > seen.notices ? notices[notices.length - 1] : undefined;
    const dismiss = () => see({ ...seen, notices: notices.length });
    screen = (
      <>
        {n && <NoticeBanner title={T.newDeviceTitle(deviceName(w, n.about))} body={T.newDeviceBody(deviceName(w, n.by))} actions={[
          { label: T.removeIt, danger: true, onClick: () => { dismiss(); if (n.about) act((w) => w.removeDevice(n.about!)); } },
          { label: T.itWasMe, onClick: dismiss },
        ]} />}
        <div className={n ? "under-banner" : ""}>
          <Inbox rows={inbox(w, me)}
            action={<span className="inbox-actions"><a onClick={ownDevices}>Devices</a><a onClick={() => act(() => { const name = prompt("Space name")?.trim(); if (name) me.createSpace(name); })}>New</a></span>}
            onOpen={(r) => { if (r.invited) act(() => me.join(r.uri)); go({ screen: "space", uri: r.uri }); }} />
        </div>
      </>
    );
  }

  return (
    <div className={`wall-device ${me.online ? "" : "offline"} ${isLive ? "" : "removed"}`}>
      <div className="wall-device-head"><b>{me.name}</b>{!isLive && <span className="tag">removed</span>}{!me.online && <span className="tag">offline</span>}</div>
      <Frame name={me.name}>{screen}</Frame>
      <div className="wall-controls">
        <button onClick={() => act((w) => w.setOnline(me, !me.online))}>{me.online ? "Go offline" : "Go online"}</button>
      </div>
    </div>
  );
}

/** The flow docs' wording, where they give one; otherwise the protocol's own text. */
function alarmBody(kind: string): string | undefined {
  if (kind === "unapproved-own" || kind === "unapproved-grant") return "None of your devices linked it. If you didn't add it, someone may be signed in to your account.";
  if (kind === "own-removed") return TOFU.removedAlarmBody;
  if (kind === "host-integrity") return "The app keeps the settings it first saw.";
  return undefined;
}

function alarmTitle(kind: string): string {
  if (kind === "unapproved-own" || kind === "unapproved-grant") return "A device you don't recognise may have access to your spaces.";
  if (kind === "own-removed") return TOFU.removedAlarm;
  if (kind === "host-integrity") return "This space's security settings changed unexpectedly.";
  return "Something about your spaces changed unexpectedly.";
}
