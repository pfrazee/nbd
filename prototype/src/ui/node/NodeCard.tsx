// One installation as a small phone-sized app, using the copy from
// ux-flows/paranoid.md. Everything shown comes from this installation's own
// state, so cards disagree exactly where installations do.

import { useState } from "react";
import type { Installation } from "../../protocol/installation";
import { type Binding, bindingId } from "../../protocol/types";
import { useSim } from "../sim";
import { allBindings, clock, deviceName, installationsOf, present, readable, short, spaceStatus, trustStatus, visibleSpaces } from "../views";

export function NodeCard({ inst }: { inst: Installation }) {
  const sim = useSim();
  const w = sim.world;
  const st = inst.trust.state;
  const [newSpace, setNewSpace] = useState("");
  const [linkName, setLinkName] = useState("");
  const attacker = w.provenance.attacker.has(inst.binding.device.deviceId);
  const revoked = st.revoked.has(bindingId(inst.binding));
  const ownDevices = allBindings(w).filter((b) => b.account === inst.did && present(w, b));
  const people = inst.trackedAccounts().filter((d) => d !== inst.did);

  return (
    <div className={`card ${inst.online ? "" : "offline"} ${attacker ? "attacker" : ""} ${revoked ? "revoked" : ""}`} data-node={inst.id}>
      <header>
        <div>
          <strong>{short(inst.did)}</strong> · {inst.name}
          {attacker && <span className="tag bad">attacker</span>}
          {(w.lag.get(inst.id) ?? 0) > 0 && <span className="tag" title="Reads repos this many hours late">{w.lag.get(inst.id)}h late</span>}
          {w.policy === "witness" && <span className="tag" title="The application whose witness this installation trusts">{inst.app}</span>}
        </div>
        <label className="toggle" title="An offline installation stops syncing">
          <input
            type="checkbox"
            checked={inst.online}
            onChange={(e) => sim.act(`${inst.id} ${e.target.checked ? "online" : "offline"}`, (w) => w.setOnline(inst, e.target.checked))}
          />
          online
        </label>
      </header>
      {inst.clockOffset !== 0 && <div className="muted small">Local clock {clock(inst.localNow())}</div>}

      {inst.liveness() && <div className="alarm" title="Witness policy: coverage age over 24 hours; cannot be dismissed">{inst.liveness()} (coverage {Number.isFinite(inst.coverageAge()) ? `${inst.coverageAge().toFixed(1)}h` : "unknown"})</div>}
      {inst.gapWarnings().map((g) => (
        <div key={g.key} className="notice gap">
          Gap in your account's history (revision {g.fromRev}{g.toRev !== g.fromRev ? `-${g.toRev}` : ""}): {g.reason}.{" "}
          <button onClick={() => sim.act(`${inst.id} acknowledged a gap`, () => inst.acknowledgeGap(g.key))}>Acknowledge</button>
        </div>
      ))}
      {st.alarms.map((a, i) => (
        <div key={`a${i}`} className="alarm">{readable(a.text)}</div>
      ))}
      {[...st.notices].reverse().slice(0, 4).map((n, i) => (
        <div key={`n${i}`} className={`notice ${n.kind}`}>{readable(n.text)}</div>
      ))}

      {visibleSpaces(w, inst).map((uri) => (
        <SpaceView key={uri} inst={inst} uri={uri} />
      ))}

      <div className="row">
        <input placeholder="New space name" value={newSpace} onChange={(e) => setNewSpace(e.target.value)} />
        <button
          disabled={!newSpace || !inst.online}
          onClick={() => {
            sim.act(`${inst.id} created ${newSpace}`, (w) => {
              inst.createSpace(newSpace);
              w.settle();
            });
            setNewSpace("");
          }}
        >
          Create
        </button>
      </div>

      <details>
        <summary>My devices ({ownDevices.length})</summary>
        {ownDevices.map((b) => (
          <DeviceRow key={bindingId(b)} viewer={inst} b={b} removable={bindingId(b) !== bindingId(inst.binding)} />
        ))}
        <div className="row">
          <input placeholder="New device name" value={linkName} onChange={(e) => setLinkName(e.target.value)} />
          <button
            disabled={!linkName || !inst.online || revoked}
            title="Link this device: it will be able to read all your spaces. Only link devices you own."
            onClick={() => {
              sim.act(`${inst.id} linked ${linkName}`, (w) => w.install(inst.did, linkName, { link: inst }));
              setLinkName("");
            }}
          >
            Link
          </button>
        </div>
      </details>

      {people.length > 0 && (
        <details>
          <summary>People</summary>
          {people.map((d) => (
            <div key={d}>
              <div className="small"><strong>{short(d)}</strong></div>
              {allBindings(w).filter((b) => b.account === d && (present(w, b) || st.accepted.has(bindingId(b)))).map((b) => (
                <DeviceRow key={bindingId(b)} viewer={inst} b={b} removable={false} />
              ))}
            </div>
          ))}
        </details>
      )}
    </div>
  );
}

function DeviceRow({ viewer, b, removable }: { viewer: Installation; b: Binding; removable: boolean }) {
  const sim = useSim();
  const w = sim.world;
  const t = trustStatus(viewer, b, (u) => w.host.spaceName(u));
  const target = installationsOf(w, b.account).find((i) => i.binding.device.deviceId === b.device.deviceId);
  return (
    <div className="device">
      <span className={`dot ${t.status}`} title={t.detail} />
      <span>{deviceName(w, b)}</span>
      <span className="muted small">{t.status === "accepted" ? "" : t.detail}</span>
      {removable && present(w, b) && (
        <button
          className="link"
          title="Signs it out at your provider, then deletes it from your account"
          onClick={() => sim.act(`${viewer.id} removed ${deviceName(w, b)}`, (w) => w.removeDevice(target ?? b))}
        >
          Remove
        </button>
      )}
    </div>
  );
}

function SpaceView({ inst, uri }: { inst: Installation; uri: string }) {
  const sim = useSim();
  const w = sim.world;
  const [draft, setDraft] = useState("");
  const [invitee, setInvitee] = useState("");
  const s = spaceStatus(w, inst, uri);
  const name = w.host.spaceName(uri);
  const admin = w.host.admin(uri) === inst.did;
  const others = [...w.registry.keys()].filter((d) => !w.host.membership(uri, d)?.eligible);

  if (!s.joined)
    return (
      <div className="space">
        <div className="space-name">{name}</div>
        <button disabled={!inst.online} onClick={() => sim.act(`${inst.id} joined ${name}`, (w) => { inst.join(uri); w.settle(); })}>
          Join {name}
        </button>
      </div>
    );

  const msgs = inst.messages(uri);
  return (
    <div className="space">
      <div className="space-name">
        {name}
        {s.hasKey ? <span className="tag ok" title={`key from ${s.keyFrom}`}>unlocked</span> : <span className="tag">locked</span>}
      </div>
      {s.waiting && <div className="muted small">Waiting for a member's device…</div>}
      {s.sole && <div className="muted small">Only this device can currently read this space.</div>}
      {!s.invited && <div className="muted small">You're no longer a member.</div>}
      <div className="messages">
        {msgs.map((m) => (
          <div key={m.author + m.rkey} className="msg">
            <span className="author">{short(m.author)}</span>
            {"text" in m ? <span>{m.text}</span> : <span className="muted">🔒 encrypted</span>}
          </div>
        ))}
      </div>
      <div className="row">
        <input placeholder={s.hasKey ? "Message" : "Draft (sends when unlocked)"} value={draft} onChange={(e) => setDraft(e.target.value)} />
        <button
          disabled={!draft || !inst.online}
          onClick={() => {
            sim.act(`${inst.id} posted in ${name}`, (w) => { inst.post(uri, draft); w.settle(); });
            setDraft("");
          }}
        >
          Send
        </button>
      </div>
      {admin && others.length > 0 && (
        <div className="row">
          <select value={invitee} onChange={(e) => setInvitee(e.target.value)}>
            <option value="">Invite…</option>
            {others.map((d) => <option key={d} value={d}>{short(d)}</option>)}
          </select>
          <button
            disabled={!invitee}
            title={`${short(invitee)} will be able to read everything already posted here.`}
            onClick={() => {
              sim.act(`${inst.id} invited ${short(invitee)} to ${name}`, (w) => { inst.invite(uri, invitee); w.settle(); });
              setInvitee("");
            }}
          >
            Invite
          </button>
        </div>
      )}
    </div>
  );
}
