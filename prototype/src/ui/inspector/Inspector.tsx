// The god's-eye view: what each installation believes about every device,
// who holds which space key, what the repos actually contain, and the log.

import { useState } from "react";
import { recordsIn } from "../../protocol/repo";
import { type Approval, type Binding, COL, type SpaceKeyGrant, bindingId } from "../../protocol/types";
import { useSim } from "../sim";
import { allBindings, clock, deviceName, labelName, present, readable, short, trustStatus } from "../views";

const TABS = ["Trust", "Keys", "Repos", "Log"] as const;
type Tab = (typeof TABS)[number];

export function Inspector() {
  const [tab, setTab] = useState<Tab>("Trust");
  return (
    <aside className="inspector">
      <nav>
        {TABS.map((t) => (
          <button key={t} className={t === tab ? "active" : ""} onClick={() => setTab(t)}>{t}</button>
        ))}
      </nav>
      {tab === "Trust" && <TrustMatrix />}
      {tab === "Keys" && <KeyHolders />}
      {tab === "Repos" && <Repos />}
      {tab === "Log" && <Log />}
    </aside>
  );
}

function TrustMatrix() {
  const w = useSim().world;
  const devices = allBindings(w);
  const viewers = [...w.installations.values()];
  if (!viewers.length) return <p className="muted">No installations yet.</p>;
  return (
    <div className="scroll">
      <p className="muted small">Rows are installations; columns are every device ever published. Each cell is that installation's own decision.</p>
      <table className="matrix">
        <thead>
          <tr>
            <th />
            {devices.map((b) => (
              <th key={bindingId(b)} className={present(w, b) ? "" : "gone"} title={present(w, b) ? "record present" : "record deleted"}>
                {short(b.account)}<br />{deviceName(w, b)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {viewers.map((v) => (
            <tr key={v.id} className={v.online ? "" : "offline"}>
              <th>{v.id}</th>
              {devices.map((b) => {
                const t = trustStatus(v, b, (u) => w.host.spaceName(u));
                // Inviters policy: accepted, but not yet granted to in some joined space.
                const fc = t.status === "accepted" && v.trust.policy === "inviters" && [...v.spaces.keys()].some((s) => !v.trust.standing(b, s));
                return <td key={bindingId(b)} className={fc ? "held" : t.status} title={t.detail}>{fc ? "✓⏳" : SYMBOL[t.status]}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="legend small">
        {Object.entries(SYMBOL).map(([k, s]) => <span key={k} className={k}>{s} {k}</span>)}
        {w.policy === "inviters" && <span className="held">✓⏳ accepted, no grant standing yet in a joined space</span>}
      </p>
    </div>
  );
}

const SYMBOL: Record<string, string> = { own: "●", accepted: "✓", held: "⏳", revoked: "✕", unlinked: "?", unknown: "·" };

function KeyHolders() {
  const w = useSim().world;
  const spaces = [...w.host.spaces.keys()];
  if (!spaces.length) return <p className="muted">No spaces yet.</p>;
  return (
    <div className="scroll">
      <table className="matrix">
        <thead>
          <tr><th />{spaces.map((u) => <th key={u}>{w.host.spaceName(u)}</th>)}</tr>
        </thead>
        <tbody>
          {[...w.installations.values()].map((i) => (
            <tr key={i.id}>
              <th>{i.id}</th>
              {spaces.map((u) => {
                const sp = i.spaces.get(u);
                const member = w.host.membership(u, i.did)?.eligible;
                return (
                  <td key={u} className={sp?.key ? "accepted" : sp ? "held" : "unknown"}>
                    {sp?.key ? `🔑 ${sp.keyFrom === "generated" ? "creator" : `from ${labelName(w, sp.keyFrom)}`}` : sp ? "waiting" : member ? "not joined" : "·"}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">A key once held stays held: removal stops new grants but never rotates the key.</p>
    </div>
  );
}

function Repos() {
  const w = useSim().world;
  return (
    <div className="scroll">
      {[...w.registry.keys()].map((did) => {
        const pds = w.pdsOf.get(did)!;
        const repo = pds.repo(did);
        const devs = recordsIn(repo.latest(), COL.device).map(([, v]) => (v as { value: Binding }).value);
        const aps = recordsIn(repo.latest(), COL.approval).map(([, v]) => (v as { value: Approval }).value);
        const sessions = pds.liveSessions(did);
        return (
          <section key={did} className="repo">
            <h4>{short(did)} <span className="muted small">@{pds.name} · rev {repo.rev}</span></h4>
            <div className="small">Devices: {devs.map((b) => deviceName(w, b)).join(", ") || "none"}</div>
            <div className="small">Approvals: {aps.map((a) => `${deviceName(w, a.signer)} → ${deviceName(w, a.target)}`).join(", ") || "none"}</div>
            <div className="small muted">Live sessions: {sessions.map((s) => `${s.label} (${s.kind})`).join(", ") || "none"}</div>
            {[...w.host.spaces.keys()].map((u) => {
              const r = pds.repos.get(`${did}|${u}`);
              if (!r) return null;
              const snap = r.latest();
              const grants = recordsIn(snap, COL.grant).map(([, v]) => (v as { value: SpaceKeyGrant }).value);
              return (
                <div key={u} className="small space-repo">
                  <em>{w.host.spaceName(u)}</em>: {recordsIn(snap, COL.message).length} messages, {recordsIn(snap, COL.keyRequest).length} key requests
                  {grants.length > 0 && <div>Grants: {grants.map((g) => `${deviceLabel(w, g.issuer)} → ${deviceLabel(w, g.recipient)}`).join(", ")}</div>}
                </div>
              );
            })}
          </section>
        );
      })}
    </div>
  );
}

function deviceLabel(w: ReturnType<typeof useSim>["world"], d: { account: string; deviceId: string }): string {
  for (const i of w.installations.values()) if (i.binding.device.deviceId === d.deviceId) return i.id;
  return `${short(d.account)}/${d.deviceId.slice(0, 6)}`;
}

function Log() {
  const sim = useSim();
  const w = sim.world;
  const violations = sim.run.monitor.violations;
  return (
    <div className="scroll">
      {violations.length > 0 && (
        <section>
          <h4 className="bad">Invariant violations</h4>
          {violations.map((v, i) => <div key={i} className="small bad">{clock(v.at)} {v.text}</div>)}
        </section>
      )}
      <section>
        <h4>Events</h4>
        {[...w.log].reverse().map((e, i) => <div key={i} className="small"><span className="muted">{clock(e.at)}</span> {e.text}</div>)}
      </section>
      <section>
        <h4>Last decisions</h4>
        {[...w.installations.values()].flatMap((i) => i.lastDecisions.map((d, k) => <div key={i.id + k} className="small"><strong>{i.id}</strong> {readable(d)}</div>))}
      </section>
    </div>
  );
}
