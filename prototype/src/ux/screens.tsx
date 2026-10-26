// App screens. Each takes plain props (from model.ts and copy.ts) so the same
// screen renders in a storyboard panel and on the device wall.

import type { ReactNode } from "react";
import { APP } from "./copy";
import type { AccessRow, Bubble, DeviceRow, Row, StartOverRow } from "./model";

const HUES = [232, 268, 200, 160, 20, 330];
function hue(s: string): number {
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return HUES[h % HUES.length];
}

export function Avatar({ label }: { label: string }) {
  return <span className="avatar" style={{ background: `hsl(${hue(label)} 55% 52%)` }}>{label}</span>;
}

export function Inbox({ rows, title = "Spaces", banner, onOpen, action }: { rows: Row[]; title?: string; banner?: ReactNode; onOpen?: (r: Row) => void; action?: ReactNode }) {
  return (
    <div className="inbox">
      {banner}
      <h2 className="inbox-title">{title}{action}</h2>
      {rows.map((r, n) => (
        <div key={r.uri} className={`inbox-row ${r.invited ? "invited" : ""}`} onClick={onOpen && (() => onOpen(r))}>
          <Avatar label={r.initials} />
          <div className="inbox-text">
            <div className="inbox-name">{r.name}</div>
            <div className={`inbox-preview ${r.locked ? "muted" : ""}`}>{r.preview}</div>
          </div>
          {r.invited ? <span className="join">{r.cta}</span> : <span className="inbox-time">{n === 0 ? "9:40" : "Tue"}</span>}
        </div>
      ))}
    </div>
  );
}

export function SpaceView({ title, subtitle, bubbles, composer, locked, banner, menu, note, onBack, onMore, onSend }: {
  title: string; subtitle: string; bubbles: Bubble[]; composer: string; locked?: string; banner?: ReactNode; menu?: ReactNode; note?: ReactNode;
  onBack?: () => void; onMore?: () => void; onSend?: (text: string) => void;
}) {
  return (
    <div className="space-view">
      {banner}
      <header className="space-header">
        <span className="back" onClick={onBack}>‹</span>
        <div>
          <div className="space-title">{title}</div>
          <div className="space-subtitle">{subtitle}</div>
        </div>
        <span className="more" onClick={onMore}>···</span>
      </header>
      {menu}
      {locked && <div className="locked"><span className="spinner" />{locked}</div>}
      <div className="bubbles">
        {bubbles.map((b, n) =>
          "line" in b ? (
            <div key={n} className="timeline-line">{b.line}</div>
          ) : (
            <div key={n} className={`bubble ${b.mine ? "mine" : ""}`}>
              {!b.mine && <div className="bubble-author">{b.author}</div>}
              {b.text}
            </div>
          ),
        )}
      </div>
      {note && <div className="space-note">{note}</div>}
      <div className="composer">
        {onSend ? (
          <input className="composer-input" placeholder={composer}
            onKeyDown={(e) => { if (e.key === "Enter" && e.currentTarget.value.trim()) { onSend(e.currentTarget.value.trim()); e.currentTarget.value = ""; } }} />
        ) : <span className="composer-input">{composer}</span>}
        <span className="send">↑</span>
      </div>
    </div>
  );
}

/** A deterministic stand-in for a QR code. */
export function QR({ seed, size = 21 }: { seed: string; size?: number }) {
  let x = 0;
  for (const ch of seed) x = (x * 33 + ch.charCodeAt(0)) >>> 0;
  const rnd = () => ((x = (x * 1103515245 + 12345) >>> 0) >>> 16) % 100;
  const finder = (r: number, c: number) => {
    for (const [fr, fc] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      const i = r - fr;
      const j = c - fc;
      if (i >= 0 && i < 7 && j >= 0 && j < 7) return i === 0 || i === 6 || j === 0 || j === 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4) ? 1 : 0;
      if (i >= -1 && i <= 7 && j >= -1 && j <= 7) return 0;
    }
    return -1;
  };
  const cells = [];
  for (let r = 0; r < size; r++)
    for (let c = 0; c < size; c++) {
      const f = finder(r, c);
      if (f === 1 || (f === -1 && rnd() < 45)) cells.push(<rect key={`${r}-${c}`} x={c} y={r} width={1} height={1} />);
    }
  return <svg className="qr" viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges">{cells}</svg>;
}

export function LinkThisDevice({ title, body }: { title: string; body: string }) {
  return (
    <div className="link-device">
      <QR seed="link-windows-pc" />
      <div>
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
    </div>
  );
}

export function ScanConfirm(props: { title: string; body: string; warning: string; confirm: string; cancel: string }) {
  return (
    <div className="scan">
      <div className="viewfinder"><QR seed="link-windows-pc" /></div>
      <div className="sheet">
        <h3>{props.title}</h3>
        <p>{props.body}</p>
        <p className="strong">{props.warning}</p>
        <button className="primary">{props.confirm}</button>
        <button className="plain">{props.cancel}</button>
      </div>
    </div>
  );
}

export function NoticeBanner({ title, body, actions }: { title: string; body: string; actions: { label: string; danger?: boolean; onClick?: () => void }[] }) {
  return (
    <div className="notice-banner">
      <div className="notice-app"><span className="app-dot" />{APP.toUpperCase()} · now</div>
      <div className="notice-title">{title}</div>
      <div className="notice-body">{body}</div>
      <div className="notice-actions">
        {actions.map((a) => <span key={a.label} className={a.danger ? "danger" : ""} onClick={a.onClick}>{a.label}</span>)}
      </div>
    </div>
  );
}

export function Sheet({ children }: { children: ReactNode }) {
  return <div className="sheet-overlay"><div className="sheet">{children}</div></div>;
}

export function NewSpaceForm({ title, name, members, note, button }: { title: string; name: string; members: string[]; note?: string; button: string }) {
  return (
    <div className="form">
      <header className="form-header"><span className="plain-link">Cancel</span><b>{title}</b><span className="plain-link strong">{button}</span></header>
      <label>Name</label>
      <div className="field">{name}</div>
      <label>Members</label>
      <div className="chips">{members.map((m) => <span key={m} className="chip">{m}</span>)}<span className="chip add">+ Add</span></div>
      {note && <p className="form-note">{note}</p>}
    </div>
  );
}

export function Menu({ items }: { items: { label: string; highlight?: boolean; danger?: boolean }[] }) {
  return (
    <div className="menu">
      {items.map((i) => <div key={i.label} className={`menu-item ${i.highlight ? "highlight" : ""} ${i.danger ? "danger" : ""}`}>{i.label}</div>)}
    </div>
  );
}

export function InfoScreen({ title, sections, onBack }: { title: string; sections: { heading?: string; lines: ReactNode[] }[]; onBack?: () => void }) {
  return (
    <div className="info">
      <header className="form-header"><span className="back" onClick={onBack}>‹</span><b>{title}</b><span /></header>
      {sections.map((s, n) => (
        <section key={n}>
          {s.heading && <h4>{s.heading}</h4>}
          {s.lines.map((l, k) => <div key={k} className="info-line">{l}</div>)}
        </section>
      ))}
    </div>
  );
}

const STATUS: Record<string, string> = { own: "This device", accepted: "", held: "Waiting", unlinked: "Isn't linked to their other devices", revoked: "Removed" };

function DeviceIcon({ name }: { name: string }) {
  const kind = /ipad|tablet/i.test(name) ? "tablet" : /phone|pixel|galaxy/i.test(name) ? "phone" : "laptop";
  return (
    <span className="device-icon">
      <svg viewBox="0 0 24 24">
        {kind === "phone" && <><rect x="7" y="3" width="10" height="18" rx="2.5" /><path d="M11 18h2" /></>}
        {kind === "tablet" && <><rect x="4.5" y="3" width="15" height="18" rx="2.5" /><path d="M11 18h2" /></>}
        {kind === "laptop" && <><rect x="5" y="5" width="14" height="10" rx="1.5" /><path d="M3 18.5h18" /></>}
      </svg>
    </span>
  );
}

export function DeviceList({ title, rows, note, actions = [], rowAction, mine, detail, overlay, onBack, onRowAction }: {
  title: string; rows: DeviceRow[]; note?: string; actions?: { label: string; danger?: boolean; onClick?: () => void }[]; rowAction?: (r: DeviceRow) => string | undefined; mine?: boolean;
  detail?: (r: DeviceRow) => string | undefined; overlay?: ReactNode; onBack?: () => void; onRowAction?: (r: DeviceRow) => void;
}) {
  return (
    <div className="info">
      <header className="form-header"><span className="back" onClick={onBack}>‹</span><b>{title}</b><span /></header>
      <section>
        {rows.map((r) => (
          <div key={r.name + r.status} className={`device-row ${r.status}`}>
            <DeviceIcon name={r.name} />
            <div className="device-text">
              <div className="device-name">{r.name}</div>
              <div className="device-detail">{detail?.(r) ?? (r.status === "held" ? r.detail : mine && r.status === "unlinked" ? "None of your devices linked it" : STATUS[r.status] ?? r.detail)}</div>
            </div>
            {rowAction?.(r) && <span className="row-action" onClick={() => onRowAction?.(r)}>{rowAction(r)}</span>}
          </div>
        ))}
        {note && <p className="form-note">{note}</p>}
      </section>
      {actions.length > 0 && <section>{actions.map((a) => <div key={a.label} className={`action-row ${a.danger ? "danger" : ""}`} onClick={a.onClick}>{a.label}</div>)}</section>}
      {overlay}
    </div>
  );
}

export function Provider({ title, intro, rows, button, danger }: { title: string; intro: string; rows: { label: string; detail: string; selected?: boolean }[]; button: string; danger?: boolean }) {
  return (
    <div className="provider">
      <div className="provider-bar">🔒 pds.example</div>
      <h3>{title}</h3>
      <p>{intro}</p>
      <div className="provider-rows">
        {rows.map((r) => (
          <div key={r.label} className={`provider-row ${r.selected ? "selected" : ""}`}>
            <span className="check">{r.selected ? "✓" : ""}</span>
            <div><div className="device-name">{r.label}</div><div className="device-detail">{r.detail}</div></div>
          </div>
        ))}
      </div>
      <button className={danger ? "primary danger-bg" : "primary"}>{button}</button>
    </div>
  );
}

export function Welcome({ title, body, options }: { title: string; body: string; options: { label: string; detail: string; primary?: boolean }[] }) {
  return (
    <div className="welcome">
      <div className="app-mark" />
      <h3>{title}</h3>
      <p>{body}</p>
      {options.map((o) => (
        <div key={o.label} className={`choice ${o.primary ? "primary-choice" : ""}`}>
          <div className="device-name">{o.label}</div>
          <div className="device-detail">{o.detail}</div>
        </div>
      ))}
    </div>
  );
}

export function Recovery({ title, body, spaces }: { title: string; body: string; spaces: { name: string; status: string }[] }) {
  return (
    <div className="info">
      <header className="form-header"><span /><b>{title}</b><span /></header>
      <p className="recovery-body">{body}</p>
      <section>
        {spaces.map((s) => (
          <div key={s.name} className="device-row">
            <div className="device-text"><div className="device-name">{s.name}</div></div>
            <span className={`pill ${s.status === "Unlocked" ? "ok" : ""}`}>{s.status}</span>
          </div>
        ))}
      </section>
    </div>
  );
}

export function FullAlarm({ title, body, action, onAction, onDismiss }: { title: string; body: string; action: string; onAction?: () => void; onDismiss?: () => void }) {
  return (
    <div className="full-alarm">
      <div className="alarm-icon">!</div>
      <h3>{title}</h3>
      <p>{body}</p>
      <button className="primary danger-bg" onClick={onAction}>{action}</button>
      <button className="plain light" onClick={onDismiss}>Not now</button>
    </div>
  );
}

export function Banner({ text, tone = "danger" }: { text: string; tone?: "danger" | "info" }) {
  return <div className={`banner ${tone}`}>{text}</div>;
}

export function MemberAccess({ title, rows, onBack }: { title: string; rows: AccessRow[]; onBack?: () => void }) {
  return (
    <div className="info">
      <header className="form-header"><span className="back" onClick={onBack}>‹</span><b>{title}</b><span /></header>
      <section>
        {rows.map((r, n) => (
          <div key={n} className="device-row">
            <div className="device-text">
              <div className="device-name">{r.member} · {r.device}</div>
              <div className={`device-detail ${r.declined ? "warn" : ""}`}>{r.declined ? "Declined: isn't linked to their other devices" : `Key from ${r.from}`}</div>
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}

export function LockScreen({ children }: { children: ReactNode }) {
  return <div className="lock-screen"><div className="lock-time">9:41</div>{children}</div>;
}

export function Availability({ title, rows }: { title: string; rows: { label: string; detail: string; badge?: string; on?: boolean; status?: string }[] }) {
  return (
    <div className="availability">
      <h3>{title}</h3>
      {rows.map((r) => (
        <div key={r.label} className="availability-row">
          <div className="device-text">
            <div className="availability-label">{r.label}{r.badge && <span className="tag">{r.badge}</span>}</div>
            <div className="device-detail">{r.detail}</div>
          </div>
          {r.on !== undefined ? <span className={`toggle ${r.on ? "on" : ""}`} /> : <span className="device-detail">{r.status}</span>}
        </div>
      ))}
    </div>
  );
}

export function StartOverList({ title, body, rows, confirm, stillHave, unrecognised, onConfirm, onStillHave, onUnrecognised }: {
  title: string; body: string; rows: StartOverRow[]; confirm: string; stillHave: string; unrecognised: string;
  onConfirm?: () => void; onStillHave?: () => void; onUnrecognised?: () => void;
}) {
  return (
    <div className="info">
      <header className="form-header"><span /><b>{title}</b><span /></header>
      <p className="recovery-body">{body}</p>
      <section>
        {rows.map((r) => (
          <div key={r.name + r.detail} className="device-row">
            <DeviceIcon name={r.name} />
            <div className="device-text"><div className="device-name">{r.name}</div><div className="device-detail">{r.detail}</div></div>
          </div>
        ))}
      </section>
      <div className="start-over-actions">
        <button className="primary" onClick={onConfirm}>{confirm}</button>
        <button className="plain" onClick={onStillHave}>{stillHave}</button>
        <button className="plain danger" onClick={onUnrecognised}>{unrecognised}</button>
      </div>
    </div>
  );
}

/** A space's members, with who invited each and when this device will share
 * with those it is still waiting on (device-enrollment.md#grant-standing). */
export function MemberList({ title, rows, invitedBy, shareFrom, onBack }: {
  title: string; rows: { name: string; invitedBy?: string; shareFrom?: string }[];
  invitedBy?: (who: string) => string; shareFrom?: (who: string, day: string) => string; onBack?: () => void;
}) {
  return (
    <div className="info">
      <header className="form-header"><span className="back" onClick={onBack}>‹</span><b>{title}</b><span /></header>
      <section>
        {rows.map((r) => (
          <div key={r.name} className={`device-row ${r.shareFrom ? "held" : ""}`}>
            <div className="device-text">
              <div className="device-name">{r.name}</div>
              {invitedBy && r.invitedBy && <div className="device-detail">{invitedBy(r.invitedBy === "you" ? "you" : r.invitedBy)}</div>}
              {shareFrom && r.shareFrom && <div className="device-detail">{shareFrom(r.name, r.shareFrom)}</div>}
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}
