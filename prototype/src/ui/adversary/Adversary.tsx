// Adversary and network controls: per-installation lag, malicious-PDS
// policies, a thief with copied keys, backups, and account takeover.

import { useState } from "react";
import { bindingId } from "../../protocol/types";
import { useSim } from "../sim";
import { accounts, allBindings, clock, deviceName, installationsOf, present, readable, short } from "../views";

export function AdversaryPanel() {
  const sim = useSim();
  const w = sim.world;
  const insts = [...w.installations.values()];
  const [lagInst, setLagInst] = useState("");
  const [lag, setLag] = useState("6");
  const [subAcct, setSubAcct] = useState("");
  const [subVictim, setSubVictim] = useState("");
  const [resetAcct, setResetAcct] = useState("");
  const [forkDevice, setForkDevice] = useState("");
  const [forkVictim, setForkVictim] = useState("");
  const [stealFrom, setStealFrom] = useState("");
  const [stolenIdx, setStolenIdx] = useState("");
  const [approveFor, setApproveFor] = useState("");
  const [backupFrom, setBackupFrom] = useState("");
  const [restoreIdx, setRestoreIdx] = useState("");
  const [takeAcct, setTakeAcct] = useState("");

  const inst = (id: string) => w.installations.get(id)!;
  const instOptions = (filter: (id: string) => boolean = () => true) => (
    <>
      <option value="">Installation…</option>
      {insts.filter((i) => filter(i.id)).map((i) => <option key={i.id} value={i.id}>{i.id}</option>)}
    </>
  );
  const acctOptions = (
    <>
      <option value="">Account…</option>
      {accounts(w).map((d) => <option key={d} value={d}>{short(d)}</option>)}
    </>
  );
  const liveDevices = allBindings(w).filter((b) => present(w, b));
  const stolen = w.stolen[Number(stolenIdx)];

  return (
    <details className="panel adversary" open>
      <summary>Adversary and network</summary>

      <h5>Network</h5>
      <div className="row">
        <select value={lagInst} onChange={(e) => setLagInst(e.target.value)}>{instOptions()}</select>
        <select value={lag} onChange={(e) => setLag(e.target.value)}>
          {["0", "1", "6", "24"].map((h) => <option key={h} value={h}>{h}h late</option>)}
        </select>
        <button disabled={!lagInst} onClick={() => sim.act(`${lagInst} lag ${lag}h`, (w) => w.setLag(inst(lagInst), Number(lag)))}>Set lag</button>
      </div>

      <h5>Malicious PDS</h5>
      <div className="row" title="The PDS shows an installation that has never met the account a device it controls">
        <select value={subAcct} onChange={(e) => setSubAcct(e.target.value)}>{acctOptions}</select>
        <select value={subVictim} onChange={(e) => setSubVictim(e.target.value)}>{instOptions((id) => inst(id).did !== subAcct)}</select>
        <button className="danger" disabled={!subAcct || !subVictim} onClick={() => sim.act(`substitute ${short(subAcct)} for ${subVictim}`, (w) => w.substituteDevices(subAcct, inst(subVictim), `sub${w.adversary.policies.length + 1}`))}>
          Substitute
        </button>
      </div>
      <div className="row" title="The PDS resets the account and keeps showing its own devices the old state">
        <select value={resetAcct} onChange={(e) => setResetAcct(e.target.value)}>{acctOptions}</select>
        <button className="danger" disabled={!resetAcct} onClick={() => sim.act(`hidden reset of ${short(resetAcct)}`, (w) => w.hiddenReset(resetAcct, `pds-device${w.adversary.policies.length + 1}`))}>
          Hidden reset
        </button>
      </div>
      <div className="row" title="The PDS shows one installation a history where a device was deleted">
        <select value={forkDevice} onChange={(e) => setForkDevice(e.target.value)}>
          <option value="">Device…</option>
          {liveDevices.map((b) => <option key={bindingId(b)} value={bindingId(b)}>{short(b.account)}/{deviceName(w, b)}</option>)}
        </select>
        <select value={forkVictim} onChange={(e) => setForkVictim(e.target.value)}>{instOptions()}</select>
        <button className="danger" disabled={!forkDevice || !forkVictim} onClick={() => {
          const b = liveDevices.find((x) => bindingId(x) === forkDevice)!;
          sim.act(`fork ${deviceName(w, b)} for ${forkVictim}`, (w) => w.hideDeviceFrom(b, inst(forkVictim)));
        }}>
          Fork
        </button>
      </div>
      {w.adversary.policies.map((p) => (
        <div key={p.id} className="policy small">
          {readable(p.describe)}
          <button className="link" onClick={() => sim.act(`stop policy ${p.id}`, (w) => { w.adversary.remove(p.id); w.settle(); })}>stop</button>
        </div>
      ))}

      <h5>Thief</h5>
      <div className="row">
        <select value={stealFrom} onChange={(e) => setStealFrom(e.target.value)}>{instOptions()}</select>
        <button disabled={!stealFrom} onClick={() => sim.act(`copied keys of ${stealFrom}`, (w) => w.stealKeys(inst(stealFrom)))}>Copy keys</button>
      </div>
      {w.stolen.length > 0 && (
        <div className="row" title="Publish an approval signed with the copied key, using the target's session to write">
          <select value={stolenIdx} onChange={(e) => setStolenIdx(e.target.value)}>
            <option value="">Copied key…</option>
            {w.stolen.map((k, i) => <option key={i} value={i}>{short(k.binding.account)}/{deviceName(w, k.binding)}</option>)}
          </select>
          <select value={approveFor} onChange={(e) => setApproveFor(e.target.value)}>
            {instOptions((id) => !!stolen && inst(id).did === stolen.binding.account && inst(id).binding.device.deviceId !== stolen.deviceId)}
          </select>
          <button className="danger" disabled={!stolen || !approveFor} onClick={() => sim.act(`approved ${approveFor} with a copied key`, (w) => w.approveWith(stolen, inst(approveFor), inst(approveFor).sessionId!))}>
            Approve
          </button>
        </div>
      )}
      <div className="row" title="Someone with the password deletes every device and enrolls their own">
        <select value={takeAcct} onChange={(e) => setTakeAcct(e.target.value)}>{acctOptions}</select>
        <button className="danger" disabled={!takeAcct} onClick={() => sim.act(`attacker took over ${short(takeAcct)}`, (w) => w.takeover(takeAcct, `attacker${installationsOf(w, takeAcct).filter((i) => i.name.startsWith("attacker")).length || ""}`))}>
          Take over
        </button>
      </div>

      <h5>Backups</h5>
      <div className="row">
        <select value={backupFrom} onChange={(e) => setBackupFrom(e.target.value)}>{instOptions()}</select>
        <button disabled={!backupFrom} onClick={() => sim.act(`backed up ${backupFrom}`, (w) => w.backup(inst(backupFrom)))}>Back up</button>
      </div>
      {w.backups.length > 0 && (
        <div className="row" title="The source installation is lost; a replacement restores its keys and this backup">
          <select value={restoreIdx} onChange={(e) => setRestoreIdx(e.target.value)}>
            <option value="">Backup…</option>
            {w.backups.map((b, i) => <option key={i} value={i} disabled={!w.installations.has(b.from)}>{b.from} at {clock(b.at)}</option>)}
          </select>
          <button disabled={!restoreIdx || !w.installations.has(w.backups[Number(restoreIdx)]?.from)} onClick={() => {
            const b = w.backups[Number(restoreIdx)];
            sim.act(`restored ${b.from}`, (w) => w.restore(inst(b.from), Number(restoreIdx)));
            setRestoreIdx("");
          }}>
            Lose device and restore
          </button>
        </div>
      )}
    </details>
  );
}
