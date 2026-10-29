// Layout: toolbar, narration for the current scenario step, the node grid,
// and the inspector.

import { useState } from "react";
import { AdversaryPanel } from "./adversary/Adversary";
import { Inspector } from "./inspector/Inspector";
import { NodeCard } from "./node/NodeCard";
import { useSim } from "./sim";
import { accounts, clock, installationsOf, short } from "./views";

// Sandbox: accounts and unlinked installs. Attacks live in AdversaryPanel.

export function App() {
  return (
    <div className="app">
      <Toolbar />
      <Narration />
      <main>
        <section className="nodes">
          <div className="panels">
            <Sandbox />
            <AdversaryPanel />
          </div>
          <Grid />
        </section>
        <Inspector />
      </main>
    </div>
  );
}

function Toolbar() {
  const sim = useSim();
  const run = sim.run;
  const steps = run.scenario.steps.length;
  return (
    <header className="toolbar">
      <h1>NBD prototype</h1>
      <select value={run.scenario.id} onChange={(e) => sim.load(e.target.value)}>
        {sim.scenarios.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}
      </select>
      {steps > 0 && (
        <>
          <button onClick={() => sim.next()} disabled={run.done} className="primary">
            {run.next === 0 ? "Start" : run.done ? "Done" : "Next step"}
          </button>
          <span className="muted">Step {run.next} of {steps}</span>
        </>
      )}
      <button onClick={() => sim.load(run.scenario.id)}>Reset</button>
      {sim.world.policy === "baseline" && <span className="muted" title="The rule from before grant standing: any first contact may grant">Policy: baseline</span>}
      {sim.world.policy === "witness" && <span className="muted" title="Witnessed history (device-enrollment.md)">Policy: witness</span>}
      <span className="spacer" />
      <span className="clock">{clock(sim.world.t)}</span>
      {[1, 24, 72].map((h) => (
        <button key={h} onClick={() => sim.act(`advanced ${h}h`, (w) => w.advance(h))}>+{h}h</button>
      ))}
    </header>
  );
}

function Narration() {
  const sim = useSim();
  const run = sim.run;
  const last = run.results[run.results.length - 1];
  const upcoming = run.scenario.steps[run.next];
  if (!run.scenario.steps.length) return <div className="narration muted">{run.scenario.summary}</div>;
  return (
    <div className="narration">
      {!last && <p><strong>{run.scenario.title}.</strong> {run.scenario.summary}</p>}
      {last && (
        <>
          <p><strong>{last.step.title}.</strong> {last.step.narration}</p>
          <ul className="checks">
            {last.checks.map((c, i) => <li key={i} className={c.ok ? "ok" : "bad"}>{c.ok ? "✓" : "✗"} {c.label}</li>)}
            {last.violations.map((v, i) => <li key={`v${i}`} className="bad">✗ invariant: {v}</li>)}
          </ul>
        </>
      )}
      {upcoming && <p className="muted small">Next: {upcoming.title}</p>}
      {run.done && <p className="muted small">Scenario complete. Keep going by hand: every control still works.</p>}
    </div>
  );
}

function Sandbox() {
  const sim = useSim();
  const w = sim.world;
  const [name, setName] = useState("");
  const [device, setDevice] = useState("phone");
  const [account, setAccount] = useState("");
  return (
    <details className="panel sandbox" open>
      <summary>Sandbox</summary>
      <div className="row">
        <input placeholder="New account (e.g. dana)" value={name} onChange={(e) => setName(e.target.value.replace(/[^a-z0-9]/g, ""))} />
        <button
          disabled={!name || w.registry.has(`did:plc:${name}`)}
          onClick={() => {
            sim.act(`created ${name}`, (w) => w.install(w.account(name), "phone"));
            setName("");
          }}
        >
          Add account + phone
        </button>
      </div>
      <div className="row">
        <select value={account} onChange={(e) => setAccount(e.target.value)}>
          <option value="">Account…</option>
          {accounts(w).map((d) => <option key={d} value={d}>{short(d)}</option>)}
        </select>
        <input placeholder="device" value={device} onChange={(e) => setDevice(e.target.value.replace(/[^a-z0-9-]/g, ""))} />
        <button
          disabled={!account || !device}
          title="Installs without linking: members' apps that know this account won't share with it"
          onClick={() => sim.act(`${short(account)} installed ${device} unlinked`, (w) => w.install(account, device))}
        >
          Install unlinked
        </button>
      </div>
    </details>
  );
}

function Grid() {
  const w = useSim().world;
  const accts = accounts(w);
  if (!accts.length) return <p className="muted">Pick a scenario and press Start, or add an account.</p>;
  return (
    <div className="grid">
      {accts.map((d) => (
        <div key={d} className="account">
          <h3>{short(d)} <span className="muted small">@{w.pdsOf.get(d)!.name}</span></h3>
          <div className="cards">
            {installationsOf(w, d).map((i) => <NodeCard key={i.id} inst={i} />)}
          </div>
        </div>
      ))}
    </div>
  );
}
