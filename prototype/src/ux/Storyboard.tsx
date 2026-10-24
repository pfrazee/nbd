// The storyboard layout the UX docs use: a numbered title and description,
// then numbered panels with a device frame and a caption, joined by arrows.

import { Fragment, type ReactNode } from "react";
import { type Figure, worldAt } from "./figure";

function Caption({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return <p className="caption">{parts.map((p, n) => (p.startsWith("**") ? <strong key={n}>{p.slice(2, -2)}</strong> : <Fragment key={n}>{p}</Fragment>))}</p>;
}

export function Storyboard({ figure }: { figure: Figure }) {
  const cache = new Map();
  const panels: ReactNode[] = figure.panels.map((p, n) => {
    const [w, c] = worldAt(figure, p.at, cache);
    return (
      <div className="panel" key={n}>
        <div className="panel-head">
          <span className="badge">{n + 1}</span>
          <span className="panel-label">{p.label}</span>
          <span className="panel-device">{p.device}</span>
        </div>
        <div className="panel-frame">{p.view(w, c)}</div>
        <Caption text={p.caption} />
      </div>
    );
  });
  return (
    <div className="figure" data-figure={figure.id}>
      <h1><span className="figure-number">{figure.number}</span> {figure.title}</h1>
      <p className="figure-description">{figure.description}</p>
      <div className="panels">
        {panels.map((p, n) => (
          <Fragment key={n}>
            {n > 0 && <span className="arrow">→</span>}
            {p}
          </Fragment>
        ))}
      </div>
    </div>
  );
}
