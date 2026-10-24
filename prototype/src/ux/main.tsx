import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { figures } from "./figures";
import { Storyboard } from "./Storyboard";
import { Wall } from "./wall";
import "./ux.css";

function App() {
  const q = new URLSearchParams(window.location.search);
  const f = figures.find((x) => x.id === q.get("figure"));
  if (f) return <Storyboard figure={f} />;
  if (!q.has("figures")) return <Wall />;
  return (
    <div className="index">
      <h1>Lantern: NBD UX flows</h1>
      <a href="?">Device wall</a>
      {figures.map((x) => <a key={x.id} href={`?figure=${x.id}`}>{x.mode === "tofu" ? "TOFU" : "Relaxed"} · {x.number}. {x.title}</a>)}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
