import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

function App() {
  return <p>PEEP prototype: the UI arrives in M2. Run the headless scenarios with npm test.</p>;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
