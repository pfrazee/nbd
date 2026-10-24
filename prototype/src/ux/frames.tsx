// Device frames for storyboard panels and the device wall.

import type { ReactNode } from "react";

function StatusBar({ dark }: { dark?: boolean }) {
  return (
    <div className={`statusbar ${dark ? "dark" : ""}`}>
      <span>9:41</span>
      <span className="status-icons">
        <span className="signal"><i /><i /><i /><i /></span>
        <span className="battery" />
      </span>
    </div>
  );
}

export function Phone({ children, dark }: { children: ReactNode; dark?: boolean }) {
  return (
    <div className="frame phone">
      <div className={`screen ${dark ? "dark" : ""}`}>
        <StatusBar dark={dark} />
        <div className="screen-body">{children}</div>
      </div>
    </div>
  );
}

export function Tablet({ children }: { children: ReactNode }) {
  return (
    <div className="frame tablet">
      <div className="screen">
        <StatusBar />
        <div className="screen-body">{children}</div>
      </div>
    </div>
  );
}

export function Laptop({ children }: { children: ReactNode }) {
  return (
    <div className="frame laptop">
      <div className="window-bar"><i /><i /><i /></div>
      <div className="window-body">{children}</div>
    </div>
  );
}
