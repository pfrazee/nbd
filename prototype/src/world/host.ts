// Emulated Spaces host (core.md#trusted-host-state). It decides membership,
// keeps configuration and membership histories by reference, and issues
// short-lived read credentials only to eligible accounts with a live PDS
// session (the delegation-token read policy NBD requires, simplified).

import { ref } from "../protocol/encoding";
import { type Configuration, type Did, type Membership, asCbor } from "../protocol/types";

export const CREDENTIAL_TTL = 10 / 60; // hours

type SpaceState = {
  uri: string;
  name: string;
  admin: Did;
  config: Configuration;
  members: Map<Did, Membership>;
  history: Map<string, Configuration | Membership>;
};

export class Host {
  readonly spaces = new Map<string, SpaceState>();
  private counter = 0;

  constructor(readonly name: string) {}

  /** Allocate a URI so the creator can bind its key commitment to it. */
  reserveUri(): string {
    return `space://${this.name}/${++this.counter}`;
  }

  createSpace(admin: Did, uri: string, name: string, keyId: string, commitment: Uint8Array): string {
    if (this.spaces.has(uri)) throw new Error(`host: ${uri} exists`);
    const config: Configuration = {
      version: 1, kind: "configuration", space: uri, revision: 1, grantProfile: "nbd-hpke-v1",
      keyId, commitment, maxEncryptedBlobBytes: 16_777_216,
    };
    const st: SpaceState = { uri, name, admin, config, members: new Map(), history: new Map() };
    st.history.set(ref(asCbor(config)), config);
    this.spaces.set(uri, st);
    this.setMembership(admin, uri, admin, true);
    return uri;
  }

  private space(uri: string): SpaceState {
    const s = this.spaces.get(uri);
    if (!s) throw new Error(`host: no space ${uri}`);
    return s;
  }

  setMembership(by: Did, uri: string, account: Did, eligible: boolean): Membership {
    const s = this.space(uri);
    if (by !== s.admin) throw new Error("host: only the admin manages membership");
    const prev = s.members.get(account);
    const m: Membership = {
      version: 1, kind: "membership", space: uri, account, revision: (prev?.revision ?? 0) + 1, eligible,
    };
    s.members.set(account, m);
    s.history.set(ref(asCbor(m)), m);
    return m;
  }

  /** A malicious host replaces the creation-fixed key ID or commitment,
   * which an honest host refuses (core.md#trusted-host-state). */
  tamper(uri: string, change: { keyId?: string; commitment?: Uint8Array }): void {
    const s = this.space(uri);
    s.config = { ...s.config, ...change, revision: s.config.revision + 1 };
    s.history.set(ref(asCbor(s.config)), s.config);
  }

  // Authenticated reads.
  spaceName(uri: string): string {
    return this.space(uri).name;
  }
  admin(uri: string): Did {
    return this.space(uri).admin;
  }
  configuration(uri: string): Configuration {
    return this.space(uri).config;
  }
  membership(uri: string, account: Did): Membership | null {
    return this.space(uri).members.get(account) ?? null;
  }
  members(uri: string): Did[] {
    return [...this.space(uri).members.values()].filter((m) => m.eligible).map((m) => m.account);
  }
  /** Every account with a membership decision, eligible or not. */
  knownAccounts(uri: string): Did[] {
    return [...this.space(uri).members.keys()];
  }
  byRef(uri: string, r: string): Configuration | Membership | null {
    return this.space(uri).history.get(r) ?? null;
  }

  /** A credential lasting CREDENTIAL_TTL, for an eligible account whose PDS
   * vouches for a live session. Returns the expiry, or null. */
  issueCredential(uri: string, account: Did, sessionAlive: boolean, now: number): number | null {
    const m = this.space(uri).members.get(account);
    if (!m?.eligible || !sessionAlive) return null;
    return now + CREDENTIAL_TTL;
  }
}
