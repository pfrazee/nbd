# NBD prototype

Several installations of several accounts running NBD against an emulated PDS and Spaces host, in one deterministic in-memory simulation ([TODO-18](../TODOs.md#todo-18)). Unlike the [Python model](../model/README.md), each installation sees only what it verifies from repos when it syncs, so partial views and delayed observations are real. It is informative: where it and the specification disagree, one of them is wrong.

## For reviewers

### Running it

You need Node.js 20 or later. From this directory:

```bash
npm install
```

```bash
npm run dev
```

Open <http://localhost:5199>, pick a scenario from the menu, and press **Start**, then **Next step**. Each step narrates what to notice and shows its checks passing or failing, along with any invariant or goal violations. When a scenario ends, every control keeps working, so you can continue by hand. The URL records the scenario and step: `http://localhost:5199/?scenario=old-key&step=5` opens scenario 5 at step 5, so links can be shared between reviewers running it locally.

The **Trust** tab is the most useful view: rows are installations, columns are every device ever published, and each cell is that installation's own decision (● own, ✓ accepted, ⏳ held, ✕ revoked, ? unlinked). Disagreements between installations, such as one holding while another accepts, are visible at a glance. **Keys** shows who holds each space key and who granted it, **Repos** shows what each repo actually contains, and **Log** shows events, grant decisions, and violations. The **Sandbox** panel adds accounts and devices; the **Adversary and network** panel adds lag, malicious-PDS behavior, copied keys, takeovers, and backups.

To run every check instead:

```bash
npm test
```

### The UX app

A second app, Lantern, shows the [Relaxed](../ux-flows/relaxed.md) and [Paranoid](../ux-flows/paranoid.md) flows as a user would see them, drawn from the same simulation. With `npm run dev` running, open <http://localhost:5199/ux.html> for the device wall: one framed device per installation, each with its own inbox, spaces, device lists, notices, and alarms. Tap through them to post, join, invite, link and remove devices; the controls under each device and in the top bar take devices offline, add people and unlinked devices, and advance time, and the bar switches between Relaxed and Paranoid copy. In development, `window.nbdWorld` is the wall's live world.

<http://localhost:5199/ux.html?figures> lists the storyboard figures used in the flow documents, and `?figure=<id>` opens one. Each figure is a script of world actions with panels that show one device at one point in it, so a panel can only show a hold, notice, or lock state the protocol actually produced; `npm test` checks every panel's expectations. To regenerate the images in `ux-flows/images/` after changing a figure or the protocol (the first time, run `npx playwright install chromium`):

```bash
npm run capture
```

Pass figure ids, such as `npm run capture paranoid-adding-a-device`, to capture only those.

### Goals and where to see them

Each [security goal](../security-goals.md) and non-goal maps to the scenarios or tests that exercise it. Scenarios are in the UI's menu; tests are under `test/`.

| Goal | Scenarios | Tests |
| --- | --- | --- |
| 1. Confidentiality from outsiders | 1 (servers store only ciphertext: see **Repos**) | `crypto.test.ts` |
| 2. No silent device addition after first contact | 2 (a linked device is accepted), 4 (a takeover's device is held), 9 (an unlinked device is declined) | random walks: acceptance needs an approval path, an import, or an elapsed hold |
| 3. Time to stop a takeover | 4, 5 (a removed device's key does not end the hold), 11 (eager pinning) | `disclosure.test.ts` |
| 4. Removed devices stop receiving keys | 2, 10 | `disclosure.test.ts` (no grant to a removed device), `infra.test.ts` (migration) |
| 5. A stolen device cannot remove the others | none | enforced by the emulated PDS: app sessions cannot delete device records (`src/world/pds.ts`) |
| 6. The account holder learns of every device change | 2, 4, 12 | `disclosure.test.ts` (the revoked-signer gap is notified) |
| 7. Detection after the fact | 6, 7, 8 | |

| Non-goal | Scenarios | Tests |
| --- | --- | --- |
| 1. First contact | 6, 11 | |
| 2. A malicious PDS hiding a reset from its own user | 7 | |
| 3. Malicious host decisions | | `host.test.ts` (a changed commitment is rejected and alarmed; the host can deny service, not substitute a key) |
| 4. Members | 10, 12 | `infra.test.ts` (a backend passing ciphertext to a removed member) |
| 5. Forward secrecy and post-compromise security | 12 (the thief keeps the old key) | |
| 6. Malicious application code | not modeled | |
| 7. Bounded freshness | 3, 8 | `world.test.ts` (network lag) |
| 8. Total key loss | | `archive.test.ts` |

### What the checks enforce

The goal-level check (`src/sim/disclosure.ts`) judges every grant from an honest installation against the world's ground truth: who really controls each device, when it appeared, and which keys were copied. It ignores the clients' own reasoning. A grant to an attacker-controlled device must follow first contact, an elapsed 72-hour hold, an approval by a compromised device while the account still had a device the attacker does not control (the documented revoked-signer gap), or an approval by a live attacker device the issuer already accepted. No grant may go to a device the issuer's own view shows removed. The invariant monitor (`src/sim/invariants.ts`) checks each installation's trust decisions against its own observations: the single-root rule, approval closure, re-enrollment holds, justified acceptance and revocation, views that never roll back, and hold credit that never exceeds real time.

Both run around every scenario step and every random-walk step. `test/disclosure.test.ts` shows the goal check flagging forbidden disclosures, and `node test/mutate.mjs --all` breaks thirteen trust rules one at a time to show the tests catch each.

### What it does not model

- Cryptographic security against a symbolic attacker: the simulations test trust logic, not secrecy proofs.
- Real atproto repos: an enumeration is a whole record map at a signed commit, with no MST, CIDs, or DID documents.
- Real Spaces credentials: a virtual-time expiry gated on a live session and membership, with no delegation tokens or HTTP Message Signatures.
- Platforms: resource budgets, background issuance on phones, key storage, and removal on real PDSes ([TODO-16](../TODOs.md#todo-16)).
- Malicious application code, and blobs.

## Running the checks

`npm test` runs the crypto vectors, the twelve scenarios, random walks in two modes, focused tests (publication, archive reading and key loss, host integrity and membership, multiple spaces, backends, key rotation and migration, imports, network lag, the disclosure check, starting over after total device loss), a check that the trace fixtures still regenerate, and every UX figure's panel expectations. Longer walks: `NBD_WALKS=300 NBD_STEPS=40 npx vitest run test/fuzz.test.ts`. `node test/mutate.mjs --all` breaks one trust rule at a time and reports whether any test notices; every mutation should be caught. `npm run build` produces a static site in `dist/`.

## Layout

- `src/protocol/`: the client, free of UI code. `crypto.ts` composes the `nbd-hpke-v1` HPKE profile from noble primitives, checked against the RFC 9180 test vector for that suite; `trust.ts` ports `SpecClient` (first use, approvals with the live-binding rule, revocation, holds); `grants.ts` implements G1–G5 and A1–A7, including archive mode; `publish.ts` and `installation.ts` implement the publication state machine P1–P8; `installation.ts` runs the sync loop and pins every member of its spaces (a lazy mode exists only to show what eager pinning prevents).
- `src/world/`: the emulated PDS (signed, timestamped commits, create-only app sessions, one-off delete authorizations, key rotation, migration), Spaces host (membership, configuration, short-lived credentials, and tampering for tests), `adversary.ts` (a malicious PDS withholding commits from, or signing forged snapshots for, chosen installations), and `World`, which adds the clock, per-installation network lag, write faults, backups, provenance for the goal check, and user and attacker actions.
- `src/sim/`: narrated scenarios with expectations; the invariant monitor; the goal-level disclosure check; and `fuzz.ts`, random walks with shrinking over two spaces and user, attacker (takeover, devices added with the password, copied keys, recreated records), network (lag, offline, write faults), clock (backward moves), host (tampering, membership changes), infrastructure (key rotation, migration), and malicious-PDS (substitution, hidden reset, forks, rollback) actions.
- `traces/`: shared-view walks recorded as public-repo operations plus the viewer's decisions after each step. `model/test_traces.py` replays them through `SpecClient`, so the prototype and the model must agree exactly. Regenerate with `NBD_WRITE_TRACES=1 npx vitest run test/traces.test.ts`.
- `src/ux/`: the UX app. `model.ts` turns an installation's state into screen models, `screens.tsx` and `frames.tsx` draw them, `copy.ts` quotes the flow documents, `figures/` holds the storyboard scripts, and `wall.tsx` is the device wall. `scripts/capture.mjs` screenshots the figures with Playwright.
- `src/ui/`: a store over one simulation (`sim.ts`), node cards that each render one installation's own state with the [Paranoid flow](../ux-flows/paranoid.md) copy, and the inspector (trust matrix, key holders, repos, log).

## Simplifications

- A repo enumeration is the whole record map at a signed commit: no MST, CIDs, or DID documents. Key rotation updates a registry of current keys; commits under an old key go unverified rather than being checked against DID history.
- Credentials are a virtual-time expiry gated on a live session and eligible membership; no delegation tokens or HTTP signatures.
- Installations sync whenever the world settles while they are online. Network lag is per installation: it reads every repo as it was that many hours ago. Host reads are never delayed.
- Keys and nonces come from a seeded generator so runs replay. Never do this outside a simulation.
- Records only; no blobs.
