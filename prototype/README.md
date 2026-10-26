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

Each [security goal](../README.md#goals) and non-goal maps to the scenarios or tests that exercise it. Scenarios are in the UI's menu; tests are under `test/`.

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

Both run around every scenario step and every random-walk step. `test/disclosure.test.ts` shows the goal check flagging forbidden disclosures, and `node test/mutate.mjs --all` breaks trust rules one at a time to show the tests catch each.

### The inviters proposal

The [inviters proposal](../proposal-inviters.md) is implemented as a world policy: `new World(seed, { policy: "inviters" })`, or `policy: "inviters"` on a scenario. The default is `"baseline"`, under which nothing below happens and every other scenario, test, trace, and mutation behaves as before. It follows `InviterClient` in [`model/nbd_trust.py`](../model/nbd_trust.py), including the two refinements the model found ([findings](../model/README.md#what-the-inviters-variant-found)).

- **Grant standing** (`Trust.standing(b, space)` in `trust.ts`) is checked by `authorizeExchange` only for the issuer role: without it, the result is `INCOMPLETE` with "first-contact hold". A binding has standing when it is the installation's own account's, re-enrolled, held (72 hours credited to its own first-contact hold), vouched in that space, or approved by a binding with standing there. Every binding accepted by first use, approval, or an invite record starts its own hold; a revoked binding's hold stops crediting and keeps its credit. Under this policy an installation credits time at the start of every sync, before any observation can revoke.
- **Invites** (`Installation.invite`) observe the invited account, pin it on first use if the installation has no pin for it, and publish a signed `com.example.nbd.invite` record in the inviter's own repo for the space, then admit the account. The record vouches only for bindings first met in making it. If the record can't be published, the account isn't admitted.
- **Other own installations** read invite records in every space where their account's PDS holds a repo for it, and take a vouch only from a record signed by an own device they accepted (even if since removed), for an account they have never pinned. They then keep that account's pin current like any member's. Imports carry a vouch only to an installation with no pin for the account, and first-contact holds as credited time.
- **The goal check** allows the first-contact excuse only when the issuer's account vouched for that device in that space, at an invite where the inviting installation first met the account, and the issuing installation first knew the account no earlier than that invite. Otherwise the device must have appeared at least 72 hours earlier, or an existing approval excuse applies.
- **The invariant monitor** checks that every accepted binding has its own first-contact hold, credited no faster than real time since the device appeared, never falling, and frozen once revoked; that each new vouch comes from an invite by the installation's account into that space that first met the account, and reaches only an installation that didn't know the account when the step began; and that new standing is explained by a vouch in that space, an approval in the installation's verified view from a signer with standing there, or an elapsed hold.

The proposal's cases map to scenarios (13–18 in the UI) and tests:

| Proposal case | Scenario | Tests |
| --- | --- | --- |
| Carol joined before the takeover: holds | 13 (Alice holds) | |
| Dave joins after the takeover and first meets the attacker's device: holds | 13 `inviters-newcomer` | `inviters.test.ts` (the same steps disclose under the baseline; a newcomer granting at once is flagged by the goal check) |
| A member's app first syncs Bob late: holds from its own first sight | 17 `inviters-offline` | `inviters.test.ts` (each clock domain credits its own hold) |
| Dave first met the taken-over Bob by inviting him elsewhere (case 1) | 14 `inviters-cross-space` | mutation "vouch scoped account-wide" |
| Alice never met Bob and invites him after the takeover: the remaining exposure | 18 `inviters-residual` | `inviters.test.ts` (the goal check accepts it) |
| Alice met the taken-over Bob in another space, then invites him (case 2) | 15 `inviters-known` (Carol) | mutation "known account vouched" |
| Alice knew Bob before the takeover and invites him, or invites him again (case 2) | 15 `inviters-known` (Alice) | `inviters.test.ts` (records vouch only at first contact) |
| Per-client timing (case 3) | 17 `inviters-offline` | `inviters.test.ts` |
| A vouch reaching an installation that already pins the account (case 4) | | `inviters.test.ts` (neither the record nor an import ends the hold); mutations "import ends a hold", "invite records override pins" |
| A device linked during its signer's hold, then the signer removed (model finding) | 16 `inviters-linked-phone` | mutations "approved devices start no hold", "hold keyed to account instead of binding", "removals observed before crediting" |
| Removal freezes credit; a device linked while the signer had standing keeps it (model finding) | 16 | `inviters.test.ts`; mutations "removal erases credit", "revoked bindings keep crediting" |
| A malicious PDS substitutes devices for a newcomer | | random walks under inviters with forged views |
| Verified-only spaces, hold notices, auditing invite records that name one's own account | not modeled | |

`test/fuzz.test.ts` runs inviters walks in both modes: four accounts, Club (Alice and Bob) and Garden (Carol and Dave), so Alice's app starts out never having met Carol or Dave, plus invites by each space's admin and joins only by admitted accounts.

#### Inviters traces

`traces-inviters/` holds shared-view inviters walks, regenerated and checked like `traces/` by `test/traces.test.ts`. Each fixture has the same shape as a baseline trace, plus:

- top level: `"policy": "inviters"` and `"spaces": ["A", "B"]` (A is Club, administered by Alice; B is Garden, administered by Carol). The viewer is Alice's first phone.
- an op `{"op": "invite", "by": [account, deviceId], "space": "A" | "B", "account": name, "bindings": [[account, deviceId], ...], "vouched": bool}` for each published invite record, in order, after the step's repo ops and before its `wait` and `skew` ops. `bindings` are the invited account's bindings the inviter accepted at the invite; `vouched` is true only if it first met them in making it. Step 0 holds the setup: four phones, then Alice inviting Bob to A and Carol inviting Dave to B.
- per step, `tracked`: the accounts (including Alice) whose repos the viewer follows: members of spaces it joined, accounts it invited, and accounts it adopted from an invite record. Only these have been through first use; replay should query `accepted`, `holds`, and standing only for them, since querying another account would pin it.
- per step, `standing`: for each space label, the bindings the viewer may grant that space's key to now.

To replay one: add, approve, delete, wait, and skew as for baseline traces. For an invite `by` the viewer, call the viewer's `invite(space, account)` (its `vouched` should match); for any other, append the record as given (inviter is `by`'s account). Every invite in these walks by one of Alice's devices comes from a device the viewer accepted, so the viewer may take any such record's vouch.

### What it does not model

- Cryptographic security against a symbolic attacker: the simulations test trust logic, not secrecy proofs.
- Real atproto repos: an enumeration is a whole record map at a signed commit, with no MST, CIDs, or DID documents.
- Real Spaces credentials: a virtual-time expiry gated on a live session and membership, with no delegation tokens or HTTP Message Signatures.
- Platforms: resource budgets, background issuance on phones, key storage, and removal on real PDSes ([TODO-16](../TODOs.md#todo-16)).
- Malicious application code, and blobs.

## Running the checks

`npm test` runs the crypto vectors, the eighteen scenarios, random walks in two modes under each policy, focused tests (publication, archive reading and key loss, host integrity and membership, multiple spaces, backends, key rotation and migration, imports, network lag, the disclosure check, starting over after total device loss, the inviters policy), a check that both sets of trace fixtures still regenerate, and every UX figure's panel expectations. Longer walks: `NBD_WALKS=300 NBD_STEPS=40 npx vitest run test/fuzz.test.ts`. `node test/mutate.mjs --all` breaks one trust rule at a time and reports whether any test notices; every mutation should be caught. `npm run build` produces a static site in `dist/`.

## Layout

- `src/protocol/`: the client, free of UI code. `crypto.ts` composes the `nbd-hpke-v1` HPKE profile from noble primitives, checked against the RFC 9180 test vector for that suite; `trust.ts` ports `SpecClient` (first use, approvals with the live-binding rule, revocation, holds); `grants.ts` implements G1–G5 and A1–A7, including archive mode; `publish.ts` and `installation.ts` implement the publication state machine P1–P8; `installation.ts` runs the sync loop and pins every member of its spaces (a lazy mode exists only to show what eager pinning prevents).
- `src/world/`: the emulated PDS (signed, timestamped commits, create-only app sessions, one-off delete authorizations, key rotation, migration), Spaces host (membership, configuration, short-lived credentials, and tampering for tests), `adversary.ts` (a malicious PDS withholding commits from, or signing forged snapshots for, chosen installations), and `World`, which adds the clock, per-installation network lag, write faults, backups, provenance for the goal check, and user and attacker actions.
- `src/sim/`: narrated scenarios with expectations; the invariant monitor; the goal-level disclosure check; and `fuzz.ts`, random walks with shrinking over two spaces and user, attacker (takeover, devices added with the password, copied keys, recreated records), network (lag, offline, write faults), clock (backward moves), host (tampering, membership changes), infrastructure (key rotation, migration), and malicious-PDS (substitution, hidden reset, forks, rollback) actions.
- `traces/`: shared-view walks recorded as public-repo operations plus the viewer's decisions after each step. `model/test_traces.py` replays them through `SpecClient`, so the prototype and the model must agree exactly. `traces-inviters/` does the same for the inviters policy ([format](#inviters-traces)). Regenerate both with `NBD_WRITE_TRACES=1 npx vitest run test/traces.test.ts`.
- `src/ux/`: the UX app. `model.ts` turns an installation's state into screen models, `screens.tsx` and `frames.tsx` draw them, `copy.ts` quotes the flow documents, `figures/` holds the storyboard scripts, and `wall.tsx` is the device wall. `scripts/capture.mjs` screenshots the figures with Playwright.
- `src/ui/`: a store over one simulation (`sim.ts`), node cards that each render one installation's own state with the [Paranoid flow](../ux-flows/paranoid.md) copy, and the inspector (trust matrix, key holders, repos, log).

## Simplifications

- A repo enumeration is the whole record map at a signed commit: no MST, CIDs, or DID documents. Key rotation updates a registry of current keys; commits under an old key go unverified rather than being checked against DID history.
- Credentials are a virtual-time expiry gated on a live session and eligible membership; no delegation tokens or HTTP signatures.
- Installations sync whenever the world settles while they are online. Network lag is per installation: it reads every repo as it was that many hours ago. Host reads are never delayed.
- Keys and nonces come from a seeded generator so runs replay. Never do this outside a simulation.
- Records only; no blobs.
