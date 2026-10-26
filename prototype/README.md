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

The goal-level check (`src/sim/disclosure.ts`) judges every grant from an honest installation against the world's ground truth: who really controls each device, when it appeared, and which keys were copied. It ignores the clients' own reasoning. A grant to an attacker-controlled device must follow first contact, an elapsed 72-hour hold, an approval by a compromised device while the account still had a device the attacker does not control (the documented revoked-signer gap), or an approval by a live attacker device the issuer already accepted. Under the default policy, the first-contact excuse applies only to a record of the issuer's own account authorizing that device, or an approval ancestor of it, in that space ([grant standing](#grant-standing-and-invites)). No grant may go to a device the issuer's own view shows removed. The invariant monitor (`src/sim/invariants.ts`) checks each installation's trust decisions against its own observations: the single-root rule, approval closure, re-enrollment holds, justified acceptance and revocation, views that never roll back, and hold credit that never exceeds real time.

Both run around every scenario step and every random-walk step. `test/disclosure.test.ts` shows the goal check flagging forbidden disclosures, and `node test/mutate.mjs --all` breaks trust rules one at a time to show the tests catch each.

### Grant standing and invites

The specification's [grant standing](../device-enrollment.md#grant-standing) and [invites](../core.md#invites), adopted from the inviters proposal, are the world's default policy, `"inviters"`. `new World(seed, { policy: "baseline" })`, or `policy: "baseline"` on a scenario, selects the rule from before them, which any first contact could grant under; it is kept for comparison. The rule's history and the review cases it closes are in the [rationale](../rationale.md#inviters-and-grant-standing). The baseline `traces/` and their walks, the baseline random walks, and the tests that contrast the two rules pin it explicitly. Scenarios 1–12 run under the default; two changed expectations because of it: in 6 (substitution) Carol, who didn't invite Bob, holds the substitute for 72 hours before disclosing it, and in 11 (eager pinning) the lazy member's late first contact is held instead of disclosing the space. The rule follows `InviterClient` in [`model/nbd_trust.py`](../model/nbd_trust.py), including the two refinements the model found ([findings](../model/README.md#what-the-inviters-variant-found)), the revision after Astra's second review (invites that must admit, pending invites, and durable invites), and the one after the third: each record authorizes exactly what was vouched when it was made.

- **Grant standing** (`Trust.standing(b, space)` in `trust.ts`) is checked by `authorizeExchange` only for the issuer role: without it, the result is `INCOMPLETE` with "first-contact hold". A binding has standing in a space when it is the installation's own account's, re-enrolled, held (72 hours credited to its own first-contact hold), authorized in that space by a published invite or capture record of its own account, or approved by a binding with standing there. Every binding accepted by first use, approval, or an invite record starts its own hold; a revoked binding's hold stops crediting and keeps its credit. Under this policy an installation credits time at the start of every sync, before any observation can revoke.
- **Authorization** (`TrustState.authorized`, space -> bindings) comes only from the installation's own account's published records: a record's `authorizes` list counts in that record's space, and nowhere else. A record authorizes the bindings first met through it plus the listed live bindings already **vouched** (`TrustState.vouched`: first met on first use through an invite or capture by its own account) or accepted by approval, directly or through a chain, from a vouched binding, revoked or not, so a replacement phone stays authorized in the next space. A capture authorizes exactly the captured bindings. Vouches decide only what a new record may authorize: a later vouch never extends an earlier record, whether that record authorized nothing, named other devices, or was a pending invite that expired. `TrustState.admitted` (spaces each account was admitted to by own records) is kept for display only.
- **Invites** (`Installation.invite`) are refused for an account that is already a member: an invite counts only if it admits. Otherwise the installation observes the account, pins it on first use if it has no pin for it, decides what the invite authorizes, and signs the record, once (`prepareInvite`). The vouch is saved then, with the record, so a second invite prepared before the first is published still authorizes what the first vouched for. The entry goes into `inviteOutbox`, strictly first in, first out: a new record goes out at once only if the outbox is empty, and otherwise waits behind older entries; each sync resends the oldest byte for byte, stopping at the first failure; a lost acknowledgement is resolved by reading the repo back. Only once a record is published does the installation take its authorization and admit the account at the host. An entry whose account became a member meanwhile is abandoned unsent; abandoning a pending invite also ends its pending state and drops any capture queued for it. Inviting the same account to the same space again while its invite is unsent resumes that invite rather than preparing a second record.
- **Pending invites**: an invite of an account the installation never pinned and that has no device records is published with `pending: true` and no bindings, and remembered in `TrustState.pending` with time credited like a hold. The first time that installation pins the account, if the pending invite was made by this very device and has credited less than `PENDING_INVITE_TTL` (168 hours), it vouches for the devices it accepted on first use and saves a capture record (`captures`: the pending record's rkey) authorizing them in the pending invite's space. The capture is saved to the outbox and published only once its pending invite has been published by this account (it waits otherwise), and never if that invite was abandoned. Pending state never transfers, by pairing, backup, or restore, even back to the device that made it; abandonments (`TrustState.abandoned`) do, so a stale backup cannot reopen one.
- **Other own installations** read invite records in every space where their account's PDS holds a repo for it, and trust a record only if it is signed by an own device they accepted (even if since removed). An installation that never pinned the account pins a record's `authorizes` as vouched, authorized in the record's space, and then keeps that account's pin current like a member's. One that already pins the account takes a record's authorization only for bindings it holds as vouched, or has accepted by approval, directly or through a chain, from one it holds as vouched. Imports follow the same rules, merging acceptance and approvers before judging imported authorizations, and carry first-contact holds as credited time.
- **The goal check** allows the first-contact excuse only when an invite or capture record of the issuer's account for that space authorizes the attacker device or an approval ancestor of it; that device was first met through a record of the issuer's account (an invite or a capture); and the issuing installation first knew the account no earlier than that record was made. Otherwise the device must have appeared at least 72 hours earlier, or an existing approval excuse applies.
- **The invariant monitor** checks that every accepted binding has its own first-contact hold, credited no faster than real time since the device appeared, never falling, and frozen once revoked; that each new vouch comes from such a record naming that device, made no later than the installation first knew the account; that each admitted space comes from a published record that admitted the account; that a capture is published only by the device that made its pending invite; that every binding a published record authorizes was first met through it, or first met through an earlier published record of the account that its maker knew of; that every authorization an installation holds traces to a published own record for that space naming the binding, which it holds as vouched; and that new standing is explained by such an authorization, an approval in the installation's verified view from a signer with standing there, or an elapsed hold.

The proposal's cases map to scenarios (13–26 in the UI) and tests:

| Proposal case | Scenario | Tests |
| --- | --- | --- |
| Carol joined before the takeover: holds | 13 (Alice holds) | |
| Dave joins after the takeover and first meets the attacker's device: holds | 13 `inviters-newcomer` | `inviters.test.ts` (the same steps disclose under the baseline; a newcomer granting at once is flagged by the goal check) |
| A member's app first syncs Bob late: holds from its own first sight | 17 `inviters-offline` | `inviters.test.ts` (each clock domain credits its own hold) |
| Dave first met the taken-over Bob by inviting him elsewhere, then joins a space where Bob is a member (case 1) | 14 `inviters-cross-space` | `inviters.test.ts` (no invite of a member, even one a host console admitted); mutation "invite published for an existing member" |
| Alice never met Bob and invites him after the takeover: the remaining exposure | 18 `inviters-residual` | `inviters.test.ts` (the goal check accepts it) |
| Alice met the taken-over Bob in another space, then invites him (case 2) | 15 `inviters-known` (Carol) | mutation "known account vouched" |
| Alice knew Bob before the takeover and invites him, or tries to invite him again (case 2) | 15 `inviters-known` (Alice) | `inviters.test.ts` |
| Alice invited Bob into one space, then invites him into a new one: instant | 23 `inviters-second-space` | `inviters.test.ts` (an own device's later invite authorizes the vouched device); mutation "a new invite drops earlier vouches" |
| A pending invite is abandoned (a host console admitted Bob first); Bob then installs (Astra's fourth review) | | `inviters.test.ts`; mutation "abandon keeps the pending state" |
| A second invite is prepared while the first is unsent (Astra's fourth review) | | `inviters.test.ts`; mutation "vouch on publication" |
| A stale import after a pending invite was abandoned, then Bob installs (Astra's fifth review) | | `inviters.test.ts` (also: a restored device captures nothing; a capture waits for its pending record); mutations "import restores pending", "capture skips the published check" |
| Alice's laptop takes, by record or import, the phone's authorization of Bob's replacement phone (Astra's fifth review) | | `inviters.test.ts`; mutation "adoption requires a direct vouch" |
| Bob replaces his phone, then Alice invites him to a new space (Astra's fourth review) | | `inviters.test.ts`; mutation "authorizes ignores descendants" |
| Alice's phone knew Bob and invited him unvouched; after a takeover, her laptop vouches by inviting him elsewhere (Astra's third review) | 25 `inviters-late-vouch` | mutation "a later vouch extends older admissions" |
| A pending invite expired; later Alice first meets the device by inviting Bob elsewhere | 26 `inviters-expired-then-vouch` | mutation "a later vouch extends older admissions" |
| A new space with someone met as a fellow member: waits | 24 `inviters-fellow-member` | |
| Alice invites Bob before he installs: instant when he does | 20 `inviters-pending` | |
| A pending invite expires: holds | 21 `inviters-pending-expiry` | mutation "pending invites never expire" |
| A takeover enrolls the first device during the pending window: the exposure, widened | 22 `inviters-pending-takeover` | |
| Only the inviting installation captures | | `inviters.test.ts`; mutation "import restores pending" (pending state never leaves the device that made it, so the capture check on the issuing device is defense in depth) |
| An invite that fails to send is resent unchanged (Astra's repro) | 19 `inviters-retry` | mutation "a retry re-derives the record" |
| Per-client timing (case 3) | 17 `inviters-offline` | `inviters.test.ts` |
| A vouch reaching an installation that already pins the account (case 4) | | `inviters.test.ts` (neither the record nor an import ends the hold); mutations "import ends a hold", "invite records override pins" |
| A device linked during its signer's hold, then the signer removed (model finding) | 16 `inviters-linked-phone` | mutations "approved devices start no hold", "hold keyed to account instead of binding", "removals observed before crediting" |
| Removal freezes credit; a device linked while the signer had standing keeps it (model finding) | 16 | `inviters.test.ts`; mutations "removal erases credit", "revoked bindings keep crediting" |
| A malicious PDS substitutes devices for a newcomer | | random walks under inviters with forged views |
| Verified-only spaces, hold notices, auditing invite records that name one's own account | not modeled | |

`test/fuzz.test.ts` runs inviters walks in both modes: Club (Alice and Bob) and Garden (Carol and Dave), so Alice's app starts out never having met Carol or Dave, and Erin, who has an account but no device until an `install` action gives her one, so invites of her are pending. Each space's admin invites accounts that aren't members, only admitted accounts join, and write faults aimed at invite records make invites wait in the outbox and be resent.

#### Inviters traces

`traces-inviters/` holds shared-view inviters walks, regenerated and checked like `traces/` by `test/traces.test.ts`. Each fixture has the same shape as a baseline trace, plus:

- top level: `"policy": "inviters"` and `"spaces": ["A", "B"]` (A is Club, administered by Alice; B is Garden, administered by Carol). The viewer is Alice's first phone. Erin has no devices at the start.
- per step, `tracked`: the accounts (including Alice) whose repos the viewer follows: members of spaces it joined, accounts it invited, and accounts it adopted from an invite record. Only these have been through first use; replay should query `accepted`, `holds`, and standing only for them, since querying another account would pin it.
- per step, `standing`: for each space label, the bindings the viewer may grant that space's key to now.
- per step, `authorized`: for each space label, the bindings the viewer's own account's published records authorize there (`TrustState.authorized`), revoked or not.
- ops: the step's repo operations (deletions, approvals, additions) come first, then invite, flush, wait, and skew ops in the order they happened.
- an invite op: `{"op": "invite", "by": [account, deviceId], "space": "A" | "B", "account": name, "bindings": [[account, deviceId], ...], "authorizes": [[account, deviceId], ...], "pending": bool, "captures": bool, "published": bool}`. `captures` is true for a capture record. For the viewer, every attempt appears where it happened: an invite it made, or a capture it made on first meeting a pending invite's account, with `published` false if it did not go out at once: the first write failed, or older records were still unsent so it queued behind them. For any other device, a record appears once, when published, with `published` true. Step 0 holds the setup: four phones, then Alice inviting Bob to A and Carol inviting Dave to B.
- a flush op: `{"op": "flush"}` when the viewer published the oldest entry in its outbox, unchanged; `{"op": "flush", "abandoned": true}` when it dropped that entry unsent because its account had become a member of the space meanwhile (if that entry was a pending invite, its pending state ends and any capture queued for it is dropped too, with no op of its own). Resends that fail again record nothing. Inviting an account again while an invite of it to that space is still in the outbox resumes the outbox (a resend) and records no invite op of its own.

To replay one: add, approve, delete, wait, and skew as for baseline traces. For an invite op `by` the viewer with `captures` false, make the viewer's invite (its `authorizes` and `pending` should match), publishing it if `published` and otherwise saving it to the viewer's outbox; the vouch is saved at once, but the account is admitted and the authorization taken only on publication. A viewer op with `captures` true is a check: the viewer should itself have prepared that capture on first use of the account during this step, and published it if `published`. On a flush op, publish or abandon the oldest outbox entry. For any other device's op, append the record as given (inviter is `by`'s account). Every invite in these walks by one of Alice's devices comes from a device the viewer accepted, so the viewer may adopt any such record. A pending invite's window is credited from when the viewer made it, not when it was published.

### What it does not model

- Cryptographic security against a symbolic attacker: the simulations test trust logic, not secrecy proofs.
- Real atproto repos: an enumeration is a whole record map at a signed commit, with no MST, CIDs, or DID documents.
- Real Spaces credentials: a virtual-time expiry gated on a live session and membership, with no delegation tokens or HTTP Message Signatures.
- Platforms: resource budgets, background issuance on phones, key storage, and removal on real PDSes ([TODO-16](../TODOs.md#todo-16)).
- Malicious application code, and blobs.

## Running the checks

`npm test` runs the crypto vectors, the twenty-six scenarios, random walks in two modes under each policy, focused tests (publication, archive reading and key loss, host integrity and membership, multiple spaces, backends, key rotation and migration, imports, network lag, the disclosure check, starting over after total device loss, the inviters policy), a check that both sets of trace fixtures still regenerate, and every UX figure's panel expectations. Longer walks: `NBD_WALKS=300 NBD_STEPS=40 npx vitest run test/fuzz.test.ts`. `node test/mutate.mjs --all` breaks one trust rule at a time and reports whether any test notices; every mutation should be caught. `npm run build` produces a static site in `dist/`.

## Layout

- `src/protocol/`: the client, free of UI code. `crypto.ts` composes the `nbd-hpke-v1` HPKE profile from noble primitives, checked against the RFC 9180 test vector for that suite; `trust.ts` ports `SpecClient` (first use, approvals with the live-binding rule, revocation, holds); `grants.ts` implements G1–G5 and A1–A7, including archive mode; `publish.ts` and `installation.ts` implement the publication state machine P1–P8; `installation.ts` runs the sync loop and pins every member of its spaces (a lazy mode exists only to show what eager pinning prevents).
- `src/world/`: the emulated PDS (signed, timestamped commits, create-only app sessions, one-off delete authorizations, key rotation, migration), Spaces host (membership, configuration, short-lived credentials, and tampering for tests), `adversary.ts` (a malicious PDS withholding commits from, or signing forged snapshots for, chosen installations), and `World`, which adds the clock, per-installation network lag, write faults, backups, provenance for the goal check, and user and attacker actions.
- `src/sim/`: narrated scenarios with expectations; the invariant monitor; the goal-level disclosure check; and `fuzz.ts`, random walks with shrinking over two spaces and user, attacker (takeover, devices added with the password, copied keys, recreated records), network (lag, offline, write faults), clock (backward moves), host (tampering, membership changes), infrastructure (key rotation, migration), and malicious-PDS (substitution, hidden reset, forks, rollback) actions.
- `traces/`: shared-view walks under the baseline policy, recorded as public-repo operations plus the viewer's decisions after each step. `model/test_traces.py` replays them through `SpecClient`, so the prototype and the model must agree exactly. `traces-inviters/` does the same for the default policy ([format](#inviters-traces)). Regenerate both with `NBD_WRITE_TRACES=1 npx vitest run test/traces.test.ts`.
- `src/ux/`: the UX app. `model.ts` turns an installation's state into screen models, `screens.tsx` and `frames.tsx` draw them, `copy.ts` quotes the flow documents, `figures/` holds the storyboard scripts, and `wall.tsx` is the device wall. `scripts/capture.mjs` screenshots the figures with Playwright.
- `src/ui/`: a store over one simulation (`sim.ts`), node cards that each render one installation's own state with the [Paranoid flow](../ux-flows/paranoid.md) copy, and the inspector (trust matrix, key holders, repos, log).

## Simplifications

- A repo enumeration is the whole record map at a signed commit: no MST, CIDs, or DID documents. Key rotation updates a registry of current keys; commits under an old key go unverified rather than being checked against DID history.
- Credentials are a virtual-time expiry gated on a live session and eligible membership; no delegation tokens or HTTP signatures.
- Installations sync whenever the world settles while they are online. Network lag is per installation: it reads every repo as it was that many hours ago. Host reads are never delayed.
- Keys and nonces come from a seeded generator so runs replay. Never do this outside a simulation.
- Records only; no blobs.
