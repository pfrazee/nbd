# PEEP prototype

Several installations of several accounts running PEEP against an emulated PDS and Spaces host, in one deterministic in-memory simulation ([TODO-18](../TODOs.md#todo-18)). Unlike the [Python model](../model/README.md), each installation sees only what it verifies from repos when it syncs, so partial views and delayed observations are real. It is informative: where it and the specification disagree, one of them is wrong.

## Running

```bash
npm install
npm test
```

`npm test` runs the crypto vectors, the ten scenarios, random walks in two modes, and a check that the trace fixtures still regenerate. Longer walks: `PEEP_WALKS=300 PEEP_STEPS=40 npx vitest run test/fuzz.test.ts`.

`npm run dev` serves the UI at <http://localhost:5199>. Pick a scenario and press **Start**, then **Next step**; the narration says what to notice and checks it. Every control keeps working after a scenario ends, and the URL (`?scenario=swap-missed&step=6`) reproduces the exact state. `npm run build` produces a static site in `dist/`.

The **Trust** tab is the heart of it: rows are installations, columns are every device ever published, and each cell is that installation's own decision, so a missed phone swap shows up as one row holding (⏳) while the others accept.

## Layout

- `src/protocol/`: the client, free of UI code. `crypto.ts` composes the `peep-hpke-v1` HPKE profile from noble primitives, checked against the RFC 9180 test vector for that suite; `trust.ts` ports `SpecClient` (first use, approvals with the live-binding rule, revocation, holds); `grants.ts` implements G1–G5 and A1–A7; `installation.ts` runs the sync loop.
- `src/world/`: the emulated PDS (signed, timestamped commits, create-only app sessions, one-off delete authorizations), Spaces host (membership, configuration, short-lived credentials), `adversary.ts` (a malicious PDS withholding commits from, or signing forged snapshots for, chosen installations), and `World`, which adds the clock, per-installation network lag, backups, and user and attacker actions.
- `src/sim/`: narrated scenarios with expectations; an invariant monitor ported from `model/test_walks.py`, judged on each installation's own observations; and `fuzz.ts`, random walks with shrinking over user, attacker, network, and malicious-PDS actions.
- `traces/`: shared-view walks recorded as public-repo operations plus the viewer's decisions after each step. `model/test_traces.py` replays them through `SpecClient`, so the prototype and the model must agree exactly. Regenerate with `PEEP_WRITE_TRACES=1 npx vitest run test/traces.test.ts`.
- `src/ui/`: a store over one simulation (`sim.ts`), node cards that each render one installation's own state with the [TOFU flow](../ux-flows/tofu.md) copy, and the inspector (trust matrix, key holders, repos, log).

## Simplifications

- A repo enumeration is the whole record map at a signed commit: no MST, CIDs, DID documents, or key rotation.
- Credentials are a virtual-time expiry gated on a live session and eligible membership; no delegation tokens or HTTP signatures.
- Installations sync whenever the world settles while they are online. Network lag is per installation: it reads every repo as it was that many hours ago. Host reads are never delayed.
- Keys and nonces come from a seeded generator so runs replay. Never do this outside a simulation.
- Records only; no blobs.

## Status

M4: scenarios 1–10, headless in tests and playable in the UI: create and join; phone swap seen; phone swap missed by an offline contact; takeover at an honest PDS; a removed device's key during a hold; first-contact substitution by a malicious PDS; a reset hidden from the account's own devices; divergent histories; total device loss with a stale backup; a removed member keeping the key. The adversary panel drives the same attacks by hand, plus network lag, copied keys, and backups. Random walks cover both a shared view, cross-checked against the Python model through the trace fixtures, and lag, forged views, offline installations, and backups, which the model cannot express. Not covered: mobile resource budgets, background issuance on real platforms, and removal on real PDSes ([TODO-16](../TODOs.md#todo-16)), which need devices and servers.
