# PEEP prototype

Several installations of several accounts running PEEP against an emulated PDS and Spaces host, in one deterministic in-memory simulation ([TODO-18](../TODOs.md#todo-18)). Unlike the [Python model](../model/README.md), each installation sees only what it verifies from repos when it syncs, so partial views and delayed observations are real. It is informative: where it and the specification disagree, one of them is wrong.

## Running

```bash
npm install
npm test
```

`npm run dev` serves the UI at <http://localhost:5199> (a placeholder until M2).

## Layout

- `src/protocol/`: the client, free of UI code. `crypto.ts` composes the `peep-hpke-v1` HPKE profile from noble primitives, checked against the RFC 9180 test vector for that suite; `trust.ts` ports `SpecClient` (first use, approvals with the live-binding rule, revocation, holds); `grants.ts` implements G1–G5 and A1–A7; `installation.ts` runs the sync loop.
- `src/world/`: the emulated PDS (signed commits, create-only app sessions, one-off delete authorizations), Spaces host (membership, configuration, short-lived credentials), and `World`, which adds the clock and user and attacker actions.
- `src/sim/`: narrated scenarios with expectations, and an invariant monitor ported from `model/test_walks.py`, judged on each installation's own observations.

## Simplifications

- A repo enumeration is the whole record map at a signed commit: no MST, CIDs, DID documents, or key rotation.
- Credentials are a virtual-time expiry gated on a live session and eligible membership; no delegation tokens or HTTP signatures.
- Installations sync whenever the world settles while they are online; no network delays yet.
- Keys and nonces come from a seeded generator so runs replay. Never do this outside a simulation.
- Records only; no blobs.

## Status

M1: protocol core, emulated world, and scenarios 1–5 headless (create and join; phone swap seen; phone swap missed by an offline contact; takeover at an honest PDS; a removed device's key during a hold). Next: the multi-node UI (M2), then adversary controls and story mode (M3).
