# NBD trust model

An executable model of [local trust](../device-enrollment.md#local-trust) in Device Enrollment ([TODO-17](../TODOs.md#todo-17)), with adversarial tests. It is informative: where the model and the prose disagree, one of them is wrong and should be fixed.

## What it models

- **Repos.** Each account's present device records and approval records, as an enumeration at a verified commit would prove them. Deleting a device record revokes it.
- **Grants.** Records in the issuer's space repo naming issuer, recipient, and space. The model never decrypts, so a grant may carry garbage, as a third party could not tell.
- **Membership.** The host's current eligible accounts per space.
- **`SpecClient`,** the specified design: trust on first use under the single-root rule, approvals afterwards with acceptance persisted alongside its evidence, revocation by observed absence, and a re-enrollment hold bound to its exact candidate for clients that knew the account.

There is no cryptography. A record signed by a binding is valid exactly when its creator held that binding's key, and tests create only records the creating party could sign. The model assumes one shared, current view of every repo, though each client keeps its own clock (`clock_offset`); partial views and delayed observations are left to the prototype in [TODO-18](../TODOs.md#todo-18).

## Running

From the repository root:

```bash
python3 -I -m unittest discover -s model -v
```

```bash
python3 -I model/mutation_check.py
```

```bash
NBD_WALKS=5000 NBD_STEPS=80 python3 -I -m unittest discover -s model -p test_walks.py
```

`test_traces.py` replays shared-view traces recorded by the TypeScript [prototype](../prototype/README.md), including recreated records and the viewer's clock moving back, through `SpecClient` and requires the same accepted bindings and holds after every step, so the two implementations cross-check each other.

`test_nbd_trust.py` tests `SpecClient` against the [security goals](../security-goals.md). Tests prefixed `test_limitation_` assert documented non-goals, such as root theft at first contact and a new contact meeting an account just after a takeover. `test_walks.py` runs seeded random walks, 1,500 by default: repo writes of every kind, elapsed time, queries, and backups exchanged between two of Alice's installations with different clocks, checking invariants after every step and shrinking any failure to a minimal trace. Walks may write any record with any key, as an attacker holding every key could, so their invariants are structural: acceptance only through approval paths, imports, or an elapsed hold; first use matching the single-root rule; holds credited no faster than real time and ending only for a stated reason; revocation, takeover alarms, and re-enrollment once their conditions hold. The docstring lists them. The mutation check breaks one `SpecClient` rule at a time and reports whether any test notices; every mutation should be caught, and the walks alone catch all of them.

## What it found

- **Single-root rule.** The prose required exactly one binding with no incoming approval. Approval records outlive deleted devices, so an honest reset that kept old approvals had two roots and could never complete. The rule now ignores roots that reach only deleted devices.
- **Durable approvals.** An earlier client recomputed acceptance from the approvals currently published, so deleting an approval record removed an accepted device. Acceptance is now persisted with its evidence, as the specification requires.
- **Holds bound to candidates.** An earlier client keyed holds by account, so a replacement candidate inherited an almost-expired hold. Holds now bind to the exact candidate, a replaced candidate's members are revoked, and imports merge holds only for identical candidates.
- **Anchors and witnesses.** Protecting newcomers with anchors drew repeated findings; the last showed one malicious PDS can manufacture its own witness. NBD accepted first-contact exposure instead; see below.
- **Takeover alarm.** The client revoked its own binding when its record disappeared but raised no alarm, despite the [required alarm](../device-enrollment.md#re-enrollment). It now alarms, including when the revocation arrives by import rather than direct observation.
- **Leftover approvals.** An attacker with create access could publish approvals from two of its own devices to an honest one; after the user deleted those devices, both deleted roots still reached the honest device, and new contacts declined it forever. Bindings without a present record now carry no authority of their own. A later review showed that leftover cycles (`M1 → M2 → M1 → Bob`) still left no root, so only present records can be roots now, and without one every record-less binding is a starting point.
- **Deleted intermediates.** Approval validation required each target's record to be present, so a contact offline while an account linked `B0 → B1 → B2` and removed `B1` never accepted `B2`. A target proven absent, or one the client had already revoked, is now accepted as an approval signer while staying revoked for grants; records must be published with their first approval so absence means deletion.
- **Stale holds.** Importing a backup taken during a hold brought the hold back after enrollment completed, and deleting the candidate left its hold pending. Holds now end on completion or cancellation, and no import brings them back while their reason for ending still applies. The fix first ended holds before checking imported bindings against the repo, so an older backup's deleted device restarted an active hold; imports now sync first.
- **Removed keys ended holds.** Random walks found that once every device of an account was revoked, an approval signed afterwards with a removed device's key, directly or through a key with no record, accepted the new device and ended the hold, so an attacker holding an old device's key skipped it. While every accepted binding of an account is revoked, approvals now accept nothing for it. A contact that missed an honest replacement before the old device's removal holds the new device too; linking flows therefore never prompt removing the replaced device.
- **Hold clocks.** Imports kept the earliest hold start time, comparing timestamps across installations whose clocks differ, so a clock 72 hours ahead finished a hold at once. Holds now carry credited elapsed time and never compare clocks.

## Rejected designs

`nbd_trust.py` keeps three rejected designs for comparison: `WarnOnlyClient`, `AccountWideAnchorClient`, and `ScopedWitnessClient`, which also holds their shared machinery. `test_variants.py` tests them, and [COMPARISON.md](COMPARISON.md) runs all four designs against the same scenarios. Regenerate its table with:

```bash
python3 -I model/compare.py
```
