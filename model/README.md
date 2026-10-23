# PEEP trust model

An executable model of [local trust](../device-enrollment.md#local-trust) in Device Enrollment ([TODO-17](../TODOs.md#todo-17)), with adversarial tests. It is informative: where the model and the prose disagree, one of them is wrong and should be fixed.

## What it models

- **Repos.** Each account's present device records and approval records, as an enumeration at a verified commit would prove them. Deleting a device record revokes it.
- **Grants.** Records in the issuer's space repo naming issuer, recipient, and space. The model never decrypts, so a grant may carry garbage, as a third party could not tell.
- **Membership.** The host's current eligible accounts per space.
- **`SpecClient`,** the specified design: trust on first use under the single-root rule, approvals afterwards with acceptance persisted alongside its evidence, revocation by observed absence, and a re-enrollment hold bound to its exact candidate for clients that knew the account.

There is no cryptography. A record signed by a binding is valid exactly when its creator held that binding's key, and tests create only records the creating party could sign. The model assumes one shared, current view of every repo; partial views and delayed observations are left to the prototype in [TODO-18](../TODOs.md#todo-18).

## Running

From the repository root:

```bash
python3 -I -m unittest discover -s model -v
```

```bash
python3 -I model/mutation_check.py
```

`test_peep_trust.py` tests `SpecClient` against the [security goals](../security-goals.md). Tests prefixed `test_limitation_` assert documented non-goals, such as root theft at first contact and a new contact meeting an account just after a takeover. The mutation check breaks one `SpecClient` rule at a time and reports whether any test notices; every mutation should be caught.

## What it found

- **Single-root rule.** The prose required exactly one binding with no incoming approval. Approval records outlive deleted devices, so an honest reset that kept old approvals had two roots and could never complete. The rule now ignores roots that reach only deleted devices.
- **Durable approvals.** An earlier client recomputed acceptance from the approvals currently published, so deleting an approval record removed an accepted device. Acceptance is now persisted with its evidence, as the specification requires.
- **Holds bound to candidates.** An earlier client keyed holds by account, so a replacement candidate inherited an almost-expired hold. Holds now bind to the exact candidate, a replaced candidate's members are revoked, and imports merge start times only for identical candidates.
- **Anchors and witnesses.** Protecting newcomers with anchors drew repeated findings; the last showed one malicious PDS can manufacture its own witness. PEEP adopted Signal-level goals instead; see below.

## Rejected designs

`peep_trust.py` keeps three rejected designs for comparison: `WarnOnlyClient`, `AccountWideAnchorClient`, and `ScopedWitnessClient`, which also holds their shared machinery. `test_variants.py` tests them, and [COMPARISON.md](COMPARISON.md) runs all four designs against the same scenarios. Regenerate its table with:

```bash
python3 -I model/compare.py
```
