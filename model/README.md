# PEEP trust model

An executable model of [local trust](../device-enrollment.md#local-trust) in Device Enrollment ([TODO-17](../TODOs.md#todo-17)), with adversarial tests. It is informative: where the model and the prose disagree, one of them is wrong and should be fixed.

## What it models

- **Repos.** Each account's present device records and approval records, as an enumeration at a verified commit would prove them. Deleting a device record revokes it.
- **Grants.** Records in the issuer's space repo naming issuer, recipient, space, and key provenance. The model never decrypts, so a grant may carry garbage, as a third party could not tell.
- **Membership.** The host's current eligible accounts per space.
- **A client.** `SpecClient` is the specified design: account-wide pins, first use from anchors witnessed by accepted members' devices, approvals, re-enrollment holds, revocation by observed absence, and restore. `ScopedWitnessClient` is the rejected per-space alternative, which also holds the shared machinery; `WarnOnlyClient` and `TofuClient` are simpler baselines.

There is no cryptography. A record signed by a binding is valid exactly when its creator held that binding's key, and tests create only records the creating party could sign.

## Running

From the repository root:

```bash
python3 -I -m unittest discover -s model -v
```

```bash
python3 -I model/mutation_check.py
```

The mutation check breaks one rule at a time, in both the specified client and the scoped alternative, and reports whether any test notices. One mutation is expected to be missed: accepting witness grants from other spaces in the scoped alternative. The witness must still be accepted in, and an eligible member of, the space in question, so it could testify there directly; the space filter adds no security.

## What it found

- **Single-root rule.** The prose required exactly one binding with no incoming approval. Approval records outlive deleted devices, so an honest reset that kept old approvals had two roots and could never complete. The rule now ignores roots that reach only deleted devices.
- **Witnesses for pinned accounts.** Basis 3 did not say it applies only to accounts not pinned account-wide, so a witness could add an unapproved device to a pinned account. It now applies only to unpinned accounts.
- **Whether to scope witnesses.** The [comparison](COMPARISON.md) showed per-space witness scope protects only against a colluding member in spaces that have their own honest witness, at the cost of per-space acceptance. The specification adopted account-wide anchors and documents the colluding-witness limitation, which `ColludingWitnessLimitation` asserts.

Tests prefixed `test_limitation_` assert documented exposures, not desired behavior.

## Variants

[COMPARISON.md](COMPARISON.md) runs all four clients against the same scenarios: `TofuClient` (no anchors), `WarnOnlyClient` (anchors only trigger holds or decline), `AccountWideAnchorClient` (the specified design, also exported as `SpecClient`), and `ScopedWitnessClient`. Regenerate its table with:

```bash
python3 -I model/compare.py
```
