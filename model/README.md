# PEEP trust model

An executable model of `accepted(binding, space)` from [Device Enrollment](../device-enrollment.md#acceptance-in-a-space) ([TODO-17](../TODOs.md#todo-17)), with adversarial tests. It is informative: where the model and the prose disagree, one of them is wrong and should be fixed.

## What it models

- **Repos.** Each account's present device records and approval records, as an enumeration at a verified commit would prove them. Deleting a device record revokes it.
- **Grants.** Records in the issuer's space repo naming issuer, recipient, space, and key provenance. The model never decrypts, so a grant may carry garbage, as a third party could not tell.
- **Membership.** The host's current eligible accounts per space.
- **A client.** Its persisted bases (account-wide pins, per-space pins, revocations, holds, history), first use with anchors, witness scope, approvals, re-enrollment holds, revocation by observed absence, and restore.

There is no cryptography. A record signed by a binding is valid exactly when its creator held that binding's key, and tests create only records the creating party could sign.

## Running

From the repository root:

```bash
python3 -I -m unittest discover -s model -v
```

```bash
python3 -I model/mutation_check.py
```

The mutation check breaks one rule at a time and reports whether any test notices. One mutation is expected to be missed: accepting witness grants from other spaces. The witness must still be accepted in, and an eligible member of, the space in question, so it could testify there directly; the space filter adds no security.

## What it found

- **Single-root rule.** The prose required exactly one binding with no incoming approval. Approval records outlive deleted devices, so an honest reset that kept old approvals had two roots and could never complete. The rule now ignores roots that reach only deleted devices.
- **Witnesses for pinned accounts.** Basis 3 did not say it applies only to accounts not pinned account-wide, so a witness could add an unapproved device to a pinned account. It now applies only to unpinned accounts.
- **Fallback in spaces without witnesses.** First use in a space with no witnesses for an account is plain trust on first use, even when witnesses elsewhere would have excluded a malicious PDS's device. The test `test_limitation_witnessless_space_falls_back_to_first_contact` asserts this; whether to use other spaces' anchors as constraints is open in TODO-17.

Tests prefixed `test_limitation_` assert documented exposures, not desired behavior.
