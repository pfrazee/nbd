# Trust variants compared

Four ways a client could use anchors at first use, run against the same scenarios by [`compare.py`](compare.py) and pinned by [`test_compare.py`](test_compare.py). Outcomes are from the viewing client's side: **compromised** means it accepts the attacker's device in the target space, **hold** means it waits out the re-enrollment hold, **declined** means it refuses an honest device, and **safe** means it accepts honest devices and refuses attackers.

| Variant | Anchors | Acceptance |
| --- | --- | --- |
| TOFU only | None. Only clients that pinned an account before detect its reset. | Account-wide |
| Warnings only | Trigger holds and decline unreachable devices; never accept. | Account-wide |
| Account-wide anchors (adopted) | Accept devices reachable from them in signed direction. | Account-wide |
| Scoped witnesses (rejected) | As above, limited to spaces the witnesses can access, recursively. | Per space |

| Scenario | TOFU only | Warnings only | Account-wide anchors (spec) | Scoped witnesses |
| --- | --- | --- | --- | --- |
| Root theft (M approves the root), honest witness | compromised | safe | safe | safe |
| Unlinked device beside live devices | declined | declined | safe | safe |
| Reset at honest PDS, newcomer with recipient anchor | compromised | hold | hold | hold |
| Reset of a creator who only issued, newcomer | compromised | hold | hold | hold |
| Reset, client already pinned the account | hold | hold | hold | hold |
| Two accounts on one malicious PDS witness each other | compromised | safe | safe | safe |
| Colluding witness + malicious PDS, other space has a witness | compromised | compromised | compromised | safe |
| Colluding witness + malicious PDS, other space has none | compromised | compromised | compromised | compromised |
| Witness chain into a private space | compromised | compromised | compromised | safe |
| Retire the only anchored branch (availability) | safe | hold | hold | hold |
| Forged witness naming a missing binding (availability) | safe | hold | hold | hold |

## Reading the table

- **Any anchors beat TOFU** wherever an attacker controls a repo but has no one else's help: root theft, unlinked devices, resets seen by newcomers, and two accounts on one PDS. TOFU loses all of these. The cost is a hold in two availability cases.
- **Warnings only is dominated.** It matches account-wide anchors on every exposure row but declines the whole account when a takeover adds an unlinked device, because without accepting anything it falls back to the single-root rule, which the extra device breaks.
- **Scoping wins two rows, both needing collusion.** The cross-space and chain cases require a member the viewer already accepted to vouch for a device published by someone controlling the victim's repo; a takeover with create access is enough for the latter. Scoping stops it only when the target space has its own honest witness for the victim. With none, every variant falls back to trust on first use there.
- **What the colluder gains without scoping** is the target space's key through the victim's identity, which it could not otherwise obtain. That is a real escalation, which is why astra raised it, but it needs two cooperating parties and is limited to accounts the viewer has not pinned.

## Decision

The specification adopted **account-wide anchors**; the reasoning below is the recommendation that led there.

Adopt **account-wide anchors** and drop witness scope, documenting the colluding-witness escalation as a known limitation alongside first-contact exposure.

Scoping buys two rows that already need a colluding member plus control of the victim's repo, and only in spaces that happen to have independent witnesses. It costs the whole "Acceptance in a space" section: per-space pins, per-space holds, live recomputation when membership or witnesses change, scope inheritance through approvals and chains, and the open questions in TODO-17, each of which has produced a review finding. Account-wide anchors keep every protection against an attacker acting alone.

Keep scoped witnesses instead if colluding members are inside the threat model you intend to defend. In that case the model's other open questions (live versus snapshotted acceptance, constraining witnessless spaces) need answers before the prose is extended further.
