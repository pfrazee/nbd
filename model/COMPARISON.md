# Trust designs compared

NBD tried several ways to protect a client meeting an account for the first time, then adopted the current [security goals](../README.md#goals): trust on first use, approvals afterwards, and a re-enrollment hold for clients that knew the account. [`compare.py`](compare.py) runs the adopted design and three rejected ones against the same scenarios, and [`test_compare.py`](test_compare.py) pins the results. Outcomes are from the viewing client's side: **compromised** means it accepts the attacker's device in the target space, **hold** means it waits out the re-enrollment hold, **declined** means it refuses an honest device, and **safe** means it accepts honest devices and refuses attackers.

| Design | First use | Status |
| --- | --- | --- |
| TOFU + approvals | Single-root rule over the account's repo. | Adopted |
| Warnings only | Anchors from other members' grants trigger holds and decline unreachable devices, never accept. | Rejected |
| Account-wide anchors | Anchors accept devices reachable from them, account-wide. | Rejected |
| Scoped witnesses | As above, limited per space to spaces the witnesses can access. | Rejected |

| Scenario | Viewer's first contact? | TOFU + approvals (spec) | Warnings only | Account-wide anchors | Scoped witnesses |
| --- | --- | --- | --- | --- | --- |
| Root theft (M approves the root), honest witness | yes | compromised | safe | safe | safe |
| Unlinked device beside live devices | yes | declined | declined | safe | safe |
| Reset at honest PDS, newcomer with recipient anchor | yes | compromised | hold | hold | hold |
| Reset of a creator who only issued, newcomer | yes | compromised | hold | hold | hold |
| Reset, client already pinned the account | no | hold | hold | hold | hold |
| Takeover adds a device, client already pinned the account | no | safe | safe | safe | safe |
| Two accounts on one malicious PDS witness each other | yes | compromised | safe | safe | safe |
| Colluding witness + malicious PDS, other space has a witness | yes | compromised | compromised | compromised | safe |
| Colluding witness + malicious PDS, other space has none | yes | compromised | compromised | compromised | compromised |
| One malicious PDS manufactures a witness for another of its accounts | yes | compromised | compromised | compromised | safe |
| Witness chain into a private space | yes | compromised | compromised | compromised | safe |
| Retire the only anchored branch (availability) | yes | safe | hold | hold | hold |
| Forged witness naming a missing binding (availability) | yes | safe | hold | hold | hold |

## Reading the table

- **After first contact, every design is the same.** A takeover cannot add a device for a client that already pinned the account, and a reset waits out the hold. These are the guarantees NBD keeps ([goals 2 and 3](../README.md#goals)).
- **Every compromise of the adopted design is at first contact,** which the goals list as a non-goal; `test_spec_is_compromised_only_at_first_contact` checks this. Signal has the same exposure for a new contact of a hijacked number.
- **Anchors protected some first contacts but composed badly.** Without collusion they stopped root theft and newcomers' resets. But one malicious PDS hosting two accounts can substitute one account at first contact and use it as a witness for the other, which compromises every anchor design except per-space scope, and per-space scope needed live recomputation, scope inheritance, and per-space holds. Each version drew new review findings.
- **Anchors also cost availability:** retiring the only witnessed branch, or a forged witness naming a missing binding, forced holds on honest accounts.

## Decision

NBD adopts TOFU + approvals. It gives up protecting first contact in exchange for a design whose guarantees hold as stated, with no witness machinery, and matches the threat model of established messengers. Independent device verification, deferred in the TODOs, is the path to protecting first contact without anchors.
