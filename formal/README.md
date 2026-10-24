# NBD: Tamarin model

A symbolic model of NBD's grants, device approvals, and key compromise in [Tamarin](https://tamarin-prover.com), [`nbd.spthy`](nbd.spthy). It complements the [Python model](../model/README.md) and the [prototype](../prototype/README.md): they test the trust rules over bounded runs against scripted adversaries, while Tamarin proves lemmas over unbounded sessions against an adversary that does anything the cryptography allows. It is informative: where it and the specification disagree, one of them is wrong.

## Running

Install Tamarin (1.12 or later) and Maude. On macOS, from the project's Homebrew tap:

```bash
brew install tamarin-prover/tap/tamarin-prover
```

Then, from the repository root:

```bash
formal/check.sh
```

It proves each lemma on its own, one at a time, with the heuristic that lets it terminate and a time cap (`CAP`, default 1800 seconds), writes `formal/results.txt`, and fails unless every lemma is verified. The whole run takes about 25 minutes on an Apple-silicon laptop. To explore a lemma or an attack trace interactively, run `tamarin-prover interactive formal/` and open <http://localhost:3001>.

## Adversary and trust

- **The adversary** controls the network and plays every PDS. Clients read device records, approvals, deletions, and grants from it, so it chooses what each client sees and can revoke any device for any client. It can compromise any device at any time, learning its signing and encryption keys and every space key it holds, and it can create devices of its own.
- **Trusted**, as in the specification: the Spaces host's membership and configuration decisions, and honest devices' code. Honest devices approve only devices of their own account, since pairing authenticates the target.

## What is modeled

- Devices with independent signing and encryption keys, published as bindings `<account, pk(sign), pk(enc)>`.
- Approvals and key requests, signed with the same device key under distinct tags.
- Space creation: a fresh key, and a host configuration committing to `h(<space, keyId, key>)`.
- Grants: the key encrypted to the recipient's encryption key, bound to a header naming the space, key ID, and both bindings, with a required issuer signature. HPKE is abstracted as public-key encryption bound to the header.
- Each client's trust in each other account:
  - first use, only for an account it never knew;
  - acceptance by approval from a binding it accepted, revoked or not, only while the account has a live accepted binding at that client (D2's live-binding rule);
  - revocation;
  - re-enrollment once every accepted binding is revoked, as a hold that blocks every other acceptance until it completes.
- Issuance only to bindings the issuer accepted and that are live, for members per the host. Acceptance checks the signature, the recipient, decryption, the commitment, the issuer's acceptance, and membership.

## What is abstracted away

- **Time.** The 72-hour hold is "starts, then may complete later"; how long it lasts, credited clocks, and the account holder's alarm during it are tested in the [simulations](../prototype/README.md#for-reviewers), not here.
- **The single-root rule.** First use accepts whatever binding the adversary offers, the worst case and exactly the documented non-goal.
- **Repo mechanics:** revisions, rollback refusal, forks, and evidence beyond what the grant header binds.
- **Publication retries, content encryption and padding, and auditing and detection.**

## Lemmas and results

All verified with Tamarin 1.12.0 and Maude 3.5.1. The pre-fix variant is the same model built with `-D=NOLIVEGUARD`, which adds the rule that let an approval accept a device while every accepted binding of its account was revoked.

| Lemma | Claim | Goal | Result |
| --- | --- | --- | --- |
| `executable_grant` | A member's device gets the key from the creator, with no compromise. | sanity | verified, 15 steps |
| `executable_approval` | A client accepts a second device through a genuine approval by the first. | sanity | verified, 14 steps |
| `executable_approved_device` | ...and that device then receives the key from the same client. | sanity | verified, 27 steps |
| `key_agreement` | Every accepted key is the key the creator committed to. | 1 | verified, 4 steps |
| `grant_authentication` | An accepted grant was issued by its issuer for this recipient, unless the issuer's signing key is compromised or the adversary's own. | 1, 7 | verified, 3431 steps |
| `approval_authenticity` | An approval signed by an honest device was made by it, unless its key is compromised. Key-request signatures never stand in for approvals. | 2 | verified, 5 steps |
| `no_silent_addition` | After first contact, a device the adversary created is accepted only after a completed hold, or through an approval by a compromised or adversary signing key. | 2, 3 | verified, 9 steps |
| `reset_acceptance_needs_hold` | While every accepted binding of an account is revoked, only a completed hold accepts anything. | 3 | verified, 2 steps |
| `key_leaks_only_via_holders_or_grants` | The adversary learns a space key only from a compromised holder, or through a grant to an encryption key it can decrypt (compromised, or its own). | 1 | verified, 471 steps |
| `adversary_grant_targets_justified` | An issuer grants to an encryption key the adversary created only if it accepted that binding by first use, after a hold, or through an approval by a compromised or adversary signing key. | 2, 3 | verified, 38 steps |
| `first_contact_substitution` | First-use substitution discloses a space key with no compromise at all: non-goal 1 is an attack the model finds, not an omission. | non-goal 1 | verified (attack found), 6 steps |
| `revoked_signer_bypass` (variant) | Without the live-binding rule, an approval signed by a revoked key ends a reset with no hold: the bypass fixed in commit `60edc67`. | 3 | verified (attack found), 20 steps |

Together, `key_leaks_only_via_holders_or_grants` and `adversary_grant_targets_justified` are space-key secrecy: substituting the second into the first's last case gives the full claim. Proved as one lemma, the search does not terminate.

**Spot check.** With the recipient's commitment check removed, the model finds a trace in which a recipient accepts a key that is not the space's key, from an adversary-issued grant. `key_agreement` rests on that check.

## Notes on the proofs

- **Sessions are unbounded** in every lemma above. To keep searches finite, acceptance is persistent and "never after revocation" is a restriction rather than a consumed fact, and live-binding counts use a free successor function (`z`, `s(z)`, ...) rather than an associative-commutative multiset.
- **`adversary_grant_targets_justified` uses [`oracle.py`](oracle.py),** which defers goals that lead into unending chains (where an issuer's key came from, how counts were built, how an approval's signer was accepted, how the adversary learned a public key) and puts signature checks first. Every other lemma uses Tamarin's default heuristic.
- **The existence lemmas name their witness** and exclude unneeded events (other approvals, holds, revocations, compromise). The exclusions only prune the search; each trace still shows what its lemma claims.
- **Tamarin warns** that a counter `n` matched inside `s(n)` is not derivable by the adversary. This is intended: the counter is client state, not a message.
