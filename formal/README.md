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

Proofs can use many cores and gigabytes of memory, so on a large machine, run them in [Docker](docker/Dockerfile), with `JOBS` proofs at once and `RTS` Haskell runtime options for each:

```bash
docker build -t nbd-tamarin formal/docker
docker run --rm -e JOBS=17 -e RTS="-N8" -v "$PWD/formal:/formal" nbd-tamarin ./check.sh
```

With every entry running at once, the whole run takes about as long as its slowest lemma: about 8 minutes on a 256-core server. On a laptop, keep `JOBS` at 1, and cap the container (`--cpus`, `--memory`) and Tamarin's heap (`RTS="-N1 -M1300m -c"`); the larger existence proofs need more memory than Docker Desktop's default 2 GB VM provides.

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

All verified with Tamarin 1.12.0 and Maude 3.4, in the [container](docker/Dockerfile). The pre-fix variant is the same model built with `-D=NOLIVEGUARD`, which adds the rule that let an approval accept a device while every accepted binding of its account was revoked. The [inviters variant](#the-inviters-variant) has its own table below.

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

## The inviters variant

Built with `-D=INVITERS`, the model adds the grant standing of [the inviters proposal](../proposal-inviters.md), following the [Python model's](../model/README.md#what-the-inviters-variant-found) `InviterClient` where the proposal's text lags. Without the flag, the model is unchanged: Tamarin parses it to the same theory as before.

- **Acceptance is unchanged.** Standing gates only what a client grants: `IssueGrant` additionally requires that the binding gained standing, earlier, in that space or in every space.
- **Vouched, in one space.** `InviteFirstUse` vouches for a binding the client accepted by first use, while the host admits that account to the space, and gives it standing in that space only. A binding accepted any other way, including one of an account the client already knew, is never vouched for, and each binding is vouched for at most once.
- **Held.** `FirstContactHoldDone` gives any binding the client accepted by first use or approval standing in every space, once its first-contact hold completes. A revoked binding never completes one, but keeps standing it earned before.
- **Re-enrolled.** A completed re-enrollment hold gives standing in every space.
- **Approved.** A binding accepted by approval inherits its signer's standing and scope, even if the signer has since been revoked.
- **Own** bindings are not modeled, since clients in the model never accept their own account's bindings.

Built with `-D=INVITERS -D=UNSCOPED`, a vouch instead gives standing in every space: the rejected design in which a vouch was account-wide.

| Lemma | Claim | Result |
| --- | --- | --- |
| `inviters_executable_vouched_grant` | An inviter grants the invited space's key on a vouch alone, with no hold and no compromise. | verified, 25 steps |
| `inviters_executable_held_grant` | A member grants after a first-contact hold, with no vouch anywhere. | verified, 24 steps |
| `inviters_grant_targets_justified` | An issuer grants a space's key to an encryption key the adversary created only if it vouched for that binding in that same space, completed a first-contact or re-enrollment hold on it, or accepted it through an approval by a compromised or adversary signing key. First use alone no longer suffices. | verified, 59 steps |
| `key_leaks_only_via_holders_or_grants` (variant) | 2a, unchanged, still holds. With the lemma above, it gives space-key secrecy under the inviters rule. | verified, 468 steps |
| `cross_space_vouch_attack` (unscoped) | With account-wide vouches, an adversary binding vouched for in one space is granted a different space's key, with no hold, no approval, and no compromise. | verified (attack found), 12 steps |

**What it shows.** Under the inviters rule, a member that meets a taken-over account for the first time can no longer grant it a space's key at once: it needs a vouch in that space, a completed hold, or a compromised or adversary-signed approval, just as members who knew the account already did. The unscoped variant confirms the reviewer's finding: an account-wide vouch lets an inviter in one space disclose another space's key.

**What it does not show.**

- **Scope through adversary-signed approvals.** When an adversary or compromised key approves the binding, `inviters_grant_targets_justified` concludes only that, not that the signer's own standing was in the same space. An induction lemma for that did not terminate.
- **The moment of the vouch.** The model lets a vouch come any time after the first use rather than only together with it. That only adds behaviors, so the lemmas above still cover the rule.
- **Time.** Hold durations, credited clocks, and per-client timing are abstracted as for re-enrollment holds. Imports of invite records, hold notices, and verified-only spaces are not modeled.

## Notes on the proofs

- **Sessions are unbounded** in every lemma above. To keep searches finite, acceptance is persistent and "never after revocation" is a restriction rather than a consumed fact, and live-binding counts use a free successor function (`z`, `s(z)`, ...) rather than an associative-commutative multiset.
- **`adversary_grant_targets_justified` and `inviters_grant_targets_justified` use [`oracle.py`](oracle.py),** which defers goals that lead into unending chains (where an issuer's key came from, how counts were built, how an approval's signer was accepted, how the adversary learned a public key) and puts signature checks first. Under `-D=INVITERS`, `key_leaks_only_via_holders_or_grants` uses Tamarin's `i` heuristic: with the default, it does not finish within the time cap. Every other lemma uses the default heuristic.
- **Grant standing is a restriction on `IssueGrant`,** not a premise, and the vouch reads nothing from the network. Either alternative multiplies the sources Tamarin precomputes for grants, and the proofs then do not finish.
- **The existence lemmas name their witness** and exclude unneeded events (other approvals, holds, revocations, compromise). The exclusions only prune the search; each trace still shows what its lemma claims.
- **Tamarin warns** that a counter `n` matched inside `s(n)` is not derivable by the adversary. This is intended: the counter is client state, not a message.
