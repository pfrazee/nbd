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

It proves each lemma on its own, one at a time, with the heuristic that lets it terminate and a time cap (`CAP`, default 1800 seconds), writes `formal/results.txt`, and fails unless every lemma is verified. Run that way, the lemmas take about 40 minutes in total on a server core, and the larger ones need several gigabytes of memory. To explore a lemma or an attack trace interactively, run `tamarin-prover interactive formal/` and open <http://localhost:3001>.

Proofs can use many cores and gigabytes of memory, so on a large machine, run them in [Docker](docker/Dockerfile), with `JOBS` proofs at once and `RTS` Haskell runtime options for each:

```bash
docker build -t nbd-tamarin formal/docker
docker run --rm -e JOBS=24 -e RTS="-N8" -v "$PWD/formal:/formal" nbd-tamarin ./check.sh
```

With every entry running at once, the whole run takes about as long as its slowest lemma: about 6 minutes on a 256-core server. On a laptop, keep `JOBS` at 1, and cap the container (`--cpus`, `--memory`) and Tamarin's heap (`RTS="-N1 -M1300m -c"`); the larger existence proofs need more memory than Docker Desktop's default 2 GB VM provides.

## Adversary and trust

- **The adversary** controls the network and plays every PDS. Clients read device records, approvals, deletions, and grants from it, so it chooses what each client sees and can revoke any device for any client. It can compromise any device at any time, learning its signing and encryption keys and every space key it holds, and it can create devices of its own.
- **Trusted**, as in the specification: the Spaces host's membership and configuration decisions, and honest devices' code. Honest devices approve only devices of their own account, since pairing authenticates the target.

## What is modeled

- Devices with independent signing and encryption keys, published as bindings `<account, pk(sign), pk(enc)>`.
- Approvals and key requests, signed with the same device key under distinct tags.
- Space creation: a fresh key, and a host configuration committing to `h(<space, keyId, key>)`.
- Admission: the host admits accounts to spaces. Each admission names the account whose [invite](../core.md#invites) admitted the account, or one with no devices for a host console or an application without NBD support.
- Grants: the key encrypted to the recipient's encryption key, bound to a header naming the space, key ID, and both bindings, with a required issuer signature. HPKE is abstracted as public-key encryption bound to the header.
- Each client's trust in each other account:
  - first use, only for an account it never knew;
  - acceptance by approval from a binding it accepted, revoked or not, only while the account has a live accepted binding at that client (D2's live-binding rule);
  - revocation;
  - re-enrollment once every accepted binding is revoked, as a hold that blocks every other acceptance until it completes.
- [Grant standing](../device-enrollment.md#grant-standing), which gates only what a client grants; acceptance is as above. `IssueGrant` requires a live accepted binding, members per the host, and that the binding gained standing earlier, in that space or in every space:
  - **Vouched, then authorized by invites.** `InviteFirstUse` vouches for a binding the client accepted by first use when its account invited the binding's account, and that invite authorizes the binding in its space (`Authorized`). A binding accepted any other way, including one of an account the client already knew, is never vouched for, and each binding is vouched for at most once. A later invite authorizes, in its space, the bindings already vouched for when it is made (`AuthorizeVouched`). Its admission must follow the vouch (restriction `InviteAfterVouch`), so a later vouch never extends an earlier invite. An invite counts only if it admits the account: no attributed admission follows an earlier admission of the account to that space (restriction `InviteAdmits`). An authorized binding has standing in that space only.
  - **Pending invites.** An invite made before the client knew the account, whose first device the client then accepts by first use and vouches for, is a captured pending invite. The vouch rule covers it, since the invite it names may come before the first use, and authorizes the pending invite's space. A pending invite that is never captured authorizes nothing.
  - **Held.** `FirstContactHoldDone` gives any binding the client accepted by first use or approval standing in every space, once its first-contact hold completes. A revoked binding never completes one, but keeps standing it earned before.
  - **Re-enrolled.** A completed re-enrollment hold gives standing in every space.
  - **Approved.** A binding accepted by approval inherits its signer's standing, scope, and root, even if the signer has since been revoked. Every standing carries its root, the binding it came from: the binding itself, or an approval ancestor.
  - **Own** bindings are not modeled, since clients in the model never accept their own account's bindings.
- Acceptance of a grant checks the signature, the recipient, decryption, the commitment, the issuer's acceptance, and membership.

## What is abstracted away

- **Time.** The 72-hour holds are "starts, then may complete later"; how long they last, credited clocks, per-client timing, pending-invite expiry, and the account holder's alarm are tested in the [simulations](../prototype/README.md#for-reviewers), not here. An expired pending invite is one whose capture simply never happens.
- **The moment of the vouch.** The model lets a vouch come any time after the first use, and the invite it names any time before or after it, rather than only together. That only adds behaviors, so the lemmas below still cover the rule. It also covers the distinction between an invite made at first contact and a pending invite captured later, so the model does not separate them.
- **Several installations of one account.** Each client device stands for its account; invite records carried between an account's installations, and imports, are not modeled.
- **The single-root rule.** First use accepts whatever binding the adversary offers, the worst case and exactly the documented non-goal.
- **Repo mechanics:** revisions, rollback refusal, forks, and evidence beyond what the grant header binds.
- **Publication retries, content encryption and padding, hold notices, verified-only spaces, and auditing and detection.**

## Lemmas and results

All verified with Tamarin 1.12.0 and Maude 3.4, in the [container](docker/Dockerfile).

| Lemma | Claim | Goal | Result |
| --- | --- | --- | --- |
| `executable_grant` | A member's device gets the key from the creator, with no compromise. | sanity | verified, 28 steps |
| `executable_approval` | A client accepts a second device through a genuine approval by the first. | sanity | verified, 14 steps |
| `executable_approved_device` | ...and that device then receives the key from the same client. | sanity | verified, 31 steps |
| `inviters_executable_vouched_grant` | An inviter grants the key of a space its account invited the account to, on a vouch alone, with no hold and no compromise. | sanity | verified, 28 steps |
| `inviters_executable_captured_grant` | The same through a captured pending invite: the account was invited before the inviter knew it. | sanity | verified, 30 steps |
| `inviters_executable_held_grant` | A member grants after a first-contact hold, with no vouch anywhere. | sanity | verified, 25 steps |
| `key_agreement` | Every accepted key is the key the creator committed to. | 1 | verified, 4 steps |
| `grant_authentication` | An accepted grant was issued by its issuer for this recipient, unless the issuer's signing key is compromised or the adversary's own. | 1, 7 | verified, 1856 steps |
| `approval_authenticity` | An approval signed by an honest device was made by it, unless its key is compromised. Key-request signatures never stand in for approvals. | 2 | verified, 5 steps |
| `no_silent_addition` | After first contact, a device the adversary created is accepted only after a completed hold, or through an approval by a compromised or adversary signing key. | 2, 3 | verified, 9 steps |
| `reset_acceptance_needs_hold` | While every accepted binding of an account is revoked, only a completed hold accepts anything. | 3 | verified, 2 steps |
| `key_leaks_only_via_holders_or_grants` | The adversary learns a space key only from a compromised holder, or through a grant to an encryption key it can decrypt (compromised, or its own). | 1 | verified, 258 steps |
| `inviters_grant_targets_justified` | An issuer grants a space's key to an encryption key the adversary created only if it vouched for that binding and an invite to that space authorized it no earlier than the vouch, completed a first-contact or re-enrollment hold on the binding, or accepted it through an approval by a compromised or adversary signing key. First use alone does not suffice. | 1, 3 | verified, 69 steps |
| `inviters_root_is_ancestor` | A standing's root is the binding itself, or the root of the binding that approved it, in the same scope: so, by induction along the chain, the binding or an approval ancestor. | 3 | verified, 17 steps |
| `inviters_standing_scoped` | Scope survives approval chains, whoever signed them: standing in a space goes back to its root's authorization in that space, by the vouch itself or by an invite whose admission followed the vouch, and standing in every space to a completed first-contact or re-enrollment hold on its root. Proved by induction. | 3 | verified, 137 steps |
| `inviters_grant_scope` | So every grant, to any binding, rests on standing whose root, the binding or an approval ancestor, was authorized in that space no earlier than its vouch, or completed a hold. | 3 | verified, 2778 steps |
| `first_contact_substitution` | The inviter's own first contact is still a substitution point: an inviter that first meets a substituted binding through its invite vouches for it and discloses the space key, with no hold and no compromise. Non-goal 1 is an attack the model finds, not an omission. | non-goal 1 | verified (attack found), 14 steps |

Together, `key_leaks_only_via_holders_or_grants` and `inviters_grant_targets_justified` are space-key secrecy: substituting the second into the first's last case gives the full claim. Proved as one lemma, the search does not terminate.

**What it shows.** A member that meets a taken-over account for the first time cannot grant it a space's key at once: it needs its own vouch, and an invite to that space authorizing the binding no earlier than the vouch, a completed hold, or a compromised or adversary-signed approval, just as members who knew the account already did. Scope survives approval chains: even through approvals by adversary or compromised keys, standing in a space goes back to an approval ancestor that an invite to that space authorized, no earlier than its vouch.

**Spot check.** With the recipient's commitment check removed, the model finds a trace in which a recipient accepts a key that is not the space's key, from an adversary-issued grant. `key_agreement` rests on that check.

### Variants

Each variant is the same model built with one flag, and each restores a rule the specification rejected or replaced. The four attacks show that the rule each variant drops is needed.

| Variant | Lemma | Claim | Result |
| --- | --- | --- | --- |
| `-D=NOLIVEGUARD` | `revoked_signer_bypass` | Without the live-binding rule, an approval signed by a revoked key ends a reset with no hold: the bypass fixed in commit `60edc67`. | verified (attack found), 20 steps |
| `-D=UNSCOPED` | `cross_space_vouch_attack` | If a vouch counted in every space, an adversary binding vouched for through an invite to one space would be granted the key of another space the issuer never invited its account to, with no hold, no approval, and no compromise. | verified (attack found), 14 steps |
| `-D=REINVITE` | `reinvite_carries_vouch` | Without `InviteAdmits`, an invite of an account already admitted to a space carries the inviter's vouch there, giving standing in a space where another admission had made the account a member first. | verified (attack found), 12 steps |
| `-D=RETRO` | `retro_vouch_attack` | Without `InviteAfterVouch`, an invite made before the client knew the account and never captured is authorized after the fact by a vouch made through another space's invite: the client grants the first space's key to the adversary's binding with no hold and no compromise. | verified (attack found), 17 steps |
| `-D=PREINVITERS` | `key_leaks_only_via_holders_or_grants` | 2a, for the rule before grant standing, in which any accepted binding may receive a grant. | verified, 471 steps |
| `-D=PREINVITERS` | `adversary_grant_targets_justified` | 2b for that rule: an issuer grants to an encryption key the adversary created only if it accepted that binding by first use, after a hold, or through an approval by a compromised or adversary signing key. | verified, 38 steps |
| `-D=PREINVITERS` | `first_contact_substitution` | Under that rule, any member's first-use substitution discloses a space key with no compromise: the exposure grant standing narrows to the inviter. | verified (attack found), 6 steps |

## Notes on the proofs

- **Sessions are unbounded** in every lemma above. To keep searches finite, acceptance is persistent and "never after revocation" is a restriction rather than a consumed fact, and live-binding counts use a free successor function (`z`, `s(z)`, ...) rather than an associative-commutative multiset.
- **`inviters_grant_targets_justified` and the pre-inviters `adversary_grant_targets_justified` use [`oracle.py`](oracle.py),** which defers goals that lead into unending chains (where an issuer's key came from, how counts were built, how an approval's signer was accepted, how the adversary learned a public key) and puts signature checks first. In the main model, `key_leaks_only_via_holders_or_grants` uses Tamarin's `i` heuristic, since with the default it did not finish within the time cap on an earlier version of the grant-standing rules, and `executable_approved_device` uses `C`, since with the default it does not finish within the cap. Every other lemma uses the default heuristic.
- **Grant standing is a restriction on `IssueGrant`,** not a premise; the vouch reads nothing from the network; and invites add no membership of their own, but name who made an admission (`Admit`). Each alternative multiplies the sources Tamarin precomputes for grants or memberships, and the proofs then slow down severalfold or do not finish.
- **`inviters_standing_scoped` is proved by induction and reused** by `inviters_grant_scope`, the only lemma after it. Standing roots are written as bindings (`<account, pk(sign), pk(enc)>`) in `InheritStanding` and the grant restriction; with an unstructured root, the reused lemma does not apply until Tamarin unrolls the approval chain, and the grant lemma does not finish.
- **The existence lemmas name their witness** and exclude unneeded events (other approvals, grants, holds, revocations, compromise). The exclusions only prune the search; each trace still shows what its lemma claims.
- **Tamarin warns** that a counter `n` matched inside `s(n)` is not derivable by the adversary. This is intended: the counter is client state, not a message.
