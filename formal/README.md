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
docker run --rm -e JOBS=26 -e RTS="-N8" -v "$PWD/formal:/formal" nbd-tamarin ./check.sh
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
  - **Authorized by invites.** `InviteFirstUse` vouches for a binding the client accepted by first use when its account invited the binding's account, and that invite authorizes the binding in its space (`Authorized`). Each binding is vouched for at most once. A later invite authorizes, in its space, each binding of the account the client accepted by first use before the invite was made, whether or not it was vouched for (`AuthorizeFirstUsed`). A binding accepted through a re-enrollment hold or by approval is never authorized this way (restriction `AuthorizeOnlyFirstUsed`), and the invite's admission must follow the binding's first use (restriction `InviteAfterFirstUse`), so an invite's record never extends to a binding first used after it. An invite counts only if it admits the account: no attributed admission follows an earlier admission of the account to that space (restriction `InviteAdmits`). An authorized binding has standing in that space only.
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
- **Repo mechanics:** revisions, rollback refusal, forks, and evidence beyond what the grant header binds. The [`WITNESS` variant](#relay-witnessed-repos-proposal) adds a relay log and witnesses for the proposal under review.
- **Publication retries, content encryption and padding, hold notices, verified-only spaces, and auditing and detection** (detection only under `WITNESS`).

## Lemmas and results

All verified with Tamarin 1.12.0 and Maude 3.4, in the [container](docker/Dockerfile).

| Lemma | Claim | Goal | Result |
| --- | --- | --- | --- |
| `executable_grant` | A member's device gets the key from the creator, with no compromise. | sanity | verified, 28 steps |
| `executable_approval` | A client accepts a second device through a genuine approval by the first. | sanity | verified, 14 steps |
| `executable_approved_device` | ...and that device then receives the key from the same client. | sanity | verified, 31 steps |
| `inviters_executable_vouched_grant` | An inviter grants the key of a space its account invited the account to, on a vouch alone, with no hold and no compromise. | sanity | verified, 32 steps |
| `inviters_executable_captured_grant` | The same through a captured pending invite: the account was invited before the inviter knew it. | sanity | verified, 30 steps |
| `inviters_executable_held_grant` | A member grants after a first-contact hold, with no vouch anywhere. | sanity | verified, 29 steps |
| `inviters_executable_later_invite_grant` | A member that first met the account by syncing, not through an invite, later invites it to a space and grants that space's key, with no vouch, no hold, and no compromise. | sanity | verified, 31 steps |
| `key_agreement` | Every accepted key is the key the creator committed to. | 1 | verified, 4 steps |
| `grant_authentication` | An accepted grant was issued by its issuer for this recipient, unless the issuer's signing key is compromised or the adversary's own. | 1, 7 | verified, 1856 steps |
| `approval_authenticity` | An approval signed by an honest device was made by it, unless its key is compromised. Key-request signatures never stand in for approvals. | 2 | verified, 5 steps |
| `no_silent_addition` | After first contact, a device the adversary created is accepted only after a completed hold, or through an approval by a compromised or adversary signing key. | 2, 3 | verified, 9 steps |
| `reset_acceptance_needs_hold` | While every accepted binding of an account is revoked, only a completed hold accepts anything. | 3 | verified, 2 steps |
| `key_leaks_only_via_holders_or_grants` | The adversary learns a space key only from a compromised holder, or through a grant to an encryption key it can decrypt (compromised, or its own). | 1 | verified, 258 steps |
| `inviters_grant_targets_justified` | An issuer grants a space's key to an encryption key the adversary created only if it first used that binding and an invite to that space authorized it, either the invite its first use was part of (a vouch, which covers capturing a pending invite) or one admitting the account after that first use; completed a first-contact or re-enrollment hold on the binding, or accepted it through an approval by a compromised or adversary signing key. First use alone does not suffice. | 1, 3 | verified, 65 steps |
| `inviters_root_is_ancestor` | A standing's root is the binding itself, or the root of the binding that approved it, in the same scope: so, by induction along the chain, the binding or an approval ancestor. | 3 | verified, 17 steps |
| `inviters_standing_scoped` | Scope survives approval chains, whoever signed them: standing in a space goes back to its root's first use by the client and authorization in that space, by the vouch itself or by an invite whose admission followed that first use, and standing in every space to a completed first-contact or re-enrollment hold on its root. Proved by induction. | 3 | verified, 141 steps |
| `inviters_grant_scope` | So every grant, to any binding, rests on standing whose root, the binding or an approval ancestor, the issuer first used and an invite to that space then authorized, or which completed a hold. | 3 | verified, 3024 steps |
| `inviters_reenrolled_never_invite_authorized` | An invite never authorizes a binding the client accepted through a re-enrollment hold. | 3 | verified, 4 steps |
| `first_contact_substitution` | The inviter's own first contact is still a substitution point: an inviter that first meets a substituted binding through its invite vouches for it and discloses the space key, with no hold and no compromise. Non-goal 1 is an attack the model finds, not an omission. | non-goal 1 | verified (attack found), 14 steps |

Together, `key_leaks_only_via_holders_or_grants` and `inviters_grant_targets_justified` are space-key secrecy: substituting the second into the first's last case gives the full claim. Proved as one lemma, the search does not terminate.

**What it shows.** A member that meets a taken-over account for the first time cannot grant it a space's key at once, unless its own account invites the account to that space. It needs an invite to that space that authorized the binding, either as part of the binding's first use or by admitting the account after it; or a completed hold; or a compromised or adversary-signed approval. Members who knew the account already were held to the same. An invite never authorizes a re-enrolled binding. Scope survives approval chains: even through approvals by adversary or compromised keys, standing in a space goes back to an approval ancestor the client first used and an invite to that space then authorized.

**Spot check.** With the recipient's commitment check removed, the model finds a trace in which a recipient accepts a key that is not the space's key, from an adversary-issued grant. `key_agreement` rests on that check.

### Variants

Each variant is the same model built with one flag, and each restores a rule the specification rejected or replaced. The four attacks show that the rule each variant drops is needed.

| Variant | Lemma | Claim | Result |
| --- | --- | --- | --- |
| `-D=NOLIVEGUARD` | `revoked_signer_bypass` | Without the live-binding rule, an approval signed by a revoked key ends a reset with no hold: the bypass fixed in commit `60edc67`. | verified (attack found), 20 steps |
| `-D=UNSCOPED` | `cross_space_vouch_attack` | If a vouch counted in every space, an adversary binding vouched for through an invite to one space would be granted the key of another space the issuer never invited its account to, with no hold, no approval, and no compromise. | verified (attack found), 14 steps |
| `-D=REINVITE` | `reinvite_carries_vouch` | Without `InviteAdmits`, an invite of an account already admitted to a space carries the inviter's vouch there, giving standing in a space where another admission had made the account a member first. | verified (attack found), 12 steps |
| `-D=RETRO` | `retro_vouch_attack` | Without `InviteAfterFirstUse`, an invite made before the client knew the account and never captured authorizes the adversary's binding after the fact: the client grants that space's key to it with no hold and no compromise. | verified (attack found), 14 steps |
| `-D=PREINVITERS` | `key_leaks_only_via_holders_or_grants` | 2a, for the rule before grant standing, in which any accepted binding may receive a grant. | verified, 471 steps |
| `-D=PREINVITERS` | `adversary_grant_targets_justified` | 2b for that rule: an issuer grants to an encryption key the adversary created only if it accepted that binding by first use, after a hold, or through an approval by a compromised or adversary signing key. | verified, 38 steps |
| `-D=PREINVITERS` | `first_contact_substitution` | Under that rule, any member's first-use substitution discloses a space key with no compromise: the exposure grant standing narrows to the inviter. | verified (attack found), 6 steps |

### Relay-witnessed repos (proposal)

`-D=WITNESS` models [Relay-Witnessed Repos](../proposal-reliable-detection.md), a proposal under review, on top of the main model, and answers its Validation section: the relay is an append-only log the adversary writes to but cannot fork, and every binding an honest client accepts either appears in, or leaves a gap in, the history the owner's installations read. The flag adds rules and restrictions only, touching no fact of the base model, so every universal lemma above still holds under it; they are not rerun.

**What it models.**

- **Relays.** The adversary, as every PDS, chooses what each relay publishes for each account, at which position and when (`Relay`). A position, once published, has one value (restriction `RelayPositionOnce`), so a relay never forks. The reference relay is `'ref'`.
- **Entries.** A relayed entry is one record change in an account's repo: a binding (a device record added) or its deletion, `<'deleted', binding>`. Positions are a counter (`s('z')`, `s(s('z'))`, ...) standing for the account's next event in the relay's one stream, so skipped sequence numbers do not appear.
- **Witnesses**, any number, all honest. Each follows one relay for each account, from the account's first position, through a cursor (`WitCur`). At each position it reconstructs the relayed entry (`Recon`), if the adversary chose to serve it, or records a gap (`Gap`). A gap needs no relayed entry, so stream gaps and gaps at positions the relay fills later are covered. A witness never reconstructs what was not relayed, and every witness tails the reference relay (restriction `ReferenceRelayOnly`). Each record names the position before it, so a reader follows the history without skipping.
- **Decisions on witnessed state.** Each device trusts exactly one witness (`UseWitness`, restriction `OneWitness`). Accepting a binding (first use, approval, or re-enrollment completion), starting a re-enrollment hold on a candidate, and treating a binding as deleted (revocation, hold cancellation) each need an entry for it that the client's own witness reconstructed earlier (restrictions `AcceptOnWitnessed`, `HoldOnWitnessed`, `RevokeOnWitnessed`, on the base model's `Accept`, `HoldStart`, and `Revoke` actions).
- **Watching your own account.** Each device follows its own account's history through its witness, in order, from the first position (`OwnCur`, `OwnerAt`). `OwnerSees` is the own-account check on each reconstructed entry: an alarm when the entry is a binding no installation of the account created (no `Device` action for it), or a deletion. `OwnerGap` is the gap warning.

**What it abstracts away**, tested in the [Python model](../model/README.md) and the [prototype](../prototype/README.md) instead:

- **Time:** the 24-hour deadline, frontier and coverage age, liveness and the 60-second frame test, and the hourly frontier. The lemmas say what an installation sees once its frontier reaches a position, and that it reaches every position on the way, not that it gets there; a frontier is a relay position here, not a moment on a witness's clock.
- **Retention, restore and pairing cursors,** and backups. Every witness and every installation starts at the account's first position, as fresh enrollment replays the history (`LATESTART` drops this).
- **Commit structure:** batched operations, inversion, `#sync` fetches, and the PDS replacing a root before serving it, all of which come down to the adversary choosing between reconstruction and a gap. Forks against reported commits and the integrity alarm.
- **What approval needs witnessed:** the model requires the approved binding's device record in a reconstructed entry, not the approval record as well.
- **Several installations** still stand for one another as in the main model; `OwnerSees` is the check any installation of the account makes, and the account's recognized devices are exactly those its honest installations created.

| Lemma | Claim | Proposal rule | Result |
| --- | --- | --- | --- |
| `witness_executable_acceptance` | A client accepts an honest device of another account by first use, on its witness's reconstruction, and an installation of that account sees the same entry, with no alarm, no gap, and no compromise. | sanity | verified, 16 steps |
| `witness_executable_owner_alarm` | A client accepts an impostor binding, and an installation of the account sees it in its witnessed history: the alarm. | sanity | verified, 16 steps |
| `witness_executable_owner_gap` | The client's witness reconstructs the impostor's entry, the owner's records a gap at its position, and the owner sees the gap. | sanity | verified, 16 steps |
| `witness_accepts_only_relayed` | Every accepted binding was published by the reference relay, and reconstructed by the client's own witness, before the acceptance. | Decisions on witnessed state, trusted witnesses | verified, 4 steps |
| `witness_revokes_only_relayed` | Every revocation's deletion was relayed and reconstructed by the client's witness first. | Decisions on witnessed state | verified, 4 steps |
| `witness_owner_step` | An installation's frontier never skips a position: to reach position `s(q)`, it first reached `q`. | Monitoring and history, reconstructed commits | verified, 12 steps |
| `witness_detects_impostor` | If an honest client accepts a binding of an account that none of its installations created, the reference relay published it at a position before the acceptance, and every installation of the account whose frontier reaches that position saw it there (the alarm) or saw a gap there (the warning), whichever witness each uses. With `witness_owner_step`, the same holds once a frontier has passed the position. | Goal; reference relay, watching your own account | verified, 5 steps |
| `witness_detects_hidden_deletion` | If an honest client treats a binding of an account as deleted, every installation of the account whose frontier reaches the deletion's position saw the deletion or a gap there, and with `witness_owner_step` once it has passed it: a reset the PDS hides from its user is detected. | Watching your own account (non-goal 2) | verified, 5 steps |

Each further variant is built with `-D=WITNESS` and one more flag, and restores a rule the proposal rejects or leaves open:

| Variant | Lemma | Claim | Result |
| --- | --- | --- | --- |
| `-D=ANYWITNESS` | `anywitness_accepts_unrelayed` | If a client took any source's word that an entry was published, it would accept an impostor binding of an account for which nothing at all was relayed, so no installation of the account could see it or a gap where it should be. | verified (attack found), 4 steps |
| `-D=TWORELAYS` | `tworelays_hides_impostor` | If witnesses could tail different relays, a client would accept an impostor binding one relay published at a position that an installation of the account processes, through a witness on another relay, without ever seeing the binding or any gap. | verified (attack found), 15 steps |
| `-D=SKIPGAP` | `skipgap_hides_impostor` | If a witness could skip to a later snapshot without recording the interval as a gap, an installation of the account would pass the impostor's position without seeing it or any gap. | verified (attack found), 16 steps |
| `-D=LATESTART` | `latestart_hides_impostor` | If a witness's history for an account began at a later snapshot with nothing recorded before it, as the proposal now allows for "an account the witness starts following", the same: an installation of the account passes the impostor's position, published and deleted before the snapshot, without seeing it or any gap. | verified (attack found), 16 steps |

## Notes on the proofs

- **Sessions are unbounded** in every lemma above. To keep searches finite, acceptance is persistent and "never after revocation" is a restriction rather than a consumed fact, and live-binding counts use a free successor function (`z`, `s(z)`, ...) rather than an associative-commutative multiset.
- **`inviters_grant_targets_justified` and the pre-inviters `adversary_grant_targets_justified` use [`oracle.py`](oracle.py),** which defers goals that lead into unending chains (where an issuer's key came from, how counts were built, how an approval's signer was accepted, how the adversary learned a public key) and puts signature checks first. In the main model, `key_leaks_only_via_holders_or_grants` uses Tamarin's `i` heuristic, since with the default it did not finish within the time cap on an earlier version of the grant-standing rules, and `executable_approved_device` uses `C`, since with the default it does not finish within the cap. Every other lemma uses the default heuristic.
- **Grant standing is a restriction on `IssueGrant`,** not a premise; the vouch reads nothing from the network; and invites add no membership of their own, but name who made an admission (`Admit`). Each alternative multiplies the sources Tamarin precomputes for grants or memberships, and the proofs then slow down severalfold or do not finish.
- **`inviters_standing_scoped` is proved by induction and reused** by `inviters_grant_scope`, the only lemma after it. Standing roots are written as bindings (`<account, pk(sign), pk(enc)>`) in `InheritStanding` and the grant restriction; with an unstructured root, the reused lemma does not apply until Tamarin unrolls the approval chain, and the grant lemma does not finish.
- **The existence lemmas name their witness** and exclude unneeded events (other approvals, grants, holds, revocations, compromise). The exclusions only prune the search; each trace still shows what its lemma claims.
- **Tamarin warns** that a counter `n` matched inside `s(n)` is not derivable by the adversary. This is intended: the counter is client state, not a message.
- **Under `WITNESS`, decisions are gated by restrictions** on the base model's `Accept`, `HoldStart`, and `Revoke` actions, not by new premises, so the base rules, and the sources Tamarin precomputes for them, are unchanged. The relay has no head fact: the adversary names each position, and `RelayPositionOnce` makes it unforgeable. A linear head would make the log sequential too, but only adds a backward chain; with one value per position and witnesses that read positions in order, the two are the same to every reader.
- **Positions are counters, and "passed `n`" is one induction made outside Tamarin.** The detection lemmas say what an installation sees when its frontier reaches `n`; `witness_owner_step` says a frontier reaches every position on the way, by a direct case split, since witness records carry the position before them. Together they give the claim for a frontier that passed `n`, by induction on positions. Stated in Tamarin as one lemma, "passed `n`" is `n << m` on the counter, and `n` must be guarded by the relay event at `n`; that event has its own timepoint, Tamarin's trace induction cannot apply its hypothesis when the event comes last, and the search unrolls positions without end, with or without an oracle. `witness_owner_step`, `witness_accepts_only_relayed`, and `witness_revokes_only_relayed` are reused by the detection lemmas.
- **The detection lemmas use [`oracle_witness.py`](oracle_witness.py),** which solves witness records (`!WRec`) first and defers both cursors (`OwnCur`, `WitCur`), which walk back one position at a time, along with adversary knowledge, which leads into the base model's public-key and grant chains. Unlike `oracle.py`, it puts adversary knowledge last.
- **The `WITNESS` results were run on a laptop,** in Docker with one CPU and a 6 GB heap (`RTS="-N1 -M6g -c"`), one lemma at a time; each took under two minutes except `skipgap_hides_impostor`, about five. Even an existence lemma (`witness_executable_owner_alarm`) ran out of memory in Docker Desktop's default 2 GB VM.
- **The `WITNESS` lemmas are guarded** to exclude its attack variants, since a reused lemma is assumed, not reproved, in each run, and is false under them.
