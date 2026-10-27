# Proposal: Relay-Witnessed Repos

Informative. A proposal for discussion, not part of the baseline. It makes every client judge an account's public device records against the same relay-published history, so that a PDS cannot show one client a device as its user's while hiding it from that user. That turns NBD's answer to first-contact substitution, detection after the fact ([goal 7](README.md#goals)), into something that holds against the PDS doing the substituting.

## Goal

**If any honest client accepts a device as yours that none of your installations generated, transferred, or approved, a running installation of yours alarms within 24 hours, or warns that it cannot check, and one that was not running does so when it next runs. This holds against a malicious PDS, including your own, as long as the reference relay is honest, and so are your application's witness and the witness of the client that accepted the device.**

This is detection, not prevention. For the member who invites the impostor into a space, the alarm reports a disclosure that has already happened. For every other member, accepting the device starts a 72-hour [first-contact hold](device-enrollment.md#grant-standing) or [re-enrollment hold](device-enrollment.md#re-enrollment), so the alarm normally arrives while they are still holding. Either way, the response stays outside the protocol: tell the members, move to another PDS, and [replace](core.md#replacing-a-space) affected spaces. Like holds, the deadline assumes honest clocks ([hold timing](device-enrollment.md#hold-timing)).

## Motivation

Since the [inviters](core.md#invites) change, the remaining first-contact exposure is narrow: a member that meets an impostor of your account and then invites it into a space can share that space's key at once, while everyone else waits out a hold ([goal 3, non-goal 1](README.md#goals)). NBD's defense is that you find out. That only works if you can see what the member saw.

### Why not alert before disclosure

An objection window on invites was considered and set aside. The parties who could object are the ones the attacker has cut off: under a malicious PDS your objection goes through that PDS, which can hide it; after a takeover at an honest PDS your old installations have lost their device records and likely their sessions; and for a pending invite or new account no honest device exists yet. A window would also delay every invite, which is the blanket hold the inviters [rationale](rationale.md#inviters-and-grant-standing) rejected. Checking devices outside the PDS, the deferred [verification](TODOs.md#deferred-extensions) extension, is the real fix. Until then, detection after the fact is the bar, and this proposal is about making it dependable.

### Where detection fails today

Detection works for a takeover at an honest PDS: the attacker has to delete your device records to enroll their own, and your surviving installations see the deletions.

It fails when your own PDS is the attacker. To impersonate you, the PDS must put a device record in your public repo, where the inviter's client reads it. The [single-root rule](device-enrollment.md#local-trust) declines unlinked devices and a PDS cannot sign approvals, so in practice the impostor is published as a reset of your account: your devices' records deleted and the impostor's added. But repo commits do not chain, so the PDS can show the inviter's client that history and your installations another, each with increasing revisions ([divergent histories](device-enrollment.md#revocation-authority)). Your installations would alarm on the impostor's device record and on their own records' deletion ([direct sync](audit.md#direct-sync)) if they ever saw them; they never do. What is left is the grant itself, which sits in the inviter's space repo, and your PDS controls whether you can reach it:

1. **Your PDS gates your access to every space.** The space authority issues read credentials only to members whose PDS supplies a delegation token ([ending access](core.md#ending-access)). A malicious PDS can stop supplying them.
2. **You may never learn the space exists.** If the inviter invites you into a new space, the paths by which your installation learns of it run through your PDS or services it can mislead.
3. **A shared PDS can hide the evidence.** If the inviter's repo is on the same malicious PDS, the grant and invite record sit on a server the attacker controls.

A malicious PDS hiding a reset from its own user ([non-goal 2](README.md#non-goals)) is the same trick: it shows members the deletions and shows its user an unchanged repo.

## Proposal

**Clients accept and remove devices only on the strength of commits the reference relay has published and a trusted witness has reconstructed. Each application runs that witness: it tails the relay, rebuilds every account's device and approval records at every published commit, and reports exactly how far it has got and where it has gaps. Every installation watches its own account's complete history through the witness and alarms on any device it did not accept, even one that was there only briefly.**

Relays are common infrastructure, run apart from PDSes, and have no reason to collude with one. Once every client judges device records against the same relay-published history, a PDS that wants an honest client to accept an impostor has to publish the impostor's device record to the relay, and the user's own installations see it there, or see a gap where it should be. That works whichever spaces were involved, whether or not the user can read them or knows they exist, and whoever hosts the inviter.

A signed commit proves what the account's repo said, not that the relay broadcast it, so publication has to be vouched for by a party the client already trusts. The witness is that party. It belongs to the application, which NBD already trusts with installation keys ([non-goal 6](README.md#non-goals)), so it adds no new party to trust, though as an online service it is a different target from shipped application code. Detection needs two witnesses honest: the one that let the inviter's client accept the device, and the user's own.

Grants stay where they are. The alarm says an impostor device exists, not which spaces leaked to it; an impostor device means treating the account as compromised.

## Rules

This sketch states the changes against the baseline [repo observations](device-enrollment.md#repo-observations) and [direct sync](audit.md#direct-sync) rules.

### Reference relay

NBD names one **reference relay**. Every witness tails it directly, with no intermediary, whatever other relays the application uses. A single relay matters: a PDS can send different relays different histories, so if the inviter's witness followed one relay and the user's followed another, both checks would pass. Tailing directly matters too: an intermediary that drops every message for one repo is not detectable downstream ([sync](https://atproto.com/specs/sync#repository-event-stream)). Witnesses MAY cross-check further relays and SHOULD raise an integrity alarm when two relays published different commits for one account at one revision.

Positions in an account's history, and the cursors installations keep and carry in backups and transfers, are reference-relay sequence numbers, not anything local to a witness, so an installation can move between witnesses.

### Trusted witnesses

A client trusts exactly one **witness**: its application's, reached at an origin the application ships with over an authenticated channel, or the client itself if it tails the reference relay directly. A client MUST NOT treat a commit as published on the word of any other source, including a PDS or another application's witness, however validly the commit is signed. Relay-signed publication receipts would remove the need to trust the witness for this; atproto has none today.

### Reconstructed commits

A witness **reconstructs** a published commit when it holds the account's complete device and approval collections at that commit's exact root:

- **A `#commit` event,** by applying its operations to the reconstructed state at the previous commit. The result MUST match the commit's root, and the reversed operations MUST produce the previous root ([inversion](https://atproto.com/specs/sync#commit-events)). A `#commit` whose previous state the witness does not hold, such as the first after a gap, is reconstructed as a `#sync` is.
- **A `#sync` event,** which carries only the commit, by fetching the repo (from the relay where it serves one, otherwise from the PDS) and verifying it against that commit's exact root. A PDS serves only its current repo, so an honest write can land between the event and the fetch. A later snapshot reconstructs the earlier root only together with every relayed commit between them, whose operations, inverted back from the snapshot, must produce the earlier root.
- **After a stream gap,** the witness restarts each account from the relay's latest published commit for it, reconstructed by a verified fetch.

A published commit the witness cannot reconstruct is a **gap** in that account's history: a `#sync` root the PDS replaced before serving it, beyond what the later commits explain; a commit whose operations fail the root or inversion check; or a commit whose fetch has not succeeded within `FETCH_TIMEOUT` (proposed: 1 hour). Until then, a commit awaiting a fetch is unprocessed: the account's frontier (below) does not pass it, but other accounts' progress is unaffected. Gaps are permanent records: later resynchronization to a newer state does not erase them.

Where a witness's history for an account starts matters as much as what it records. If the witness does not hold the account's history from its first event on the reference relay, because it started following the account later, pruned history past `WITNESS_RETENTION`, or rebuilt its state, the interval it lacks is a gap in that history, reported like any other.

### Decisions on witnessed state

A client MUST base these decisions only on commits its trusted witness reports as published and reconstructed, in the history of the account the binding names:

- accepting a binding by [first use](device-enrollment.md#local-trust) or as a [re-enrollment](device-enrollment.md#re-enrollment) candidate;
- accepting a binding by [approval](device-enrollment.md#approvals), which needs both the approval record and the target's device record in reconstructed commits;
- completing a re-enrollment hold, which re-checks that the candidate is present at the latest reconstructed commit;
- treating a device record as present or absent, including [revocation](device-enrollment.md#device-revocations).

A client meeting an account it has never pinned starts from the account's latest published commit, which must be reconstructed. The client may still fetch records and proofs from the PDS, but checks that the commit they prove against is one the witness reports. A commit the witness does not yet report returns `INCOMPLETE`: the client waits and retries, normally for seconds. A PDS-served commit raises an integrity alarm, with both signed commits as proof, when it differs from the reported commit at the same revision, and when the witness's frontier for the account has passed its revision but the witness never reported it.

### Witness progress

Neither field of a relay event shows how current a witness is: sequence numbers may skip values ([sequence numbers](https://atproto.com/specs/event-stream#sequence-numbers)), and event `time` is not authoritative ([event stream](https://atproto.com/specs/sync#repository-event-stream)). Nor does receiving frames: an honest relay with a backlog for one slow subscriber still delivers pings, while that subscriber falls hours behind. A witness instead measures progress against the relay's head, on its own clock:

- **Continuity.** The witness follows the reference relay through one subscription, resuming after each disconnect from the cursor of the last event it processed. A resume the relay refuses as outdated, or any other break the witness cannot resume across, is a **stream gap** covering everything since that event. Skipped sequence numbers within a continuous subscription are not gaps.
- **Live.** The witness is live at a moment on its clock when its subscription is open and it has processed every event up to a relay head sequence number that it learned from the relay within the previous 60 seconds. Delivery delay therefore counts against the witness.

With every answer, a witness MUST report, for each account it serves, its **frontier age**: the time elapsed on its own clock since it was last live with no unprocessed commit for that account, as a duration, never as a timestamp, following the [hold timing](device-enrollment.md#hold-timing) rule against comparing clocks. It also reports its stream gaps, where its history for the account starts, and the commits it could not reconstruct. A stream gap is a gap in every account's history. This relies on the relay delivering one stream to every subscriber, which an honest relay does.

Witnesses MUST retain every reconstructed state change and gap in the device and approval collections for at least `WITNESS_RETENTION` (proposed: 90 days), and serve each account's history from a cursor.

### Monitoring and history

An installation tracks two separate things for its own account:

- **Monitoring frontier.** The latest moment, on its witness's clock, up to which the installation has processed every commit the witness received for the account, each one either reconstructed and applied or recorded as a gap. A recorded gap does not hold the frontier back: once the installation has recorded and surfaced it, the frontier moves past it. The installation's **coverage age** is the frontier age the witness reported when the frontier last advanced, plus the time elapsed locally since then: from a monotonic clock that keeps counting while the device sleeps (or, where the platform's does not, treating each wake as a restart), and across restarts the wall-clock interval since its last checkpoint. If it cannot establish that interval, for example because the clock moved backward, it treats its coverage age as exceeding any limit until the frontier next advances.
- **Historical gaps.** Every gap in the account's history is kept permanently: a commit the witness could not reconstruct, a stream gap, or an interval the witness lacks, whether before its history starts or older than its retention. Each one raises its own gap warning naming the commit or interval. The user can acknowledge a gap warning; that acknowledges only that gap, and never suppresses warnings about later gaps or the liveness warning.

A witness that answers quickly with stale or partial history does not advance the frontier: coverage, not a successful response, is what counts.

### Watching your own account

Each installation MUST follow its own account's history through its witness, persisting its monitoring frontier and the cursor up to which it has processed that history. It applies the baseline [own-account notices](audit.md#direct-sync) and alarms to every device record and approval that appears in **any** reconstructed commit, not only the latest, so a device the PDS publishes and then deletes still alarms. It does the same for deletions of its account's device records, which is how it learns of a reset its PDS hides from it. An approval that appears after its signer's device record was deleted, which only a removed device's key could produce ([revoked signers](device-enrollment.md#approval-validation)), raises an alarm, not just a notice.

Where the history starts:

- **Fresh enrollment.** Replay the account's history from its first event on the reference relay, and present every binding that appeared in it, including deleted ones, for the user to recognize, as [starting over](device-enrollment.md#total-device-loss) does for current bindings. A brand-new account should have none; one that does was impersonated before its first device existed, for example around a [pending invite](core.md#invites). Any part of that history the witness lacks raises a gap warning, so an impersonation older than the witness's history is not silently lost.
- **Restore or pairing.** Resume from the cursor in the backup or transferred state, not from the moment of restoring, and replay everything since. Any part of the history after that cursor that the witness lacks, because it pruned it or its history starts later, raises a gap warning for that interval.

### Pinned accounts

A client MUST advance its observed state for each pinned account by processing, in order, every commit its witness received for that account: applying each reconstructed one and recording each gap. It never skips to a later snapshot without recording the interval skipped as a gap. A gap in a pinned account's history is reported in audit as an interval the client could not check. Across such a gap the baseline [missed-deletion](device-enrollment.md#revocation-authority) limit still applies: a binding present on both sides may have been deleted and recreated in between. Without gaps, no deletion followed by recreation goes unseen.

### Liveness and deadline

An installation MUST show a liveness warning whenever its coverage age for its own account reaches 24 hours, naming what failed: the witness is unreachable, the witness is not live, or a fetch for the account is outstanding. On launch it MAY first spend up to a minute catching up. The deadline runs from the frontier, not from when a check completes, so neither a freshness allowance nor an outstanding fetch can stretch it: a device accepted at any moment is either processed, and alarms, or leaves the coverage age at 24 hours, and warns, within 24 hours.

Installations SHOULD advance the frontier at least hourly while running, so that the warning shows only for real failures. The warning is not an integrity alarm, since an outage looks the same as withholding. It clears when the coverage age falls back under 24 hours, and it MUST NOT be dismissible while it lasts. Historical gap warnings are separate and do not affect it.

## What it achieves

| Attack | Baseline | With this proposal |
| --- | --- | --- |
| Your PDS shows an inviter an impostor device | Detected only if you can read the inviter's grant | Your installations see the device record and alarm, or see a gap and warn, within 24 hours |
| ...in a space you can't read or never learned of | Undetected | Same: the alarm comes from your public repo |
| ...with the inviter on the same PDS | Undetected | Same |
| A device published briefly, then deleted | Undetected | Alarms: watching covers every reconstructed commit |
| A root broadcast with an impostor, then replaced before your witness fetches it | Undetected | A gap your installations warn on |
| Your PDS hides a reset from you ([non-goal 2](README.md#non-goals)) | Detected after disclosure, if at all | Alarms, normally while members' re-enrollment holds still run |
| An impostor added and deleted while you were offline or restoring from backup | Undetected | Replayed from your saved cursor, or a gap warning where the witness lacks the history |
| An impostor captured by a pending invite and deleted before you first install | Undetected | Presented at fresh enrollment, or a gap warning where the witness lacks the history |
| Your witness falls behind an honest relay | Not applicable | Coverage ages against the relay's head; warns within 24 hours |
| Divergent histories, missed deletions | Undetectable | Every client judges the same history; missed deletions only across reported gaps |

## What stays out of reach

- **A dishonest reference relay, or a dishonest witness on either side.** A relay colluding with a PDS can show different witnesses different histories again. The inviter's witness can let its clients accept a commit the relay never carried, and your own can hide what it saw from you, as dishonest application code already could. Cross-checking further relays reduces the first.
- **Malicious host admissions.** An attacker's own account, admitted by the space host, has legitimate device records and raises no alarm here ([non-goal 3](README.md#non-goals)).
- **No honest installation running.** Detection needs one of your installations online, as own-account notices already do.
- **The inviter's disclosure.** For the space it invites the impostor into, the alarm comes after the key is shared.
- **Which spaces leaked.** Learning that from grants still depends on space access, which your PDS gates.
- **Distinguishing withholding from failure.** A gap or stalled coverage produces a warning, not proof of an attack. A PDS can create own-account gaps at will, so harmless ones can train a user to acknowledge the one that hides an impostor.
- **Dishonest clocks.** A clock set back while an installation is stopped shortens its count of coverage age, as it shortens holds.

## Costs

- **Trust anchors.** The reference relay joins the trust model, and naming one concentrates trust in its operator, in practice probably Bluesky's relay. Each application's witness is trusted by that application's clients, and every user relies on the witnesses of the applications their contacts use.
- **Availability.** If the reference relay or the witness is down or lagging, clients cannot accept or remove devices until it recovers. Existing trust and grants to devices that already have standing are unaffected.
- **Infrastructure.** Every application runs a witness that tails the full firehose, checks the relay's head, reconstructs two collections for every account, fetches repos on `#sync` events and after gaps, and retains 90 days of changes. Clients that cannot reach one may tail the relay themselves, at much higher cost.
- **Latency.** Accepting a device waits for the relay and the witness, normally seconds.

## Discussion

### Rejected: public contact records

Before relay witnessing, a heavier design closed the same gaps differently. A client would publish a public `contact` record naming each device it accepted on first use or through re-enrollment, confirm it had reached an index its own PDS does not operate, and only then grant; installations would look their own account up in such indexes daily. It was rejected because the records publicly reveal who shares encrypted spaces with whom, and because it added a record type, a confirmation step, and an index dependency to a scheme that promises to be no big deal to implement. Relay witnessing gets the same coverage from records that are already public.

### Rejected: liveness on space access only

A lighter design kept the baseline and only added a warning when an installation could not sync its spaces, plus a 24-hour sweep. It turns a blocked space into a visible warning, but leaves spaces the user never learned of, and a shared PDS, out of reach. Relay witnessing makes those cases detectable, so the space-access warning is no longer the main defense.

### Rejected: any witness

An earlier draft let clients use any witness, since witnessed commits verify on their own. Review found that a signature proves only what the repo said, not that the relay broadcast it: a malicious PDS acting as a witness could supply validly signed commits that never reached the relay. Clients now trust only their application's witness or their own relay connection.

### Rejected: liveness by received frames

An earlier draft called a witness live when the relay had delivered any frame within the last 60 seconds. All three models found that an honest relay can keep a slow subscriber's pings flowing while its events queue hours behind, so the witness looked current while missing an impostor accepted elsewhere. Liveness is now measured against the relay's head.

### Rejected: history starting at a snapshot

An earlier draft let a witness start following an account at a verified snapshot, which became the start of its history. An impostor published and deleted before that snapshot then left nothing in the history: no binding and no gap. The Tamarin model finds this attack (`LATESTART`), and the Python model and prototype find its everyday forms, a fresh enrollment more than 90 days after a pending invite's capture and an installation whose witness started following its account later. The interval a witness lacks is now a gap.

## Questions for review

1. Should NBD name a single reference relay, let each deployment name one, or require cross-checking several? Who decides, and how does a witness learn it?
2. How does a witness learn the relay's head? atproto has no standard request for a relay's current sequence number; should NBD rely on one, or on a head carried in the stream?
3. Should witnesses ask each other whether they reconstructed a commit, so that a gap another honest witness filled counts as withholding and raises an alarm rather than a warning? That would blunt gap farming.
4. Should an account invited before it had devices be followed from the invite's cursor, rather than met at its latest commit? It would catch a quick takeover before the first device, at the cost of first-using whatever device was published first.
5. Are 90 days of retention and a 1-hour fetch timeout the right values, and should the witness progress report be specified as a lexicon so that applications can share witnesses?

## Validation

All three artifacts model the proposal as a variant beside the specified design. Their findings are folded into the rules above.

- **[Python model](model/README.md)** (`WitnessClient`, `test_witness.py`, `test_witness_walks.py`): 185 tests pass, including every row of the table above, the out-of-reach cases, and the reviewed edge cases; seeded walks check the goal after every step; all 22 witness mutations, one per rule, are caught.
- **[Prototype](prototype/README.md)** (the `witness` policy, scenarios 27 to 35 with specified-rule twins, `test/witness.test.ts`): 156 tests and the type check pass; walks under the policy check the goal; all 55 mutations, 15 of them for the witness rules, are caught; 40 traces are recorded in `traces-witness/` for replay by the Python model, not yet wired.
- **[Tamarin model](formal/README.md)** (`-D=WITNESS`): every accepted binding was relayed and reconstructed by the accepting client's witness first, and every installation of the account that reaches its position saw it or a gap there (`witness_detects_impostor`), and likewise for a deletion behind a revocation (`witness_detects_hidden_deletion`); an installation's frontier reaches every position on the way (`witness_owner_step`), which gives the same for a frontier that has passed the position. Four variants find the attacks the rules prevent: any witness, two relays, skipping without a gap, and a late start. Time, liveness, retention, and cursors are abstracted there and tested in the other two.

The models found the flaws now fixed in [witness progress](#witness-progress) (liveness against the head), [reconstructed commits](#reconstructed-commits) (where history starts, fetch timeouts, root checks, honest writes racing a fetch), [watching your own account](#watching-your-own-account) (fresh enrollment, cursors, removed-key approvals), [monitoring](#monitoring-and-history) (sleeping clocks), [decisions](#decisions-on-witnessed-state) (approvals, hold completion, unreported commits), and the [goal](#goal) (the accepting client's witness, honest clocks). The fix for honest writes racing a `#sync` fetch is not modeled.

## Spec changes

- [device-enrollment.md](device-enrollment.md#repo-observations): the reference relay, trusted witnesses, reconstructed commits as the basis for acceptance and removal, forks against reported commits, and complete history for pinned accounts; narrow the divergent-histories limit to a dishonest relay or witness and the missed-deletion limit to reported gaps.
- [device-enrollment.md](device-enrollment.md#backup-and-transfer): backups and transfers carry the own-account cursor as a reference-relay sequence number.
- [audit.md](audit.md#direct-sync): witness progress, watching your own account's full history, enrollment and restore starting points, the removed-key approval alarm, and liveness; replace "detection has no guaranteed deadline" with the 24-hour bound.
- [rationale.md](rationale.md): the divergent-history caveats.
- [README.md](README.md#goals): restate goal 7 as the goal above, shrink non-goal 2 to a colluding relay or witness, and add both to the trust assumptions.
- [ux-flows](ux-flows/relaxed.md): the liveness and gap warnings in both flows.
