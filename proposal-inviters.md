# Proposal: Inviters Vouch at First Contact

Informative. A proposal for discussion, not part of the baseline. It changes who may grant a space key to a device met for the first time, so that the [re-enrollment hold](device-enrollment.md#re-enrollment) protects a whole space rather than only the members who already knew the account.

## Problem

The hold lets a user stop an account takeover at an honest PDS: every client that already knew the account waits at least 72 hours before sharing with the attacker's device, and the user's own installations alarm. But a client meeting the account for the first time after the takeover sees an ordinary [first contact](device-enrollment.md#local-trust) and gets no hold. With one shared key, a single such member can grant the attacker's device the space key at once, and the hold is undone for everyone ([goal 3](README.md#goals), [non-goal 1](README.md#non-goals)).

Today any member can be that client. Every member admitted after the takeover, and every member whose app first meets the account late, is a separate way around the hold.

## Proposal

**Only the member who invited an account may grant to its devices on first contact, and only in spaces they invited it to. Every other member holds first-contact devices before granting to them.**

The inviter's first contact happens at a moment a person chose: Alice decided to invite Bob. Everyone else's first contact happens automatically as their app syncs the membership, which is the case the hold should cover. This keeps exactly one first-contact grant per invitation and makes everything else wait as long as an existing contact would.

The rule only restricts what honest clients grant. A malicious member can already leak the key, so nothing here needs to stop one.

## Rules

This sketch states the changes against the baseline. Terms follow [local trust](device-enrollment.md#local-trust).

### Grant standing

A client's acceptance of a binding is unchanged: first use, approval, or a completed re-enrollment hold. This proposal adds a second property, **grant standing**, which [grant authorization](core.md#grant-authorization) G3 requires of the recipient binding before this client issues a grant in a given space. A binding has grant standing for a client when it is:

1. **Authorized, in a space.** A published [invite record](#invite-records) or capture record of the client's own account, for that space, names the binding in its `authorizes` list. A record authorizes only bindings that were **vouched** for the client when the record was made: bindings it first accepted on first use as part of an invite by its own account, either while making this invite or an earlier one, or by capturing a [pending invite](#pending-invites). Authorization is fixed when the record is made. A later vouch never extends an earlier record, whether that record vouched for nothing, named other devices, or was a pending invite that expired.
2. **Approved.** Accepted by approval from a binding with grant standing. It inherits that binding's scope: a device linked by an authorized device has standing in the spaces that device was authorized in, and a device linked by a held, re-enrolled, or own device has standing in every space.
3. **Held.** The client has credited `REENROLL_HOLD` (72 hours) of elapsed time to it since accepting it, by first use, approval, or an [invite record](#invite-records), under the existing [hold timing](device-enrollment.md#hold-timing). This is the **first-contact hold**. Every binding accepted those ways starts its own, even one that already has standing through rule 1 or 2: otherwise a device linked during its signer's hold would have no standing at all once the signer was removed. Revocation stops the hold's credit but keeps what it earned, so a device the revoked binding linked while it had standing keeps that standing. Clients credit elapsed time before applying an observation, so a removal costs no credit earned before it was learned. Standing from a completed hold applies in every space.
4. **Re-enrolled.** Accepted through a completed re-enrollment hold. Applies in every space.
5. **Own.** An accepted binding of the client's own account. Grants among a user's own devices are unchanged.

Identity pins stay global, as in the baseline: a binding a client accepted in one space is accepted everywhere. Only the permission to grant before a hold ends is scoped, to the spaces the inviter's account admitted the account to. This matters when an account was taken over in a space the inviter later joins. If Dave, who never met Bob, invites the taken-over Bob into a new space, Dave's devices may grant there at once, which is the [remaining exposure](#inviting-someone-youve-never-met-during-their-takeover). If Dave then joins a space where Bob was already a member, his devices hold Bob's attacker device there like any newcomer's would, and don't undo that space's hold: Dave's account never admitted Bob there, and can't, since an invite record only counts if it admitted the account.

A binding without grant standing is still accepted: the client can receive keys from it, show it, and verify its signatures. The client just does not grant to it yet. Receiving a key from a first-contact issuer was already safe, because the key must match the space's [commitment](core.md#key-generation).

### Invites vouch only at first contact

**An invite vouches only for bindings the inviter meets for the first time through an invite.** Inviting an account the inviter already pins lists the bindings the inviter currently accepts for audit, and vouches for nothing new. It authorizes, in its own space, those listed bindings that the inviter had already vouched for, by first meeting them through an earlier invite. Pins the inviter made any other way, including ones whose first-contact hold is still running, are listed but not authorized, and stay held. Invitations never shorten a first-contact hold or a re-enrollment hold.

So no action lets a member skip a hold their own app has started. The only way to grant to a binding early is to be the one who first met it through an invite, or to [verify](#verification) it. Inviting the same person into a second space adds no first contact: the inviter took that risk once, at the first invite, and the second space is one their own account chose to admit the person to.

An invite counts only if it admits the account. A client never publishes an invite record for an account that is already a member of the space, so a vouch cannot be carried into a space whose members were already holding the account's devices. Nor can a vouch reach back into a space the account was admitted to earlier: each record authorizes exactly what was vouched when it was made. Without that, a vouch made through an invite to one space would also authorize every space the inviter's account had ever admitted the account to, including through an unvouched invite made by another of the inviter's installations, or a pending invite that expired.

### Pending invites

An invite is **pending** when the inviter has never pinned the account and the account has no devices yet, as when someone is invited before installing an NBD app. The inviting installation publishes the invite record with no bindings and `pending: true`, which admits the account, and remembers the pending invite. The first time it then accepts that account's devices on first use, it vouches for them, and publishes a **capture record**: an invite record for the pending invite's space naming them in `authorizes`, with a `captures` reference to the pending record. A capture completes only the invite it references. The inviter's other installations adopt the capture as they adopt any invite that authorizes devices.

A pending invite expires after `PENDING_INVITE_TTL` of elapsed time credited by the inviting installation, measured like a hold ([hold timing](device-enrollment.md#hold-timing)); this proposal suggests seven days. An expired pending invite captures nothing, and the account's devices are an ordinary first contact. Only the installation that made the pending invite captures it, since the capture is its own first contact.

Capturing widens the remaining exposure from an instant to a window. If the account is taken over between the invite and its first device, and the attacker enrolls first, the inviter vouches for the attacker's device. That is the same risk as inviting a never-met account during a takeover, and the expiry bounds how long it stays open.

### Durable invites

Pinning on first use, deciding what the invite authorizes, and signing the record are one durable local operation: the client saves the pins, the vouch, and the exact signed record together before any upload. If publication fails, the client retries the same bytes until the write is acknowledged or the user abandons the invite, as for [grant publication](audit.md#publication). It never re-derives the record, so a retry cannot drop an authorization because the first attempt already pinned the account. Inviting the same account to the same space again while an invite is still unsent resumes that invite rather than preparing a second record. Unsent records are resent oldest first. An unsent invite whose account has meanwhile become a member is dropped, since it would no longer admit. Authorized standing in the space starts only once the record is published.

### Invite records

When a client adds an account to a space, it resolves that account's devices, pins them on first use if it has no pin for the account, and publishes an immutable `com.example.nbd.invite` record in its own space repo:

```typescript
{
  version: 1,
  space: string,          // Exact space URI.
  account: string,        // Invited account DID.
  bindings: Binding[],    // The invited account's bindings this client accepted at the invite.
  authorizes: Binding[],  // Listed bindings that were vouched for this client when it made the record.
  pending: boolean,       // True if the account had no devices yet; bindings is then empty.
  captures: string | null,// For a capture record, the pending invite record it completes.
  issuer: DeviceIdentity, // The inviting device.
  proof: bytes            // Ed25519 signature by the inviting device over the record without proof.
}
```

The record does three things:

- **It carries the authorization to the inviter's other installations.** They treat a valid invite or capture from their own account that authorizes devices like a pin copied by [pairing](device-enrollment.md#backup-and-transfer): if the installation has no pin for that account yet, it pins the authorized bindings as vouched, authorized in that record's space. An installation that already pins the account takes a record's authorization only for bindings it already holds as vouched, and otherwise keeps its own state, including any hold it is running. A PDS can withhold a record but not forge it.
- **It makes vouching auditable.** Every member can see who vouched for whom, in which space, and for which devices. If an account turns out to have been taken over, the record names where its first-contact grant came from.
- **It lets the invited account check it.** The invited account's own installations [audit](audit.md#direct-sync) invite records naming their account and alarm on listed bindings they never accepted, just as they do for grants.

A membership change made without an invite record, for example by a host console or an application without NBD support, has no inviter: every member holds.

### Host requirements

None beyond the baseline. The inviter is established by the inviter's own signed record, not by the host, so a malicious host cannot make an honest member skip its holds. A host can still admit any account, which is already a [malicious host decision](README.md#non-goals).

## What it protects

| Scenario | Baseline | With inviters |
| --- | --- | --- |
| Bob's account is taken over and reset. Carol joined the space before the takeover. | Carol holds. | Carol holds. |
| Same, but Dave joins the space after the takeover and first meets Bob's new device. | Dave can grant at once. The space's hold is undone. | Dave holds. |
| Same, but a member's app was offline and first syncs Bob after the takeover. | It can grant at once. | It holds. |
| Same, but Dave first met the taken-over Bob by inviting him into another space. | Dave can grant at once. | Dave holds in this space; his vouch covers only spaces his account admitted Bob to. |
| Alice, who has never met Bob, invites Bob after the takeover. | Alice grants at once. | Alice grants at once. **This is the remaining exposure.** |
| Alice invites Bob before he installs, and the takeover enrolls the first device. | Alice grants at once. | Alice grants at once, if the pending invite has not expired. The same exposure, over the pending window. |
| Alice met the taken-over Bob yesterday in another space, then invites him. | Alice grants at once. | Alice holds: the invite is not her first contact. |
| Alice invited Bob into one space, then invites him into a new one. | Alice grants at once. | Alice grants at once in both: she first met Bob through an invite, and the new invite authorizes his vouched devices. |
| Alice's phone knew Bob and invited him to Book club. After the takeover, Alice's laptop, which never met Bob, invites him to Garden. | Both grant at once once they meet the new device. | The laptop grants in Garden at once (the remaining exposure). In Book club both hold: the phone's invite authorized nothing, and a later vouch never extends it. |
| Alice invited Bob before he installed, and the pending invite expired. Later she first meets his device by inviting him to Garden. | Alice grants at once. | Alice grants at once in Garden. In the first space she holds: the expired invite authorized nothing. |
| Alice, who knew Bob from before the takeover, invites Bob. | Alice holds. | Alice holds. |
| A malicious PDS shows Dave a substituted device for Bob. | Dave grants at once; detected after disclosure, if at all. | Dave holds. With [hold notices](#hold-notices), Bob's installations can alarm before disclosure. |

The hold becomes space-wide: an attacker's device gets a space's key early only if someone whose first contact with the taken-over account came through an invite admits it to that space. That exposure is the same one a Signal-style messenger has at first contact, and it now occurs once per invitation instead of once per newcomer.

## What it does not change

- **First contact by the inviter.** An inviter meeting a taken-over account for the first time trusts the attacker's devices. Only [verification](#verification) at the invite closes that.
- **A malicious PDS hiding a reset from its own user** ([non-goal 2](README.md#non-goals)). [Hold notices](#hold-notices) help here but are a separate addition.
- **Approval by a removed device's key** ([goal 2](README.md#goals)). That path is not a first contact and never had a hold.
- **Honest clocks and application code.**
- **No universal unlock time.** Each client starts its own holds when it first observes a binding, and a grant still needs a running holder, so neither the invitee nor anyone else can be promised when access arrives ([re-enrollment](device-enrollment.md#re-enrollment)).

## User experience

Presented in the [Relaxed](ux-flows/relaxed.md) style, with Paranoid differences noted.

### Creating a space

The creator invites the initial members, so the creator's devices grant at once to everyone they first met through an invite, in this space or an earlier one. Members meeting each other for the first time hold each other, but they rarely need to grant to each other: the creator already did.

**Not every new space is instant.** If the creator met someone some other way, for example as a fellow member of another space, and their first-contact hold for that person is still running, the new space waits for it: "Your device will share with Carol from Friday." Applications that create spaces often, such as one per conversation, will hit this whenever someone starts a space with a person they met in another space less than three days earlier. Someone else in the new space who already has standing for that person can grant instead.

### Adding a member

Alice invites Bob.

1. **Alice taps Invite.** If she has never met Bob, her app pins his devices now, at the invite, not when Bob joins. Paranoid: the confirmation shows Bob's device names ("Bob's devices: iPhone, MacBook") so Alice can notice an obviously wrong list, and offers **Verify in person** where [verification](#verification) exists.
2. **Bob taps Join.** Alice's devices grant in the background, usually within seconds. Push notifications wake her phone as they do today ([distribution](core.md#distribution-scheduling)).
3. **If Alice's devices are offline,** Bob sees "Waiting for Alice's device." After an application-defined window, Bob can ask Alice to open the app. Other members' apps can also grant once their own first-contact holds for Bob end, but each started when that app first saw Bob's devices, and each needs a device running to grant. Bob's app shows no unlock time. Each member's own app can show its own ("Your device will share with Bob from Friday"), as for resets.
4. **Timeline:** "Alice added Bob." Unchanged. Space info can show "Invited by Alice" for each member; Paranoid shows it in the member list.

### Inviting someone who hasn't installed the app

Alice invites Bob, who has an account but no NBD app yet.

1. **Alice taps Invite.** Her app finds no devices for Bob and publishes a [pending invite](#pending-invites). Bob is admitted; the invite link or notification reaches him however the application delivers invites.
2. **Bob installs the app and joins.** The next time Alice's app syncs, it meets Bob's new device for the first time, vouches for it, and publishes the capture. Her devices grant at once, as if Bob had been installed when she invited him.
3. **If Bob takes longer than the pending window,** the invite still admits him, but Alice's app meets his device as an ordinary first contact and holds it like everyone else's. Paranoid can say so on the invite: "If Bob joins after Tuesday, he'll get access when members' apps finish their checks."

### Inviting someone you already know

Alice invites Bob, whom she already knows from another space. If she first met Bob by inviting him somewhere, she grants at once here too: the new invite authorizes the devices she vouched for then, and the ones they have since linked. If she met him some other way, nothing about trust changes: if her app's hold for Bob's devices is over, she grants at once; if it is still running, she keeps holding, and the invite says so: "Your device will share with Bob from Friday." The invite record lists Bob's devices without authorizing them.

### When an invite fails to send

Alice invites Bob while offline or while her PDS is failing writes. Her app has already met Bob and saved the signed invite. It shows "Invite pending, will send when you're back online", and resends the same invite until it lands. Bob is admitted, and Alice's devices may grant to him, only once it does.

### Joining a space that has members

Dave is invited into a space with Alice, Bob, and Carol. Dave's app pins all of them on first sight, as it must. All of them are first contacts for Dave, so Dave's app won't grant to any of them until its own holds end. Dave never notices: everyone already holds the key, and new members are served by their own inviters.

### Linking a new device

Unchanged. Bob's phone links his laptop, his phone grants the laptop his spaces, and other members' apps grant to it in the spaces where they gave his phone standing.

### An account is taken over

Mallory takes over Bob's account at an honest PDS and resets it.

1. Bob's old devices alarm, and members who knew Bob see "Bob reset his devices. This device will share with his new device from Friday." Unchanged.
2. Dave, who joined last night and never knew Bob, sees the same kind of line, with his own app's time. Today Dave's app would quietly share at once.
3. Bob has at least three days from each member's app to notice, change his password, and remove Mallory's device, as before. Now that holds for every member of the space, not just those who knew him.

### Inviting someone you've never met during their takeover

Alice invites Bob the day after the takeover and has never met him in NBD. Her app grants to Mallory's device in that space. Nothing distinguishes this from inviting an honest new contact. Bob's installations alarm when they see Alice's invite record or grant, after disclosure. This is the residual risk, and the copy should not claim otherwise.

### Waiting on an inviter

If Alice is unreachable, Bob waits for her devices or for other members' holds. There is no "let him in now" button: a hold that members can click through whenever someone says they're locked out stops being a hold, and "I'm locked out, can you let me in?" is exactly what an attacker would say. Members who can meet Bob can [verify](#verification) him instead, where verification exists.

## Benefits

1. **The hold protects the space, not just existing contacts.** Goal 3's caveat about members who never knew the account goes away for every member except the inviter, and only in spaces the inviter's account admitted the account to.
2. **No new roles or authority.** It reuses the baseline's acceptance rules and hold timer, adding one predicate to grant authorization and one record type. Nothing depends on the host.
3. **First contact moves to a decision point.** The only first-contact grants happen right after a person chose to invite someone. That is the natural place for a glance at the device list, or for verification.
4. **Verified spaces become practical.** Today verification only helps if every pair of members verifies, because any member can grant at first contact ([device trust](core.md#device-trust)). Under this rule, if every inviter verifies their invitee, every first-contact grant in the space is verified: N verifications, not N². See [verification](#verification).
5. **Vouching is visible.** Invite records show who brought in whom and which devices they vouched for, which helps both audits and people's ordinary judgement.
6. **New spaces are instant with people you invited.** Unlike a blanket first-contact hold, the person who sets up a space can share at once with everyone they first met through an invite, including people invited before they installed the app. People they met some other way wait for the rest of the first-contact hold ([creating a space](#creating-a-space)).

## Costs and risks

1. **Availability depends on the inviter.** A new member gets the key from the inviter's devices, or later from members whose own holds have ended and who have a device running. Inviters are usually online right after inviting, and push notifications cover most of the rest, but a member invited by someone who then goes quiet can wait days, with no time anyone can promise.
2. **Inviters who leave.** If an inviter leaves the space before the invitee joins, the invitee waits on other members' holds. An invite from someone who had already met the invitee, including a second invite, does not help.
3. **One more record type.** Invite records add storage, sync, and audit work. They are small and immutable.
4. **New spaces can wait.** A creator's first-contact hold for someone they met in another space delays a new space with that person, which applications that create many spaces will surface.
5. **Pending invites widen the exposure window.** Between a pending invite and its capture, whoever enrolls the account's first device gets the inviter's vouch.
6. **Model work.** See [before changing the baseline](#before-changing-the-baseline).

## Possible additions

### Hold notices

A client in a first-contact or re-enrollment hold publishes a small record in its own space repo naming the binding it is holding. The held account's installations read these from other members' repos, which their own PDS does not control, and alarm on a binding they never accepted: "Dave's app will trust a device of yours you don't recognise in 3 days." This turns detection of substitution, including by the user's own malicious PDS, from after disclosure into before it, whenever the user's installations can still read the space. It applies to the baseline's re-enrollment hold too, independent of this proposal, but this proposal creates many more holds for it to report.

### Verification

With independent device [verification](TODOs.md#deferred-extensions) available, two uses fit this proposal.

**Verified early grants.** A member who verifies a binding out of band gains grant standing for it in every space, ending any hold for it. This is the only early override: the inviter verifying at the invite, or any member verifying someone stuck waiting or reset. Relaxed apps can offer it or not; they offer no unverified override.

**Verified-only spaces.** A space created with a verified-only policy grants only on verification provenance. In such a space, a binding has standing for a client only when it is:

- verified by this client;
- approved by a binding that has verified standing for this client, inheriting it; or
- an own binding this installation generated, received through its own authenticated [backup or transfer](device-enrollment.md#backup-and-transfer), or accepted by approval from such a binding. Own bindings re-pinned on first use after lost state do not qualify.

Vouched and held standing (rules 1 and 3) do not apply, since both rest on an unverified first contact. Re-enrolled standing (rule 4) does not apply either, since a completed hold proves elapsed time, not identity: an account that resets regains access in a verified-only space only when a member verifies its new binding. Provenance must be tracked, not inferred:

- **Approvals** carry the approving binding's provenance; a verified device's approval passes it on, and an unverified device's approval cannot create it.
- **Imports, backups, and transfers** carry each binding's provenance with it. An importer never upgrades provenance, and keeps the weaker of two records for the same binding.
- **Resets** end it. Revoked bindings lose their verified standing, and nothing about a re-enrollment candidate inherits it.

[TODO-02](TODOs.md#deferred-extensions)'s constraints apply: first-use pins must not stand in for verification, and devices whose trust rests only on a first-use pin must not approve devices in such spaces.

### Comparing invite snapshots

A newcomer could compare its own first-contact view of an account with the bindings in that account's invite record and alarm on a mismatch not explained by approvals. That would expose a PDS showing different members different devices. It must only alarm, never decline: the rejected "warnings only" design in the [model comparison](model/COMPARISON.md) declined honest devices after legitimate resets.

## Before changing the baseline

The rule should be modeled before it changes the specification.

**Revision after Astra's third review.** Astra found that the second revision let a later vouch retroactively authorize an older admission. Alice's phone, which already knew Bob, invited him to Book club unvouched. After Bob's account was taken over, Alice's laptop, which had never met Bob, vouched for the attacker's device by inviting him to Garden. The laptop then had standing in Book club too, with zero hours elapsed. An expired pending invite could be reopened the same way. Each record now authorizes exactly the devices vouched when it was made ([rule 1](#grant-standing)).

- **Python model and prototype: done.** Both now read standing only from records' `authorizes` lists, and both have Astra's two-device case and the expired pending case as tests.
- **Stronger checks.** The invariants in both now check that every authorization traces to a published own record for that space naming the device. The prototype's disclosure check excuses an early grant only through such a record.
- **Mutations.** In each, a mutation restoring the old rule is caught. In the Python model the random walks catch it on their own, so the checks that missed this regression now detect it. The model catches 44 mutations and the prototype 35.
- **Cross-check.** All 40 regenerated traces agree at every step, including each step's authorized devices. None of them re-invites someone into a second space, so that path rests on unit tests in both.
- **Tamarin: done.** Standing in a space now comes only from an authorization emitted by an invite or capture to that space, of a binding vouched no later than that invite.
  - The scope lemmas are strengthened to match: every grant rests on standing whose root, the binding or an approval ancestor, was authorized in that space no earlier than its vouch, or completed a hold.
  - Built with `-D=RETRO`, which restores the old rule, the model finds Astra's attack: an uncaptured invite authorized after the fact by a vouch made through another space's invite.
  - All 23 `check.sh` entries verify, the base lemmas among them.

**Revision after Astra's second review.** [Pending invites](#pending-invites), [durable invites](#durable-invites), and vouches that follow the inviter's later invites were added after the first round of results below.

- **Python model and prototype: done.** Both implement them. Each has new tests: Astra's three reproductions (invite before install, a failed write that must stay vouched, a second new space), pending expiry, a capture of an attacker who enrolled first (the remaining exposure over the pending window), and only the inviting installation capturing.
- **Random walks and mutations.** The walks add an account that installs late and failing writes. The model's walks check every published vouched record against their own record of first contacts. The model catches 40 mutations and the prototype 34.
- **A spec gap the cross-check found.** Re-inviting while an invite was still unsent: the model resumed the unsent invite, and the prototype prepared a second record. Standing came out the same, but the proposal was silent. "Durable invites" now says a re-invite resumes the unsent one.
- **Cross-check: done.** With that settled, all 40 regenerated traces agree at every step, on pending invites, captures, unsent writes, and resends. None of the traces drops a stale unsent invite, so that path rests on unit tests in both.
- **Tamarin: done.** The [variant](formal/README.md#the-inviters-variant) now has per-binding vouches, invites attributed to the inviting account, pending captures, and the rule that an invite counts only if it admits the account.
  - It proves that a grant to an attacker's device in a space needs the issuer's vouch plus an invite of that account to that space, a completed hold, or a compromised signer.
  - It proves Astra's priority by induction: scope survives approval chains, including ones signed by attacker keys (`inviters_standing_scoped`, `inviters_grant_scope`).
  - It finds an attack in each restriction's absence: unscoped vouches leak into other spaces, and without "an invite must admit", a re-invite carries a vouch into a space where the account was already a member.
  - The base lemmas still verify, 21 entries in all.
  - What it still abstracts: time, including pending-invite expiry, and an account's several installations.

**Python model: done.** `InviterClient` in [`model/nbd_trust.py`](model/nbd_trust.py) implements the rule. [`model/test_inviters.py`](model/test_inviters.py) covers every row of [what it protects](#what-it-protects) and cases 1–4 below, the random walks run it with invites into two spaces, and the mutation check catches all eleven inviter-rule mutations. It found two gaps in the earlier text of rule 3, both now fixed above: holds must start on approval as well as first use, and revocation must freeze credit rather than cancel it ([findings](model/README.md#what-the-inviters-variant-found)).

**Prototype: done.** The [prototype](prototype/README.md) runs the rule as a world policy, with invite records published and synced between installations, six scenarios (newcomer after a takeover, cross-space vouch, inviting a known account, a phone linked mid-hold, an offline inviter, and the remaining exposure), random walks under partial views and malicious-PDS behavior, a goal-level disclosure check that excuses a first-contact grant only for an issuer whose account vouched in that space, and ten new mutations, all caught. Under the default policy the baseline is unchanged.

**Cross-check: done.** [`model/test_traces.py`](model/test_traces.py) replays the prototype's 40 inviters traces through `InviterClient`, and the two agree at every step on accepted bindings, holds, standing in each space, and whether each of the viewer's invites vouched.

**Tamarin: done.** The [Tamarin model](formal/README.md#the-inviters-variant) built with `-D=INVITERS` proves, for unbounded sessions against an adversary that controls every PDS, that an issuer grants a space's key to an attacker's device only if it vouched for that device in that same space, completed a first-contact or re-enrollment hold on it, or accepted it through an approval by a compromised or attacker-held key. First use alone no longer suffices, and space-key secrecy still holds. Built with `-D=UNSCOPED` as well, where a vouch counts in every space, it finds Astra's cross-space attack. The base model's lemmas are unchanged and still verify. The model allows a vouch at any time after first use, so the rule that invites vouch only at first contact rests on the Python model and prototype. (The first round also could not show scope through attacker-signed approvals; the revision below proves it.)

Not yet modeled anywhere: the invited account's own installations auditing invite records that name them. The Python model, Tamarin model, and prototype need grant standing with scopes, the first-contact hold, invite records, and a lemma: after first contact, an attacker's device obtains a space's key from an honest client only through a vouch in that space, a completed hold, verification, or a compromised signer. Cases to cover:

1. **Cross-space vouches.** Dave vouches for a taken-over account in one space and then joins another where it was already a member; his devices must hold there.
2. **Invites of known accounts.** Inviting an account the inviter already pins, including one still held, and inviting it again, must change no standing.
3. **Per-client timing.** Holds start when each client first observes a binding; no client's grant may depend on another client's clock or start time.
4. **Imports.** A vouched invite reaching an installation that already pins the account must not end that installation's hold.
5. **Verified-only provenance**, if that addition goes ahead: across approvals, imports, lost state, and resets, with no path to standing that skips verification.

## Open questions

1. Should `PENDING_INVITE_TTL` be fixed, or left to applications, which know how long their invites usually take to be accepted?
2. Should a vouch survive the invitee being removed and later readmitted to the same space, or should readmission be treated like a new invite?
