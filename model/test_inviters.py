"""Cases for InviterClient, the inviters proposal (proposal-inviters.md):
grant standing, vouches scoped to the invited space, and the first-contact
hold. Each test matches a case in the proposal's "What it protects" table or
its "Before changing the baseline" list.

Run: python3 -I -m unittest discover -s model
"""

import unittest

from nbd_trust import PENDING_INVITE_TTL, REENROLL_HOLD, Binding, InviteRecord, InviterClient, World

BOOK = "book-club"
GARDEN = "garden"


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


class Base(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.alice = InviterClient(self.w, self.w.add_device(B("alice", "a0")))
        self.dave = InviterClient(self.w, self.w.add_device(B("dave", "d0")))

    def account(self, name, *devices):
        """An honest account: first device is the root, which approves the rest."""
        bs = [self.w.add_device(B(name, d)) for d in devices]
        for b in bs[1:]:
            self.w.approve(bs[0], b)
        return bs

    def take_over(self, name, *bindings):
        """Delete every device of the account and enroll an attacker's."""
        for b in self.w.present_devices(name):
            self.w.delete_device(b)
        return self.w.add_device(B(name, "m"))


class Vouching(Base):
    def test_inviter_grants_at_once(self):
        (bob,) = self.account("bob", "b0")
        rec = self.alice.invite(BOOK, "bob")
        self.assertEqual(rec.authorizes, {bob})
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_vouch_is_scoped_to_the_invited_space(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertFalse(self.alice.standing(bob, GARDEN))

    def test_newcomer_holds_first_contact(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertTrue(self.dave.accepted(bob))
        self.assertFalse(self.dave.standing(bob, BOOK))
        self.w.now += REENROLL_HOLD - 1
        self.assertFalse(self.dave.standing(bob, BOOK))
        self.w.now += 1
        self.assertTrue(self.dave.standing(bob, BOOK))
        self.assertTrue(self.dave.standing(bob, GARDEN))

    def test_held_standing_counts_from_this_clients_acceptance(self):
        # Bob's device has existed for days; Dave's hold starts when Dave
        # first accepts it, not when it appeared.
        (bob,) = self.account("bob", "b0")
        self.w.now += 200
        self.assertTrue(self.dave.accepted(bob))
        self.w.now += REENROLL_HOLD - 1
        self.assertFalse(self.dave.standing(bob, BOOK))

    def test_inviting_a_known_account_vouches_for_nothing(self):
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.alice.accepted(bob))
        rec = self.alice.invite(BOOK, "bob")
        self.assertEqual(rec.authorizes, set())
        self.assertEqual(rec.bindings, {bob})
        self.assertFalse(self.alice.standing(bob, BOOK))

    def test_vouch_follows_the_inviters_later_invites(self):
        # Astra: a second new space with someone Alice invited is instant.
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {bob})  # already vouched
        self.assertTrue(self.alice.standing(bob, GARDEN))

    def test_member_met_another_way_waits_in_a_new_space(self):
        # Astra: Alice met Carol as a fellow member, not by inviting her.
        (carol,) = self.account("carol", "c0")
        self.assertTrue(self.alice.accepted(carol))
        self.alice.invite(GARDEN, "carol")
        self.assertFalse(self.alice.standing(carol, GARDEN))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.alice.standing(carol, GARDEN))

    def test_no_invite_for_an_existing_member(self):
        (bob,) = self.account("bob", "b0")
        self.w.admit(BOOK, "bob")
        self.assertIsNone(self.dave.invite(BOOK, "bob"))
        self.assertFalse(self.dave.standing(bob, BOOK))

    def test_approved_device_inherits_vouched_scope(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(bob, b1)
        self.assertTrue(self.alice.standing(b1, BOOK))
        self.assertFalse(self.alice.standing(b1, GARDEN))

    def test_declined_first_use_vouches_for_nothing(self):
        self.account("bob", "b0")
        self.w.add_device(B("bob", "m"))  # a second root
        self.assertEqual(self.alice.invite(BOOK, "bob").authorizes, set())


class Takeover(Base):
    def test_newcomer_after_takeover_holds(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        m = self.take_over("bob")
        self.w.admit(BOOK, "dave")
        self.assertTrue(self.dave.accepted(m))
        self.assertFalse(self.dave.standing(m, BOOK))
        self.assertFalse(self.alice.standing(m, BOOK))  # Alice holds for re-enrollment

    def test_offline_member_first_syncing_after_takeover_holds(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.w.admit(BOOK, "dave")  # Dave was admitted before, but never synced Bob
        m = self.take_over("bob")
        self.assertFalse(self.dave.standing(m, BOOK))

    def test_cross_space_vouch_does_not_reach_the_other_space(self):
        # Astra's case: Bob, a member of Book club, is taken over. Dave, who
        # never met Bob, invites him into Garden, then joins Book club.
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        m = self.take_over("bob")
        self.assertEqual(self.dave.invite(GARDEN, "bob").authorizes, {m})
        self.assertTrue(self.dave.standing(m, GARDEN))
        self.w.admit(BOOK, "dave")
        self.assertFalse(self.dave.standing(m, BOOK))
        self.assertIsNone(self.dave.invite(BOOK, "bob"))  # Bob is already a member there
        self.assertFalse(self.dave.standing(m, BOOK))

    def test_inviting_a_held_pin_does_not_end_its_hold(self):
        # Dave met the taken-over Bob yesterday in another space; inviting
        # him now is not Dave's first contact.
        (bob,) = self.account("bob", "b0")
        m = self.take_over("bob")
        self.assertTrue(self.dave.accepted(m))
        self.w.now += 24
        self.assertEqual(self.dave.invite(GARDEN, "bob").authorizes, set())
        self.assertFalse(self.dave.standing(m, GARDEN))

    def test_inviter_who_knew_the_account_holds(self):
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.alice.accepted(bob))
        m = self.take_over("bob")
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, set())
        self.assertFalse(self.alice.standing(m, GARDEN))

    def test_limitation_inviter_who_never_met_the_account_grants_at_once(self):
        # The remaining exposure: Dave's first contact with Bob is the
        # attacker's device, met while inviting.
        self.account("bob", "b0")
        m = self.take_over("bob")
        self.dave.invite(GARDEN, "bob")
        self.assertTrue(self.dave.standing(m, GARDEN))

    def test_reset_waits_out_both_holds(self):
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.dave.accepted(bob))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.dave.standing(bob, BOOK))
        m = self.take_over("bob")
        self.assertFalse(self.dave.accepted(m))  # re-enrollment hold
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.dave.standing(m, BOOK))  # re-enrolled: every space


class PendingInvites(Base):
    def test_invite_before_install_captures_the_first_device(self):
        # Astra: Bob is invited before installing; Alice is online when he joins.
        rec = self.alice.invite(BOOK, "bob")
        self.assertTrue(rec.pending)
        self.assertTrue(self.w.eligible("bob", BOOK))
        self.w.now += 30
        bob = self.w.add_device(B("bob", "b0"))
        self.assertTrue(self.alice.standing(bob, BOOK))
        capture = self.w.invites[-1]
        self.assertTrue(capture.captures)
        self.assertEqual(capture.bindings, {bob})
        self.assertEqual(capture.authorizes, {bob})

    def test_expired_pending_invite_captures_nothing(self):
        self.alice.invite(BOOK, "bob")
        self.w.now += PENDING_INVITE_TTL
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_pending_capture_follows_later_invites(self):
        self.alice.invite(BOOK, "bob")
        bob = self.w.add_device(B("bob", "b0"))
        self.assertTrue(self.alice.standing(bob, BOOK))
        self.alice.invite(GARDEN, "bob")
        self.assertTrue(self.alice.standing(bob, GARDEN))

    def test_limitation_takeover_enrolling_first_is_captured(self):
        # The remaining exposure, over the pending window.
        self.alice.invite(BOOK, "bob")
        m = self.w.add_device(B("bob", "m"))
        self.assertTrue(self.alice.standing(m, BOOK))

    def test_capture_needs_the_capture_record_published(self):
        self.alice.invite(BOOK, "bob")
        self.w.fail_writes = True
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.w.fail_writes = False
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_newcomer_still_holds_a_captured_device(self):
        self.alice.invite(BOOK, "bob")
        bob = self.w.add_device(B("bob", "b0"))
        self.assertTrue(self.alice.standing(bob, BOOK))
        self.assertFalse(self.dave.standing(bob, BOOK))


class NoRetroactiveAuthorization(Base):
    """Astra's third review: a later vouch must never extend what an older,
    completed invite authorized."""

    def test_laptop_vouch_does_not_reach_the_phones_older_invite(self):
        a1 = InviterClient(self.w, self.w.add_device(B("alice", "a1")))
        self.w.approve(self.alice.own, a1.own)
        self.alice.pair(a1.own)
        a1.pair(self.alice.own)
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.alice.accepted(bob))
        self.assertEqual(self.alice.invite(BOOK, "bob").authorizes, set())
        m = self.take_over("bob")
        self.assertFalse(self.alice.standing(m, BOOK))  # the phone holds
        self.assertEqual(a1.invite(GARDEN, "bob").authorizes, {m})
        self.assertTrue(a1.standing(m, GARDEN))  # the remaining exposure
        self.assertFalse(a1.standing(m, BOOK))
        self.assertFalse(self.alice.standing(m, GARDEN))  # the phone never vouched for m

    def test_expired_pending_invite_is_not_reopened_by_a_later_vouch(self):
        self.alice.invite(BOOK, "bob")
        self.w.now += PENDING_INVITE_TTL
        m = self.w.add_device(B("bob", "m"))
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {m})
        self.assertTrue(self.alice.standing(m, GARDEN))
        self.assertFalse(self.alice.standing(m, BOOK))

    def test_later_invite_authorizes_vouched_devices_and_their_descendants(self):
        # A device Bob linked from a vouched one is authorized too; one Alice
        # met some other way never is.
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(bob, b1)
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {bob, b1})
        self.assertTrue(self.alice.standing(b1, GARDEN))
        (carol,) = self.account("carol", "c0")
        self.assertTrue(self.alice.accepted(carol))
        self.assertEqual(self.alice.invite(GARDEN, "carol").authorizes, set())

    def test_replacement_phone_is_authorized_in_the_next_space(self):
        # Astra's fourth review: Bob replaces his phone and removes the
        # original before Alice's hold on it ends, then Alice invites him on.
        (b0,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.alice.standing(b1, BOOK))
        self.w.delete_device(b0)
        self.w.now += 10
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {b1})
        self.assertTrue(self.alice.standing(b1, GARDEN))


class DurableInvites(Base):
    def test_abandoned_pending_invite_cannot_capture(self):
        # Astra's fourth review: the pending invite never publishes, a host
        # console admits Bob, and the retry drops the stale invite.
        self.w.fail_writes = True
        self.assertTrue(self.alice.invite(BOOK, "bob").pending)
        self.w.admit(BOOK, "bob")
        self.w.fail_writes = False
        self.alice.sync()
        self.assertEqual(self.alice.state.outbox, [])
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.assertFalse(any(r.captures for r in self.w.invites))

    def test_queued_capture_is_dropped_with_its_abandoned_invite(self):
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        bob = self.w.add_device(B("bob", "b0"))
        self.alice.accepted(bob)  # first contact: a capture queues behind the invite
        self.assertEqual(len(self.alice.state.outbox), 2)
        self.w.admit(BOOK, "bob")
        self.w.fail_writes = False
        self.alice.sync()
        self.assertEqual(self.alice.state.outbox, [])
        self.assertEqual(self.w.invites, [])
        self.assertFalse(self.alice.standing(bob, BOOK))

    def test_capture_waits_for_its_pending_invite(self):
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        self.w.fail_writes = False
        bob = self.w.add_device(B("bob", "b0"))
        self.alice.state.outbox and self.alice._first_use("bob")  # capture prepared, invite unsent
        self.assertEqual(self.w.invites, [])  # the capture does not jump the queue
        self.alice.sync()
        self.assertEqual([r.captures for r in self.w.invites], [False, True])
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_second_invite_before_the_first_publishes_is_authorized(self):
        # Astra's fourth review: the vouch is saved when the first record is
        # prepared, not when it publishes.
        (bob,) = self.account("bob", "b0")
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {bob})
        self.w.fail_writes = False
        self.alice.sync()
        self.assertTrue(self.alice.standing(bob, BOOK))
        self.assertTrue(self.alice.standing(bob, GARDEN))

    def test_failed_write_retries_the_vouched_record(self):
        # Astra: pinning before a failed write must not turn the retry into
        # an unvouched invite.
        (bob,) = self.account("bob", "b0")
        self.w.fail_writes = True
        rec = self.alice.invite(BOOK, "bob")
        self.assertEqual(rec.authorizes, {bob})
        self.assertFalse(self.w.eligible("bob", BOOK))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.assertIs(self.alice.invite(BOOK, "bob"), rec)  # the same prepared record
        self.w.fail_writes = False
        self.alice.sync()
        self.assertEqual(self.w.invites, [rec])
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_record_that_would_no_longer_admit_is_dropped(self):
        (bob,) = self.account("bob", "b0")
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        self.w.admit(BOOK, "bob")  # someone else admitted Bob meanwhile
        self.w.fail_writes = False
        self.alice.sync()
        self.assertEqual(self.w.invites, [])
        self.assertFalse(self.alice.standing(bob, BOOK))


class Approvals(Base):
    def test_device_linked_during_hold_survives_its_signers_removal(self):
        # An honest phone swap seen by a newcomer mid-hold: the old phone is
        # removed before its first-contact hold ends, and the new one still
        # earns standing on its own hold.
        (b0,) = self.account("bob", "b0")
        self.assertTrue(self.dave.accepted(b0))
        self.w.now += 10
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.dave.accepted(b1))
        self.w.delete_device(b0)
        self.dave.sync()  # revocations take effect when learned
        self.w.now += REENROLL_HOLD - 1
        self.assertFalse(self.dave.standing(b1, BOOK))
        self.w.now += 1
        self.assertTrue(self.dave.standing(b1, BOOK))

    def test_approved_device_inherits_held_standing(self):
        (b0,) = self.account("bob", "b0")
        self.assertTrue(self.dave.accepted(b0))
        self.w.now += REENROLL_HOLD
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.dave.standing(b1, GARDEN))

    def test_removed_signer_keeps_credit_earned_while_live(self):
        # b0 linked b1 at hour 70 and was removed at hour 80, after its own
        # hold ended; b1 inherits that standing though its own hold has not.
        (b0,) = self.account("bob", "b0")
        self.assertTrue(self.dave.accepted(b0))
        self.w.now += 70
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.dave.accepted(b1))
        self.w.now += 10
        self.w.delete_device(b0)
        self.dave.sync()
        self.w.now += 1
        self.assertTrue(self.dave.standing(b1, BOOK))

    def test_removed_signer_does_not_lend_a_siblings_hold(self):
        # b0 is removed at hour 10 with 10 hours credited. A removed device's
        # key still approves while the account has a live device (b1), but
        # its device inherits b0's credit, not b1's.
        (b0,) = self.account("bob", "b0")
        self.assertTrue(self.dave.accepted(b0))
        self.w.now += 1
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.dave.accepted(b1))
        self.w.now += 9
        self.w.delete_device(b0)
        self.dave.sync()
        self.w.now += 40
        x = self.w.add_device(B("bob", "x"))
        self.w.approve(b0, x)
        self.assertTrue(self.dave.accepted(x))
        self.w.now += 23
        self.assertTrue(self.dave.standing(b1, BOOK))
        self.assertFalse(self.dave.standing(x, BOOK))


class Imports(Base):
    def setUp(self):
        super().setUp()
        self.a1 = InviterClient(self.w, self.w.add_device(B("alice", "a1")), clock_offset=-30)
        self.w.approve(self.alice.own, self.a1.own)
        self.alice.pair(self.a1.own)
        self.a1.pair(self.alice.own)

    def test_invite_record_carries_vouch_to_unpinned_installation(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertTrue(self.a1.standing(bob, BOOK))
        self.assertFalse(self.a1.standing(bob, GARDEN))
        self.a1.invite(GARDEN, "bob")
        self.assertTrue(self.a1.standing(bob, GARDEN))
        self.assertTrue(self.alice.standing(bob, GARDEN))  # learned from a1's record

    def test_stale_import_does_not_reopen_an_abandoned_pending_invite(self):
        # Astra's fifth review: a backup taken while the invite was pending
        # is imported after the invite was abandoned.
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        stale = self.alice.export_state()
        self.w.admit(BOOK, "bob")
        self.w.fail_writes = False
        self.alice.sync()
        self.alice.import_state(stale)
        self.assertEqual(self.alice.state.pending, {})
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.assertFalse(any(r.captures for r in self.w.invites))

    def test_resurrected_pending_state_cannot_capture(self):
        # Defense in depth: even if stale pending state came back by some
        # other path, an abandoned invite captures nothing.
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        entry = dict(self.alice.state.pending)
        self.w.admit(BOOK, "bob")
        self.w.fail_writes = False
        self.alice.sync()
        self.alice.state.pending.update(entry)  # resurrected
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.alice.standing(bob, BOOK))
        self.assertFalse(any(r.captures for r in self.alice.state.outbox + self.w.invites))

    def test_capture_never_publishes_without_its_published_invite(self):
        # Defense in depth: a capture queued with no published pending invite
        # behind it (say, restored alone) stays unsent.
        bob = self.w.add_device(B("bob", "b0"))
        self.alice.state.outbox.append(
            InviteRecord("alice", BOOK, "bob", frozenset({bob}), frozenset({bob}), captures=True))
        self.alice.sync()
        self.assertFalse(any(r.captures for r in self.w.invites))

    def test_pending_invites_do_not_transfer(self):
        self.alice.invite(BOOK, "bob")
        self.a1.import_state(self.alice.export_state())
        self.assertEqual(self.a1.state.pending, {})
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.a1.standing(bob, BOOK))  # a1 meets Bob as a first contact
        self.assertTrue(self.alice.standing(bob, BOOK))  # the inviting installation captures

    def test_abandonment_transfers(self):
        self.w.fail_writes = True
        self.alice.invite(BOOK, "bob")
        self.w.admit(BOOK, "bob")
        self.w.fail_writes = False
        self.alice.sync()
        self.a1.import_state(self.alice.export_state())
        self.assertIn(("bob", BOOK), self.a1.state.abandoned)

    def test_installation_trusting_the_chain_adopts_a_replacements_authorization(self):
        # Astra's fifth review: the laptop already trusts Bob's replacement
        # through the same approval chain the phone vouched for.
        (b0,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertTrue(self.a1.standing(b0, BOOK))  # adopted the phone's vouch
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.alice.accepted(b1) and self.a1.accepted(b1))
        self.w.delete_device(b0)
        self.assertEqual(self.alice.invite(GARDEN, "bob").authorizes, {b1})
        self.assertTrue(self.a1.standing(b1, GARDEN))

    def test_import_judges_a_replacements_authorization_after_its_evidence(self):
        (b0,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.assertTrue(self.a1.standing(b0, BOOK))
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        self.assertTrue(self.alice.accepted(b1))  # a1 has not seen the approval
        self.w.delete_device(b0)
        self.alice.invite(GARDEN, "bob")
        self.w.invites.clear()  # withheld: only the import carries it
        self.w.approvals.clear()
        self.a1.import_state(self.alice.export_state())
        self.assertTrue(self.a1.standing(b1, GARDEN))

    def test_only_the_inviting_installation_captures(self):
        self.alice.invite(BOOK, "bob")
        bob = self.w.add_device(B("bob", "b0"))
        self.assertFalse(self.a1.standing(bob, BOOK))  # a1 met Bob first, as a first contact
        self.assertTrue(self.alice.standing(bob, BOOK))

    def test_invite_record_does_not_end_a_running_hold(self):
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.a1.accepted(bob))
        self.alice.invite(BOOK, "bob")
        self.assertFalse(self.a1.standing(bob, BOOK))

    def test_imported_vouch_does_not_end_a_running_hold(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.w.invites.clear()  # withheld by the PDS
        self.assertTrue(self.a1.accepted(bob))
        self.a1.import_state(self.alice.export_state())
        self.assertFalse(self.a1.standing(bob, BOOK))

    def test_imported_vouch_reaches_unpinned_installation(self):
        (bob,) = self.account("bob", "b0")
        self.alice.invite(BOOK, "bob")
        self.w.invites.clear()
        self.a1.import_state(self.alice.export_state())
        self.assertTrue(self.a1.standing(bob, BOOK))

    def test_first_contact_credit_transfers_without_comparing_clocks(self):
        (bob,) = self.account("bob", "b0")
        self.assertTrue(self.alice.accepted(bob))
        self.w.now += 50
        saved = self.alice.export_state()
        self.w.now += 10  # storage time is not credited
        self.a1.import_state(saved)
        self.w.now += 21
        self.assertFalse(self.a1.standing(bob, BOOK))
        self.w.now += 1
        self.assertTrue(self.a1.standing(bob, BOOK))


if __name__ == "__main__":
    unittest.main()
