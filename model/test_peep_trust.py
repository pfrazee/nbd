"""Adversarial cases for SpecClient, the design the specification adopts
(TODO-17). Anchor and witness variants are tested in test_variants.py.

Run: python3 -I -m unittest discover -s model
"""

import unittest

from peep_trust import REENROLL_HOLD, Binding, SpecClient, World

COMMUNITY = "community"
PRIVATE = "private"


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


class Base(unittest.TestCase):
    CLIENT = SpecClient

    def setUp(self):
        self.w = World()
        self.alice = self.w.add_device(B("alice", "a0"))
        self.client = self.CLIENT(self.w, self.alice)

    def account(self, name, *devices, root=None):
        """An honest account: first device is the root, which approves the rest."""
        bs = [self.w.add_device(B(name, d)) for d in devices]
        for b in bs[1:]:
            self.w.approve(bs[0], b)
        return bs

    def meet(self, b, space):
        """Have the client evaluate b (running first use if needed)."""
        return self.client.accepted(b, space)


class GenuineFirstContact(Base):
    def test_pins_account_wide_without_anchors(self):
        (bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(bob, COMMUNITY))
        self.assertTrue(self.meet(bob, PRIVATE))

    def test_two_unrelated_roots_are_declined(self):
        (bob,) = self.account("bob", "b0")
        m = self.w.add_device(B("bob", "m"))  # attacker device, no approvals
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertFalse(self.meet(bob, COMMUNITY))
        self.assertFalse(self.meet(m, COMMUNITY))

    def test_limitation_attacker_can_steal_root_at_first_contact(self):
        # Documented exposure: whoever controls the repo at genuine first
        # contact chooses the graph, e.g. M approving the honest root.
        (bob,) = self.account("bob", "b0")
        m = self.w.add_device(B("bob", "m"))
        self.w.approve(m, bob)
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(m, COMMUNITY))


class LeftoverApprovals(Base):
    """Approvals signed by bindings without a present record carry no
    authority of their own and cannot block first use."""

    def test_deleted_attacker_roots_do_not_block_new_contacts(self):
        (bob,) = self.account("bob", "b0")
        existing = self.CLIENT(self.w, self.w.add_device(B("dave", "d0")))
        self.assertTrue(existing.accepted(bob, COMMUNITY))
        m1, m2 = self.w.add_device(B("bob", "m1")), self.w.add_device(B("bob", "m2"))
        self.w.approve(m1, bob)
        self.w.approve(m2, bob)
        self.w.delete_device(m1)  # Bob removes the attacker's devices;
        self.w.delete_device(m2)  # their approvals stay as evidence
        self.assertTrue(existing.accepted(bob, COMMUNITY))
        self.assertTrue(self.meet(bob, COMMUNITY))

    def test_deleted_attacker_cycle_does_not_block_new_contacts(self):
        (bob,) = self.account("bob", "b0")
        m1, m2 = self.w.add_device(B("bob", "m1")), self.w.add_device(B("bob", "m2"))
        self.w.approve(m1, m2)
        self.w.approve(m2, m1)
        self.w.approve(m1, bob)
        self.w.delete_device(m1)
        self.w.delete_device(m2)
        self.assertTrue(self.meet(bob, COMMUNITY))

    def test_lost_root_that_approved_several_survivors(self):
        r, b1, b2 = self.account("bob", "r", "b1", "b2")
        self.w.delete_device(r)
        self.assertTrue(self.meet(b1, COMMUNITY))
        self.assertTrue(self.meet(b2, COMMUNITY))

    def test_recordless_approvals_do_not_block_new_contacts(self):
        (bob,) = self.account("bob", "b0")
        self.w.approve(B("bob", "x1"), bob)  # keys that never had a record
        self.w.approve(B("bob", "x2"), bob)
        self.assertTrue(self.meet(bob, COMMUNITY))

    def test_present_root_must_reach_every_device(self):
        r, a = self.account("bob", "r", "a")
        m = self.w.add_device(B("bob", "m"))
        self.w.approve(B("bob", "x"), m)  # recordless signer covers m, r does not
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertFalse(self.meet(r, COMMUNITY))

    def test_limitation_recordless_signer_can_root_attacker_device(self):
        # Documented first-contact exposure, as under the earlier rule by
        # approving the honest root: create access chooses the graph.
        (bob,) = self.account("bob", "b0")
        m = self.w.add_device(B("bob", "m"))
        x = B("bob", "x")
        self.w.approve(x, bob)
        self.w.approve(x, m)
        self.assertTrue(self.meet(m, COMMUNITY))


class TakeoverAfterFirstContact(Base):
    """Goal 2: after first contact, takeover cannot silently add a device."""

    def setUp(self):
        super().setUp()
        (self.bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(self.bob, COMMUNITY))

    def test_unlinked_device_is_declined(self):
        m = self.w.add_device(B("bob", "m"))
        self.assertFalse(self.meet(m, COMMUNITY))

    def test_backward_approval_is_declined(self):
        m = self.w.add_device(B("bob", "m"))
        self.w.approve(m, self.bob)
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.meet(self.bob, COMMUNITY))

    def test_approved_device_is_accepted(self):
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(self.bob, b1)
        self.assertTrue(self.meet(b1, COMMUNITY))

    def test_approval_acceptance_survives_deleted_approval(self):
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(self.bob, b1)
        self.assertTrue(self.meet(b1, COMMUNITY))
        self.w.approvals["bob"].clear()  # withhold or delete the approval
        self.assertTrue(self.meet(b1, COMMUNITY))
        other = self.CLIENT(self.w, self.alice)
        other.import_state(self.client.export_state())
        self.assertTrue(other.accepted(b1, COMMUNITY))


class FirstUseDirection(Base):
    def test_attacker_cycle_pointing_at_honest_device_is_declined(self):
        r, a = self.account("bob", "r", "a")
        m1, m2 = self.w.add_device(B("bob", "m1")), self.w.add_device(B("bob", "m2"))
        self.w.approve(m1, m2)
        self.w.approve(m2, m1)
        self.w.approve(m1, a)  # no root of their own; points at an honest device
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertFalse(self.meet(m1, COMMUNITY))
        self.assertFalse(self.meet(r, COMMUNITY))  # declined and surfaced


class Holds(Base):
    def setUp(self):
        super().setUp()
        (self.bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.w.delete_device(self.bob)

    def test_replacing_candidate_restarts_hold_and_revokes_it(self):
        m1 = self.w.add_device(B("bob", "m1"))
        self.assertFalse(self.meet(m1, COMMUNITY))
        self.w.now += REENROLL_HOLD - 1
        self.w.delete_device(m1)
        m2 = self.w.add_device(B("bob", "m2"))
        self.assertFalse(self.meet(m2, COMMUNITY))
        self.w.now += 1
        self.assertFalse(self.meet(m2, COMMUNITY))  # only 1h for m2
        self.assertIn(m1, self.client.state.revoked)
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m2, COMMUNITY))

    def test_growing_candidate_restarts_hold(self):
        m1 = self.w.add_device(B("bob", "m1"))
        self.meet(m1, COMMUNITY)
        self.w.now += REENROLL_HOLD - 1
        m2 = self.w.add_device(B("bob", "m2"))
        self.w.approve(m1, m2)  # no revocation; the candidate grows
        self.assertFalse(self.meet(m2, COMMUNITY))
        self.w.now += 1
        self.assertFalse(self.meet(m1, COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m2, COMMUNITY))

    def test_resurrected_record_neither_blocks_nor_joins_candidate(self):
        n = self.w.add_device(B("bob", "n"))
        self.assertFalse(self.meet(n, COMMUNITY))
        self.w.add_device(self.bob)  # revoked record reappears
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(n, COMMUNITY))
        self.assertFalse(self.meet(self.bob, COMMUNITY))

    def test_import_merges_hold_only_for_identical_candidate(self):
        m1 = self.w.add_device(B("bob", "m1"))
        self.meet(m1, COMMUNITY)  # hold for {m1} starts at 0
        old = self.client.export_state()
        self.w.now += 10
        self.w.delete_device(m1)
        m2 = self.w.add_device(B("bob", "m2"))
        fresh = self.CLIENT(self.w, self.alice)
        fresh.pair(self.bob)
        fresh.sync()
        self.assertFalse(fresh.accepted(m2, COMMUNITY))  # hold for {m2} at 10
        fresh.import_state(old)
        self.w.now = REENROLL_HOLD
        self.assertFalse(fresh.accepted(m2, COMMUNITY))
        self.w.now = REENROLL_HOLD + 10
        self.assertTrue(fresh.accepted(m2, COMMUNITY))

    def test_revoked_candidate_still_carries_approval_authority(self):
        b1 = self.w.add_device(B("bob", "b1"))
        self.meet(b1, COMMUNITY)  # observed as a candidate...
        self.w.delete_device(b1)
        self.client.sync()  # ...then revoked
        c = self.w.add_device(B("bob", "c"))
        self.meet(c, COMMUNITY)
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(c, COMMUNITY))  # Bob has a live device again
        b2 = self.w.add_device(B("bob", "b2"))
        self.w.approve(self.bob, b1)  # an authenticated path appears later
        self.w.approve(b1, b2)
        self.assertTrue(self.meet(b2, COMMUNITY))
        self.assertNotIn(b1, self.client.account_wide_set())

    def test_removed_device_key_cannot_end_hold(self):
        m = self.w.add_device(B("bob", "m"))
        self.assertFalse(self.meet(m, COMMUNITY))
        self.w.approve(self.bob, m)  # signed with b0's key after its removal
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m, COMMUNITY))

    def test_removed_device_path_cannot_end_hold(self):
        m = self.w.add_device(B("bob", "m"))
        self.assertFalse(self.meet(m, COMMUNITY))
        self.w.approve(self.bob, B("bob", "k"))  # through a key with no record
        self.w.approve(B("bob", "k"), m)
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))

    def test_import_cannot_resurrect_completed_hold(self):
        m = self.w.add_device(B("bob", "m"))
        self.meet(m, COMMUNITY)
        backup = self.client.export_state()
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m, COMMUNITY))
        self.client.import_state(backup)
        self.assertFalse(self.client.hold_pending("bob", COMMUNITY))
        self.assertTrue(self.meet(m, COMMUNITY))

    def test_import_of_unseen_deleted_binding_keeps_hold_credit(self):
        laptop = self.CLIENT(self.w, self.w.add_device(B("alice", "l")))
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(self.bob, b1)
        self.assertTrue(laptop.accepted(b1, COMMUNITY))  # the laptop's first contact
        backup = laptop.export_state()
        self.w.delete_device(b1)
        self.w.approvals["bob"].clear()  # its approval goes too: only the
                                         # import tells this client about b1
        m = self.w.add_device(B("bob", "m"))
        self.assertFalse(self.meet(m, COMMUNITY))
        self.w.now += REENROLL_HOLD - 1
        self.client.import_state(backup)  # b1 is new to this client
        self.w.now += 1
        self.assertTrue(self.meet(m, COMMUNITY))

    def test_deleting_candidate_cancels_hold(self):
        m = self.w.add_device(B("bob", "m"))
        self.meet(m, COMMUNITY)
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))
        self.w.delete_device(m)
        self.assertFalse(self.client.hold_pending("bob", COMMUNITY))

    def test_import_cannot_resurrect_cancelled_hold(self):
        m = self.w.add_device(B("bob", "m"))
        self.meet(m, COMMUNITY)
        backup = self.client.export_state()
        self.w.delete_device(m)
        self.client.sync()
        self.client.import_state(backup)
        self.assertFalse(self.client.hold_pending("bob", COMMUNITY))

    def test_import_never_compares_clocks_across_domains(self):
        m = self.w.add_device(B("bob", "m"))
        ahead = self.CLIENT(self.w, self.w.add_device(B("alice", "l")),
                            clock_offset=REENROLL_HOLD)
        ahead.pair(self.bob)
        ahead.sync()
        self.assertFalse(self.meet(m, COMMUNITY))  # both observe at once
        self.assertFalse(ahead.accepted(m, COMMUNITY))
        mine, theirs = self.client.export_state(), ahead.export_state()
        self.client.import_state(theirs)
        ahead.import_state(mine)
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertFalse(ahead.accepted(m, COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m, COMMUNITY))
        self.assertTrue(ahead.accepted(m, COMMUNITY))

    def test_import_credits_elapsed_time_for_identical_candidate(self):
        m = self.w.add_device(B("bob", "m"))
        self.meet(m, COMMUNITY)
        self.w.now += 50
        saved = self.client.export_state()
        fresh = self.CLIENT(self.w, self.alice, clock_offset=-1000)
        fresh.pair(self.bob)
        fresh.import_state(saved)
        self.w.now += REENROLL_HOLD - 50 - 1
        self.assertFalse(fresh.accepted(m, COMMUNITY))
        self.w.now += 1
        self.assertTrue(fresh.accepted(m, COMMUNITY))

    def test_backup_storage_time_is_not_credited(self):
        m = self.w.add_device(B("bob", "m"))
        self.meet(m, COMMUNITY)
        backup = self.client.export_state()
        self.w.now += REENROLL_HOLD
        restored = self.CLIENT(self.w, self.alice)
        restored.import_state(backup)
        self.assertFalse(restored.accepted(m, COMMUNITY))


class FirstContactExposure(Base):
    """Documented non-goals: first contact, including just after takeover."""

    def test_limitation_newcomer_after_takeover_gets_no_hold(self):
        (carol,) = self.account("carol", "c0")
        self.w.admit(COMMUNITY, "alice", "carol")
        self.w.delete_device(carol)
        m = self.w.add_device(B("carol", "m"))
        self.assertTrue(self.meet(m, COMMUNITY))

    def test_limitation_hold_is_per_client_not_space_wide(self):
        # Documented: at the same instant, a client that knew the account
        # holds while a newcomer in the same space accepts and can grant.
        (bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(bob, COMMUNITY))
        self.w.delete_device(bob)
        m = self.w.add_device(B("bob", "m"))
        carol = self.CLIENT(self.w, self.w.add_device(B("carol", "c0")))
        self.w.admit(COMMUNITY, "carol")
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(carol.accepted(m, COMMUNITY))

    def test_restore_keeps_revocations_after_resurrection(self):
        (bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(bob, COMMUNITY))
        self.w.delete_device(bob)
        self.client.sync()
        saved = self.client.export_state()
        self.w.add_device(bob)
        other = self.CLIENT(self.w, self.alice)
        other.import_state(saved)
        self.assertFalse(other.accepted(bob, COMMUNITY))


class RevocationAndReset(Base):
    def test_pinned_reset_waits_out_hold(self):
        (bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(bob, COMMUNITY))
        self.w.delete_device(bob)
        m = self.w.add_device(B("bob", "m"))
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(m, COMMUNITY))
        self.assertTrue(self.meet(m, PRIVATE))  # account-wide after the hold

    def test_honest_reset_with_old_approval_records_retained(self):
        r, b1 = self.account("bob", "r", "b1")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(b1, COMMUNITY))
        self.w.delete_device(r)
        self.w.delete_device(b1)  # approval r -> b1 stays in the repo
        n = self.w.add_device(B("bob", "n"))
        self.meet(n, COMMUNITY)
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(n, COMMUNITY))

    def test_resurrected_binding_stays_revoked_and_alarms(self):
        (bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(bob, COMMUNITY))
        self.w.delete_device(bob)
        self.client.sync()
        self.w.add_device(bob)
        self.assertFalse(self.meet(bob, COMMUNITY))
        self.assertIn("resurrected bob/b0", self.client.state.alarms)

    def test_own_removal_alarms(self):
        self.w.delete_device(self.alice)
        self.client.sync()
        self.assertIn(self.alice, self.client.state.revoked)
        self.assertIn("removed alice/a0", self.client.state.alarms)

    def test_imported_own_removal_alarms_once(self):
        laptop = self.w.add_device(B("alice", "l"))
        self.client.pair(laptop)
        other = self.CLIENT(self.w, laptop)
        other.pair(self.alice)
        self.w.delete_device(laptop)
        self.client.sync()  # the phone observes the deletion
        self.w.add_device(laptop)  # laptop never sees the absence itself
        other.import_state(self.client.export_state())
        self.assertIn("removed alice/l", other.state.alarms)
        other.sync()
        self.assertEqual(other.state.alarms.count("removed alice/l"), 1)

    def test_path_through_deleted_device_reaches_descendant(self):
        # Alice was offline while Bob linked b0 -> b1 -> b2 and removed b1.
        (b0,) = self.account("bob", "b0")
        self.assertTrue(self.meet(b0, COMMUNITY))
        b1 = self.w.add_device(B("bob", "b1"))
        self.w.approve(b0, b1)
        b2 = self.w.add_device(B("bob", "b2"))
        self.w.approve(b1, b2)
        self.w.delete_device(b1)
        self.assertTrue(self.meet(b2, COMMUNITY))
        self.assertNotIn(b1, self.client.account_wide_set())  # revoked at once
        self.assertFalse(self.meet(b1, COMMUNITY))

    def test_approval_survives_approver_revocation(self):
        a, b = self.account("bob", "a", "b")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(b, COMMUNITY))
        self.w.delete_device(a)
        self.assertTrue(self.meet(b, COMMUNITY))

    def test_limitation_revoked_key_adds_beside_live_device(self):
        # Documented: while the account keeps a live device, whoever holds a
        # removed device's key and can write to the repo adds devices that
        # clients accept; own-account notices surface them.
        a, b = self.account("bob", "a", "b")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(b, COMMUNITY))
        self.w.delete_device(a)
        self.client.sync()
        c = self.w.add_device(B("bob", "c"))
        self.w.approve(a, c)
        self.assertTrue(self.meet(c, COMMUNITY))

    def test_replacement_seen_before_removal_needs_no_hold(self):
        (old,) = self.account("bob", "old")
        self.assertTrue(self.meet(old, COMMUNITY))
        new = self.w.add_device(B("bob", "new"))
        self.w.approve(old, new)
        self.assertTrue(self.meet(new, COMMUNITY))  # Alice sees the link
        self.w.delete_device(old)
        self.assertTrue(self.meet(new, COMMUNITY))

    def test_replacement_missed_before_removal_is_held(self):
        # Alice was offline while Bob linked a new phone and removed the old
        # one: indistinguishable from an attacker holding the old key.
        (old,) = self.account("bob", "old")
        self.assertTrue(self.meet(old, COMMUNITY))
        new = self.w.add_device(B("bob", "new"))
        self.w.approve(old, new)
        self.w.delete_device(old)
        self.assertFalse(self.meet(new, COMMUNITY))
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(new, COMMUNITY))


if __name__ == "__main__":
    unittest.main()
