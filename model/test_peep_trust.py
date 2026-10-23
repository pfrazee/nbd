"""Adversarial cases for the PEEP trust model (TODO-17).

Most classes test SpecClient, the design the specification adopts.
ScopedWitnessAlternative tests the rejected per-space design, kept so the
comparison in COMPARISON.md stays honest.

Run: python3 -I -m unittest discover -s model
"""

import unittest

from peep_trust import REENROLL_HOLD, Binding, ScopedWitnessClient, SpecClient, World

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


class Anchors(Base):
    def setUp(self):
        super().setUp()
        (self.dave,) = self.account("dave", "d0")
        (self.bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob", "dave")
        self.assertTrue(self.meet(self.dave, COMMUNITY))
        # Dave witnesses Bob's honest device.
        self.w.grant("g-dave-bob", COMMUNITY, self.dave, self.bob)

    def test_backward_approval_does_not_admit_newcomer(self):
        m = self.w.add_device(B("bob", "m"))
        self.w.approve(m, self.bob)  # signed by M's own key
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.assertFalse(self.meet(m, COMMUNITY))

    def test_disconnected_device_beside_live_ones_is_declined(self):
        m = self.w.add_device(B("bob", "m"))
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.assertFalse(self.meet(m, COMMUNITY))

    def test_self_issued_grant_is_not_an_anchor(self):
        m = self.w.add_device(B("bob", "m"))
        self.w.grant("g-m-dave", COMMUNITY, m, self.dave)  # garbage, from Bob's repo
        self.w.grant("g-m-self", COMMUNITY, m, m)
        self.assertFalse(self.meet(m, COMMUNITY))

    def test_unaccepted_other_account_cannot_witness(self):
        # One malicious PDS hosts X and Y: YM grants garbage to XM.
        (xa,) = self.account("x", "xa")
        (ya,) = self.account("y", "ya")
        xm = self.w.add_device(B("x", "xm"))
        ym = self.w.add_device(B("y", "ym"))
        self.w.admit(COMMUNITY, "x", "y")
        self.w.grant("g-dave-xa", COMMUNITY, self.dave, xa)
        self.w.grant("g-ym-xm", COMMUNITY, ym, xm)
        self.assertFalse(self.meet(ym, COMMUNITY))  # two roots in Y: declined
        self.assertTrue(self.meet(xa, COMMUNITY))
        self.assertFalse(self.meet(xm, COMMUNITY))

    def test_forged_witness_for_missing_binding_only_holds(self):
        # Fresh account Carol with an honest device; Dave names a binding
        # Carol never had. That reads as a reset: a hold, never admission.
        (carol,) = self.account("carol", "c0")
        self.w.admit(COMMUNITY, "carol")
        self.w.grant("g-dave-fake", COMMUNITY, self.dave, B("carol", "fake"))
        self.assertFalse(self.meet(carol, COMMUNITY))
        self.assertTrue(self.client.hold_pending("carol", COMMUNITY))
        self.w.now += REENROLL_HOLD
        self.assertTrue(self.meet(carol, COMMUNITY))


class WitnessScenes(Base):
    """Shared setup for astra's cross-space and chained-witness cases."""

    def setUp(self):
        super().setUp()
        (self.charlie,) = self.account("charlie", "c0")
        (self.dave,) = self.account("dave", "d0")
        (self.eve,) = self.account("eve", "e0")
        (self.bob,) = self.account("bob", "b0")
        (self.dana,) = self.account("dana", "n0")
        self.w.admit(COMMUNITY, "alice", "charlie", "dave", "bob", "dana")
        self.w.admit(PRIVATE, "alice", "eve", "bob", "dana")
        for b in (self.charlie, self.dave, self.eve):
            self.assertTrue(self.meet(b, COMMUNITY))
        # Honest witnesses for Bob and Dana in each space.
        self.w.grant("g-dave-bob", COMMUNITY, self.dave, self.bob)
        self.w.grant("g-dave-dana", COMMUNITY, self.dave, self.dana)
        self.w.grant("g-eve-bob", PRIVATE, self.eve, self.bob)
        self.w.grant("g-eve-dana", PRIVATE, self.eve, self.dana)
        # Bob's malicious PDS publishes BM; Charlie (community only) colludes.
        self.bm = self.w.add_device(B("bob", "bm"))
        self.w.grant("g-charlie-bm", COMMUNITY, self.charlie, self.bm)


class ColludingWitnessLimitation(WitnessScenes):
    """The spec's documented limitation: a member the client accepted can
    vouch for a device published by someone controlling another member's
    repo, and the resulting pin is account-wide."""

    def test_limitation_colluding_witness_reaches_other_spaces(self):
        self.assertTrue(self.meet(self.bm, COMMUNITY))
        self.assertTrue(self.meet(self.bm, PRIVATE))

    def test_limitation_witness_chain(self):
        self.meet(self.bm, COMMUNITY)
        dm = self.w.add_device(B("dana", "dm"))
        self.w.grant("g-bm-dm", PRIVATE, self.bm, dm)
        self.assertTrue(self.meet(dm, PRIVATE))

    def test_honest_witnesses_alone_admit_nothing_extra(self):
        del self.w.grants["g-charlie-bm"]
        self.assertTrue(self.meet(self.bob, PRIVATE))
        self.assertFalse(self.meet(self.bm, COMMUNITY))
        self.assertFalse(self.meet(self.bm, PRIVATE))

    def test_first_use_pin_is_account_wide_and_persists(self):
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.assertIn(self.bob, self.client.account_wide_set())
        self.w.remove_member(COMMUNITY, "dave")
        self.w.delete_device(self.charlie)
        self.assertTrue(self.meet(self.bob, PRIVATE))

    def test_pinned_account_ignores_witnesses(self):
        fresh = self.CLIENT(self.w, self.alice)
        fresh.pair(self.bob, self.charlie)
        self.assertTrue(fresh.accepted(self.bob, COMMUNITY))
        self.assertFalse(fresh.accepted(self.bm, COMMUNITY))

    def test_pinned_reset_holds_despite_witness(self):
        # Every pinned Bob device is revoked; Charlie's witness for BM must
        # not let BM skip the re-enrollment hold.
        fresh = self.CLIENT(self.w, self.alice)
        fresh.pair(self.bob, self.charlie)
        self.assertTrue(fresh.accepted(self.bob, COMMUNITY))
        self.w.delete_device(self.bob)
        self.assertFalse(fresh.accepted(self.bm, COMMUNITY))
        self.assertTrue(fresh.hold_pending("bob", COMMUNITY))


class ScopedWitnessAlternative(WitnessScenes):
    """The rejected per-space design (ScopedWitnessClient)."""

    CLIENT = ScopedWitnessClient

    def test_reset_holds(self):
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.w.delete_device(self.bob)
        self.w.delete_device(self.bm)
        n = self.w.add_device(B("bob", "n"))
        self.assertFalse(self.meet(n, COMMUNITY))
        self.assertTrue(self.client.hold_pending("bob", COMMUNITY))

    def test_cross_space_witness_is_scoped(self):
        self.assertTrue(self.meet(self.bm, COMMUNITY))
        self.assertFalse(self.meet(self.bm, PRIVATE))
        self.assertTrue(self.meet(self.bob, PRIVATE))

    def test_witness_chain_does_not_launder_scope(self):
        dm = self.w.add_device(B("dana", "dm"))
        self.w.grant("g-bm-dm-private", PRIVATE, self.bm, dm)
        self.w.grant("g-bm-dm-community", COMMUNITY, self.bm, dm)
        self.assertFalse(self.meet(dm, PRIVATE))
        self.assertTrue(self.meet(dm, COMMUNITY))  # within Charlie's reach only

    def test_approvals_inherit_scope(self):
        bm2 = self.w.add_device(B("bob", "bm2"))
        self.w.approve(self.bm, bm2)
        self.assertTrue(self.meet(bm2, COMMUNITY))
        self.assertFalse(self.meet(bm2, PRIVATE))

    def test_scoped_acceptance_never_becomes_account_wide(self):
        self.meet(self.bob, COMMUNITY)
        self.meet(self.bob, PRIVATE)
        self.assertNotIn(self.bob, self.client.account_wide_set())

    def test_witness_ineligibility_lapses_its_bases(self):
        self.assertTrue(self.meet(self.bm, COMMUNITY))
        self.w.remove_member(COMMUNITY, "charlie")
        self.assertFalse(self.meet(self.bm, COMMUNITY))
        self.assertTrue(self.meet(self.bob, COMMUNITY))

    def test_witness_revocation_lapses_its_bases(self):
        self.assertTrue(self.meet(self.bm, COMMUNITY))
        self.w.delete_device(self.charlie)
        self.assertFalse(self.meet(self.bm, COMMUNITY))

    def test_multiple_paths_union_and_lapse_independently(self):
        self.assertTrue(self.meet(self.bob, COMMUNITY))
        self.assertTrue(self.meet(self.bob, PRIVATE))
        self.w.remove_member(PRIVATE, "eve")
        self.assertTrue(self.meet(self.bob, COMMUNITY))

    def test_restore_does_not_widen_scope(self):
        self.assertTrue(self.meet(self.bm, COMMUNITY))
        saved = self.client.export_state()
        other = self.CLIENT(self.w, self.alice)
        other.import_state(saved)
        self.assertFalse(other.accepted(self.bm, PRIVATE))
        self.assertTrue(other.accepted(self.bob, PRIVATE))

    def test_pinned_account_ignores_witnesses(self):
        fresh = self.CLIENT(self.w, self.alice)
        fresh.pair(self.bob, self.charlie)  # both pinned account-wide
        self.assertTrue(fresh.accepted(self.bob, COMMUNITY))
        self.assertFalse(fresh.accepted(self.bm, COMMUNITY))

    def test_first_contact_in_witnessless_space_stays_scoped(self):
        third = "book-club"
        (gus,) = self.account("gus", "g0")
        self.w.admit(third, "alice", "gus")
        self.w.grant("g-dave-gus", COMMUNITY, self.dave, gus)
        self.w.admit(COMMUNITY, "gus")
        self.assertTrue(self.meet(gus, third))  # no anchors in book-club
        self.assertNotIn(gus, self.client.account_wide_set())

    def test_limitation_witnessless_space_falls_back_to_first_contact(self):
        # In a space with no witnesses for Hal, a malicious PDS that steals
        # the root wins there: the per-space fallback is plain TOFU.
        third = "book-club"
        hal = self.w.add_device(B("hal", "h0"))
        hm = self.w.add_device(B("hal", "hm"))
        self.w.approve(hm, hal)
        self.w.admit(COMMUNITY, "hal")
        self.w.admit(third, "alice", "hal")
        self.w.grant("g-dave-hal", COMMUNITY, self.dave, hal)
        self.assertFalse(self.meet(hm, COMMUNITY))  # anchors exclude HM here
        self.assertTrue(self.meet(hm, third))        # but not in book-club


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

    def test_restore_keeps_pins_and_revocations(self):
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

    def test_approval_survives_approver_revocation(self):
        a, b = self.account("bob", "a", "b")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(b, COMMUNITY))
        self.w.delete_device(a)
        self.assertTrue(self.meet(b, COMMUNITY))

    def test_limitation_revoked_approver_with_session_can_still_add(self):
        # Documented: removal must end the session first; a revoked device
        # that can still write publishes approvals clients accept.
        a, b = self.account("bob", "a", "b")
        self.w.admit(COMMUNITY, "alice", "bob")
        self.assertTrue(self.meet(b, COMMUNITY))
        self.w.delete_device(a)
        self.client.sync()
        c = self.w.add_device(B("bob", "c"))
        self.w.approve(a, c)
        self.assertTrue(self.meet(c, COMMUNITY))


class NewcomerResets(Base):
    """A client meeting an account for the first time after its reset."""

    def setUp(self):
        super().setUp()
        (self.bob,) = self.account("bob", "b0")
        self.w.admit(COMMUNITY, "alice", "bob", "carol")
        self.assertTrue(self.meet(self.bob, COMMUNITY))

    def takeover(self):
        self.w.delete_device(self.carol)
        return self.w.add_device(B("carol", "m"))

    def test_recipient_anchor_triggers_hold(self):
        (self.carol,) = self.account("carol", "c0")
        self.w.grant("g-bob-carol", COMMUNITY, self.bob, self.carol)
        m = self.takeover()
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.client.hold_pending("carol", COMMUNITY))

    def test_creator_issuer_anchor_via_provenance(self):
        (self.carol,) = self.account("carol", "c0")
        bob2 = self.w.add_device(B("bob", "b1"))
        self.w.approve(self.bob, bob2)
        # Carol created the space: her grant to Bob, Bob to his own device.
        self.w.grant("g-carol-bob", COMMUNITY, self.carol, self.bob)
        self.w.grant("g-bob-bob2", COMMUNITY, self.bob, bob2, provenance="g-carol-bob")
        self.w.grant("g-bob2-x", COMMUNITY, bob2, B("zed", "z0"), provenance="g-bob-bob2")
        m = self.takeover()
        self.assertFalse(self.meet(m, COMMUNITY))
        self.assertTrue(self.client.hold_pending("carol", COMMUNITY))

    def test_retiring_with_descendants_needs_no_hold(self):
        self.carol, c1 = self.account("carol", "c0", "c1")
        self.w.grant("g-bob-carol", COMMUNITY, self.bob, self.carol)
        self.w.delete_device(self.carol)
        self.assertTrue(self.meet(c1, COMMUNITY))
        self.assertFalse(self.client.hold_pending("carol", COMMUNITY))

    def test_limitation_retiring_only_anchored_branch_holds(self):
        phone, tablet = self.account("carol", "phone", "tablet")
        self.carol = phone
        self.w.grant("g-bob-tablet", COMMUNITY, self.bob, tablet)
        self.w.delete_device(tablet)
        self.assertFalse(self.meet(phone, COMMUNITY))
        self.assertTrue(self.client.hold_pending("carol", COMMUNITY))

    def test_mitigation_survivor_obtains_grant_before_retirement(self):
        phone, tablet = self.account("carol", "phone", "tablet")
        self.carol = phone
        self.w.grant("g-bob-tablet", COMMUNITY, self.bob, tablet)
        self.w.grant("g-bob-phone", COMMUNITY, self.bob, phone)
        self.w.delete_device(tablet)
        self.assertTrue(self.meet(phone, COMMUNITY))


if __name__ == "__main__":
    unittest.main()
