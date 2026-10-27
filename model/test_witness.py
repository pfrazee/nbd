"""Cases for WitnessClient (proposal-reliable-detection.md, relay-witnessed
repos): each row of the proposal's "What it achieves" table, with the
baseline InviterClient fooled under a forking PDS where it applies; the
"What stays out of reach" items (`test_limitation_`); Astra's cases; the
revision rules (`Revisions`: unrelayed commits against consecutive
reconstructions, honest relay drops, far-future and non-increasing
revisions); and
findings about the proposal (`test_finding_`), each showing the goal failing
under the rule as written and, where there is one, holding under the fix.

Run: python3 -I -m unittest discover -s model
"""

import unittest

from nbd_trust import Approval, Binding, InviterClient
from nbd_witness import (CLOCK_SKEW, FETCH_TIMEOUT, INCOMPLETE, INF, LIVENESS_LIMIT, RELAY_REPLAY_WINDOW,
                         REV_ALLOWANCE, WITNESS_RETENTION, ClientView, Commit, LyingWitness, RelayWorld,
                         RogueWitness, Witness, WitnessClient, goal_violations, rev_at)

BOOK = "book-club"


def B(account: str, device: str) -> Binding:
    return Binding(account, device)


class NoFreshGap(WitnessClient):
    """The earlier draft: fresh enrollment replays only what the witness has."""

    FRESH_HISTORY_GAP = False


class Base(unittest.TestCase):
    """Alice runs app1, whose witness is app1; Bob and Carol run app2. One
    PDS hosts everyone and may misbehave; the relay and witnesses are honest."""

    def setUp(self):
        w = self.w = RelayWorld()
        w.now = 100.0
        self.app1 = Witness(w, "app1")
        self.app2 = Witness(w, "app2")
        self.a0 = w.add_device(B("alice", "a0"))
        self.a1 = w.link(self.a0, B("alice", "a1"))
        self.b0 = w.add_device(B("bob", "b0"))
        self.c0 = w.add_device(B("carol", "c0"))
        self.legit = {self.a0, self.a1}
        self.m = B("alice", "m")
        self.alice = WitnessClient(w, self.a0, self.app1)
        self.alice.pair(self.a1)
        self.bob = WitnessClient(w, self.b0, self.app2)
        self.carol = WitnessClient(w, self.c0, self.app2)
        for c in (self.alice, self.bob, self.carol):
            c.sync()
        # The baseline design reads whatever the PDS serves each client.
        self.base_alice = InviterClient(ClientView(w, "alice/a0"), self.a0)
        self.base_alice.pair(self.a1)
        self.base_bob = InviterClient(ClientView(w, "bob/b0"), self.b0)
        self.base_carol = InviterClient(ClientView(w, "carol/c0"), self.c0)

    def graft(self, **kw):
        """Publish an impostor device that approves Alice's root, so first
        use accepts it with her real devices."""
        return self.w.pds_write("alice", add=[self.m], approve=[(self.m, self.a0)], **kw)

    def ungraft(self, **kw):
        return self.w.pds_write("alice", delete=[self.m], unapprove=[(self.m, self.a0)], **kw)

    def goal(self, installs=None, clients=None):
        return goal_violations("alice", installs or [self.alice], clients or [self.bob, self.carol],
                               self.legit, self.w.now)

    def hours(self, n, *clients, step=1.0):
        """Let time pass, running clients advancing their frontier hourly."""
        end = self.w.now + n
        while self.w.now < end - 1e-9:
            self.w.now = min(end, self.w.now + step)
            for c in clients:
                c.sync()


def baseline_grant_audit(owner: InviterClient, w: RelayWorld, readable):
    """The baseline's remaining detection: grants to own bindings the owner
    never accepted, found only in spaces it can read."""
    return {g.recipient for g in w.grants.values()
            if g.space in readable and g.recipient.account == owner.own.account
            and g.recipient not in owner.state.accepted}


class Achieves(Base):
    def test_impostor_shown_to_an_inviter(self):
        # Baseline: the PDS forks what it serves Bob; Alice never sees it.
        self.w.fork("bob/b0", "alice", add=[self.m], approve=[(self.m, self.a0)])
        self.assertTrue(self.base_bob.accepted(self.m))
        self.w.grant("g1", BOOK, self.b0, self.m)
        self.base_alice.sync()
        self.assertEqual(self.base_alice.state.alarms, [])
        self.assertEqual(baseline_grant_audit(self.base_alice, self.w, set()), set())
        self.assertEqual(baseline_grant_audit(self.base_alice, self.w, {BOOK}), {self.m})
        # Witnessed: a commit the relay never saw is not a basis for acceptance.
        self.assertIs(self.bob.accepted(self.m), INCOMPLETE)
        self.w.unfork("bob/b0", "alice")
        self.graft()  # the PDS has to publish the impostor to fool Bob
        self.assertTrue(self.bob.accepted(self.m))
        self.alice.sync()
        self.assertIn(self.m, self.alice.state.own_alarms)
        self.assertEqual(self.goal(), [])

    def test_impostor_in_a_space_alice_cannot_read(self):
        self.graft()
        rec = self.bob.invite(BOOK, "alice")
        self.assertIn(self.m, rec.authorizes)
        self.w.grant("g1", BOOK, self.b0, self.m)
        self.assertEqual(baseline_grant_audit(self.base_alice, self.w, set()), set())
        self.alice.sync()  # no space access involved
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_inviter_on_the_same_pds(self):
        self.graft()
        self.bob.invite(BOOK, "alice")
        self.w.grant("g1", BOOK, self.b0, self.m)
        self.w.grants.clear()  # the shared PDS hides the evidence
        self.w.invites.clear()
        self.assertEqual(baseline_grant_audit(self.base_alice, self.w, {BOOK}), set())
        self.alice.sync()
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_device_published_briefly_then_deleted(self):
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.assertTrue(self.base_bob.accepted(self.m))
        self.ungraft()
        self.base_alice.sync()
        self.assertEqual(self.base_alice.state.alarms, [])
        self.alice.sync()  # first look after the deletion
        self.assertIn(self.m, self.alice.state.own_alarms)
        self.assertEqual(self.goal(), [])

    def test_sync_root_replaced_before_alices_witness_fetches(self):
        s = self.graft(kind="sync")
        self.assertTrue(self.bob.accepted(self.m))  # app2 fetched it at once
        seq = self.bob.state.basis[self.m][0]
        self.w.replace_sync("alice")
        self.ungraft()
        self.alice.sync()
        self.assertNotIn(self.m, self.alice.state.seen_own)
        self.assertTrue(self.alice.gap_covers(seq))
        self.assertTrue(self.alice.gap_warnings())
        self.assertEqual(self.goal(), [])
        self.assertEqual(s.rev, self.app1.commit_at("alice", s.rev).rev)

    def test_pds_hides_a_reset_from_alice(self):
        self.assertTrue(self.bob.accepted(self.a0))  # Bob knew Alice
        self.assertTrue(self.base_bob.accepted(self.a0))
        honest = self.w.head["alice"]
        self.w.pds_write("alice", add=[self.m], delete=[self.a0, self.a1])
        self.w.fork("alice/a0", "alice", add=[self.a0, self.a1], delete=[self.m])
        # Baseline: Alice sees an unchanged repo; members wait out the hold.
        self.base_alice.sync()
        self.assertEqual(self.base_alice.state.alarms, [])
        self.assertTrue(self.base_bob.hold_pending("alice"))
        self.w.now += 72
        self.assertTrue(self.base_bob.accepted(self.m))
        self.w.now -= 72
        # Witnessed: Alice reads the deletions in the relay's history.
        self.assertTrue(self.bob.hold_pending("alice"))
        self.alice.sync()
        self.assertIn(f"removed {self.a0}", self.alice.state.alarms)
        self.assertIn(self.m, self.alice.state.own_alarms)
        self.assertTrue(self.bob.hold_pending("alice"))  # the alarm arrives during the hold
        self.assertNotEqual(honest, self.w.head["alice"])

    def test_impostor_added_and_deleted_while_offline(self):
        self.alice.stop()
        self.w.now += 5
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += 5
        self.alice.start()  # replays from its saved cursor
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_impostor_added_and_deleted_before_a_restore(self):
        backup = self.alice.export_state()
        self.w.now += 5
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += 50
        restored = WitnessClient.restore(self.w, backup, self.app1)
        self.assertIn(self.m, restored.state.own_alarms)
        self.assertEqual(self.goal([restored]), [])

    def test_divergent_histories_are_one_history(self):
        self.assertTrue(self.bob.accepted(self.a1))
        self.assertTrue(self.carol.accepted(self.a1))
        self.assertTrue(self.base_bob.accepted(self.a1))
        self.assertTrue(self.base_carol.accepted(self.a1))
        # The PDS shows Carol a1's deletion and Bob nothing.
        self.w.fork("carol/c0", "alice", delete=[self.a1])
        self.assertTrue(self.base_bob.accepted(self.a1))
        self.assertFalse(self.base_carol.accepted(self.a1))
        self.assertTrue(self.bob.accepted(self.a1))
        self.assertIs(self.carol.accepted(self.a1), INCOMPLETE)  # not published
        self.assertIn(self.a1, self.carol.account_wide_set())

    def test_missed_deletion_is_seen_in_history(self):
        self.assertTrue(self.bob.accepted(self.a1))
        self.assertTrue(self.base_bob.accepted(self.a1))
        self.w.delete_device(self.a1)
        self.w.add_device(self.a1)  # recreated between two of Bob's reads
        self.assertTrue(self.base_bob.accepted(self.a1))  # baseline misses it
        self.assertFalse(self.bob.accepted(self.a1))
        self.assertIn(f"resurrected {self.a1}", self.bob.state.alarms)

    def test_missed_deletion_only_across_a_reported_gap(self):
        self.assertTrue(self.bob.accepted(self.a1))
        self.w.withhold("app2", "alice")
        self.w.publish_sync("alice", delete=[self.a1])
        self.bob.sync()
        self.w.withhold("app2", "alice", on=False)
        self.w.add_device(self.a1)
        self.assertTrue(self.bob.accepted(self.a1))
        self.assertTrue(self.bob.state.audit_gaps["alice"])


class Rules(Base):
    def test_incomplete_until_the_witness_reports_the_commit(self):
        self.app2.lag = 0.5
        self.w.now += 1
        self.graft()
        self.assertIs(self.bob.accepted(self.m), INCOMPLETE)
        self.w.now += 0.5
        self.assertTrue(self.bob.accepted(self.m))

    def test_unreachable_witness_decides_nothing(self):
        self.app2.reachable = False
        self.assertIs(self.bob.accepted(self.a0), INCOMPLETE)

    def test_fork_at_a_witnessed_revision_alarms(self):
        head = self.w.head["alice"]
        self.w.fork("bob/b0", "alice", add=[self.m], approve=[(self.m, self.a0)], rev=head.rev)
        self.assertFalse(self.bob.accepted(self.m))
        (wc, served), = self.bob.state.forks
        self.assertEqual((wc, served.rev), (head, head.rev))
        self.assertNotEqual(wc, served)

    def test_own_installation_detects_a_fork_of_its_own_repo(self):
        self.w.pds_write("alice", delete=[self.a1])
        self.w.fork("alice/a0", "alice", add=[self.a1], rev=self.w.head["alice"].rev)
        self.alice.sync()
        self.assertTrue(self.alice.state.forks)

    def test_stream_gap_after_an_outage_longer_than_the_replay_window(self):
        self.app1.set_up(False)
        self.w.now += 1
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += RELAY_REPLAY_WINDOW + 1
        self.app1.set_up(True)
        self.alice.sync()
        self.assertIn("stream-gap", {g.kind for g in self.alice.state.gaps})
        self.assertEqual(self.goal(), [])

    def test_outage_inside_the_replay_window_resumes_without_a_gap(self):
        self.app1.set_up(False)
        self.w.now += 1
        self.graft()
        self.ungraft()
        self.w.now += 10
        self.app1.set_up(True)
        self.alice.sync()
        self.assertEqual(self.alice.state.gaps, [])
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_restore_older_than_retention_warns_for_the_interval(self):
        backup = self.alice.export_state()
        self.w.now += 10
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += WITNESS_RETENTION + 1
        self.app1.poll()
        restored = WitnessClient.restore(self.w, backup, self.app1)
        self.assertNotIn(self.m, restored.state.seen_own)
        self.assertIn("retention", {g.kind for g in restored.state.gaps})
        self.assertEqual(self.goal([restored]), [])

    def test_fresh_enrollment_presents_bindings_that_ever_appeared(self):
        # Bob invites Erin before she has a device; her PDS enrolls an
        # impostor, which Bob captures; it is gone by the time she installs.
        rec = self.bob.invite(BOOK, "erin")
        self.assertTrue(rec.pending)
        em = self.w.add_device(B("erin", "m"))
        self.assertTrue(self.bob.accepted(em))
        self.w.delete_device(em)
        self.w.now += 30
        e0 = self.w.add_device(B("erin", "e0"))
        erin = WitnessClient(self.w, e0, self.app1)
        erin.sync()
        self.assertIn(em, erin.state.presented)
        self.assertEqual(goal_violations("erin", [erin], [self.bob], {e0}, self.w.now), [])

    def test_replay_does_not_revoke_a_binding_before_its_record_appears(self):
        # A fresh installation replays from before a1 existed; a commit older
        # than a binding's record proves nothing about it.
        fresh = WitnessClient(self.w, self.a1, self.app1)
        fresh.pair(self.a0)
        fresh.sync()
        self.assertEqual(fresh.account_wide_set(), {self.a0, self.a1})
        self.assertEqual(fresh.state.alarms, [])
        self.assertEqual(self.alice.account_wide_set(), {self.a0, self.a1})

    def test_pairing_resumes_from_the_transferred_cursor(self):
        self.alice.stop()
        self.w.now += 1
        self.graft()
        self.ungraft()
        a2 = self.w.link(self.a0, B("alice", "a2"))  # linking from a0's device
        self.legit.add(a2)
        paired = WitnessClient(self.w, a2, self.app1, transfer=self.alice.state)
        paired.sync()
        self.assertIn(self.m, paired.state.own_alarms)
        self.assertNotIn(a2, paired.state.own_alarms)

    def test_linked_own_device_is_a_notice_not_an_alarm(self):
        a2 = self.w.link(self.a1, B("alice", "a2"))
        self.alice.sync()
        self.assertIn(a2, self.alice.state.notices)
        self.assertEqual(self.alice.state.own_alarms, set())

    def test_stale_answer_does_not_advance_the_frontier(self):
        self.app1.set_up(False)  # answers, but no longer tails the relay
        self.hours(30, self.alice)
        self.assertGreater(self.alice.coverage_age(), LIVENESS_LIMIT)
        self.assertTrue(self.alice.liveness_warning())
        self.app1.set_up(True)
        self.alice.sync()
        self.assertFalse(self.alice.liveness_warning())

    def test_coverage_counts_across_restarts(self):
        self.alice.stop()
        self.w.now += 25
        self.app1.reachable = False
        self.alice.start()
        self.assertTrue(self.alice.liveness_warning())

    def test_backward_clock_across_a_restart_is_stale(self):
        self.alice.stop()
        self.alice.clock_offset -= 50
        self.w.now += 1
        self.app1.reachable = False
        self.alice.start()
        self.assertTrue(self.alice.liveness_warning())
        self.app1.reachable = True
        self.alice.sync()
        self.assertFalse(self.alice.liveness_warning())

    def test_restored_installation_starts_stale(self):
        backup = self.alice.export_state()
        self.app1.reachable = False
        restored = WitnessClient(self.w, backup.own, self.app1, transfer=backup)
        self.assertTrue(restored.liveness_warning())

    def test_hidden_intermediate_commit_leaves_a_gap(self):
        # A commit served but never relayed; the next relayed commit's
        # operations then fail inversion against the witness's state.
        self.w.pds_write("alice", add=[self.m], approve=[(self.m, self.a0)], relay=False)
        self.ungraft()
        self.alice.sync()
        self.assertTrue(self.alice.state.gaps)
        self.assertNotIn(self.m, self.alice.state.seen_own)

    def test_pinned_account_is_not_advanced_by_snapshot(self):
        self.assertTrue(self.bob.accepted(self.a0))
        self.app2.lag = 10  # Bob's witness is behind
        self.w.now += 1
        self.w.delete_device(self.a1)
        self.w.add_device(self.a1)
        self.w.now += 10
        self.app2.lag = 0
        self.assertFalse(self.bob.accepted(self.a1))  # both commits processed in order


class Frontier(Base):
    """The event-time frontier, clock skew, and revision cursors."""

    def test_frontier_is_relay_time_not_delivery_time(self):
        self.app1.lag = 2
        self.w.now += 1
        c = self.w.post("alice")
        t = self.w.relay[-1].time
        self.w.now += 3
        self.alice.sync()
        e = self.app1.latest_rec("alice")
        self.assertEqual((e.hi, e.rtime), (c.rev, t))
        self.assertAlmostEqual(e.wtime - e.rtime, 2)  # delivered 2 hours after the relay sequenced it
        self.assertAlmostEqual(self.app1.frontier("alice"), self.w.now - 2)
        self.assertAlmostEqual(self.alice.coverage_age(), 2)

    def test_frontier_ahead_of_the_witness_clock_is_a_fault(self):
        self.app1.clock_offset = -2 * CLOCK_SKEW  # the witness's clock is 10 minutes slow
        self.alice.sync()
        self.assertTrue(self.app1.skew_fault("alice"))
        self.assertEqual(self.app1.frontier_age("alice"), INF)
        self.assertTrue(self.alice.liveness_warning())  # the owner warns
        self.app1.clock_offset = 0.0  # resolved
        self.alice.sync()
        self.assertFalse(self.alice.liveness_warning())

    def test_skew_fault_lasts_while_the_witness_stalls(self):
        # Found by the walks: a fault that cleared once the frontier fell
        # more than the skew behind the slow clock let a stalled witness
        # understate its frontier age by the clock's whole error.
        self.app1.clock_offset = -0.5
        self.alice.sync()
        self.assertTrue(self.alice.liveness_warning())
        self.app1.set_up(False)
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(LIVENESS_LIMIT + 0.25, self.alice, step=0.5)
        self.assertTrue(self.app1.skew_fault("alice"))
        self.assertTrue(self.alice.liveness_warning())
        self.assertEqual(self.goal(), [])

    def test_finding_slow_witness_clock_is_undetected_once_behind(self):
        # Finding 11. The skew check sees a slow witness clock only while the
        # frontier is current. A clock that goes slow while the witness is
        # down or behind is never a fault, and understates frontier age by
        # its whole error, so the warning comes that much late.
        self.app1.set_up(False)
        self.app1.clock_offset = -0.5
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(LIVENESS_LIMIT + 0.25, self.alice, step=0.5)
        self.assertFalse(self.app1.skew_fault("alice"))
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.goal())

    def test_frontier_within_the_skew_is_no_fault(self):
        self.app1.clock_offset = -CLOCK_SKEW / 2
        self.alice.sync()
        self.assertFalse(self.app1.skew_fault("alice"))
        self.assertFalse(self.alice.liveness_warning())

    def test_finding_skew_within_the_allowance_stretches_the_deadline(self):
        # Finding 10. A witness clock slow by less than CLOCK_SKEW is no
        # fault, but it understates frontier age by that much, so the
        # warning comes up to 5 minutes after the 24 hours the goal states.
        self.app1.clock_offset = -0.9 * CLOCK_SKEW
        self.app1.set_up(False)
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(LIVENESS_LIMIT + 0.8 * CLOCK_SKEW, self.alice, step=0.5)
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.goal())
        self.assertEqual(goal_violations("alice", [self.alice], [self.bob], self.legit, self.w.now,
                                         slack=CLOCK_SKEW), [])

    def test_pending_fetch_holds_its_accounts_frontier_at_its_time(self):
        self.w.stall("app1", "alice")
        self.w.now += 1
        s = self.graft(kind="sync")
        t = self.w.relay[-1].time
        self.w.now += 0.5
        self.w.post("bob")
        self.alice.sync()
        self.assertAlmostEqual(self.app1.frontier("alice"), t)
        self.assertAlmostEqual(self.app1.frontier("bob"), self.w.now)  # other accounts unaffected
        self.assertAlmostEqual(self.alice.coverage_age(), 0.5)
        self.assertIsNone(self.app1.commit_at("alice", s.rev))  # not yet reported
        self.w.now += FETCH_TIMEOUT
        self.alice.sync()  # timed out: a gap, and the frontier moves on
        self.assertTrue(self.alice.gap_covers(s.rev))
        self.assertAlmostEqual(self.alice.coverage_age(), 0.0)

    def test_commits_behind_a_pending_fetch_wait_in_order(self):
        self.w.stall("app1", "alice")
        s = self.graft(kind="sync")
        self.ungraft()  # a #commit queued behind the stalled #sync
        self.alice.sync()
        self.assertEqual(self.alice.state.gaps, [])
        self.w.stall("app1", "alice", on=False)
        self.alice.sync()
        self.assertTrue(self.alice.gap_covers(s.rev))  # root replaced: the #sync is a gap
        self.assertNotIn(self.m, self.alice.state.seen_own)
        self.assertEqual(self.app1.state["alice"], self.w.head["alice"].root)

    def _bob_posts(self, n):
        for _ in range(n):
            self.w.post("bob")

    def test_restore_onto_another_applications_witness_resumes_by_revision(self):
        # app3's history of Alice starts before the backup but is much
        # shorter than app1's log, so only a revision cursor means the same
        # place on both.
        self._bob_posts(10)
        app3 = Witness(self.w, "app3", from_now=True)
        self.w.post("alice")
        self.alice.sync()
        backup = self.alice.export_state()
        self.w.now += 5
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += 5
        restored = WitnessClient.restore(self.w, backup, app3)
        self.assertIn(self.m, restored.state.own_alarms)
        self.assertEqual(restored.state.gaps, [])
        self.assertEqual(self.goal([restored]), [])

    def test_pairing_onto_a_witness_whose_history_starts_later_warns(self):
        self.alice.stop()
        self.w.now += 1
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        rev = self.bob.state.basis[self.m][0]
        self.ungraft()
        self._bob_posts(10)
        app3 = Witness(self.w, "app3", from_now=True)  # starts following Alice after the impostor
        a2 = self.w.link(self.a0, B("alice", "a2"))
        self.legit.add(a2)
        paired = WitnessClient(self.w, a2, app3, transfer=self.alice.state)
        paired.sync()
        self.assertNotIn(self.m, paired.state.seen_own)
        self.assertIn("before history", {g.kind for g in paired.state.gaps})
        self.assertTrue(paired.gap_covers(rev))
        self.assertEqual(self.goal([paired]), [])

    def test_restore_onto_a_pruned_witness_warns_for_the_interval(self):
        backup = self.alice.export_state()
        self.w.now += 10
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += WITNESS_RETENTION + 1
        self.app2.poll()
        restored = WitnessClient.restore(self.w, backup, self.app2)  # another application's witness
        self.assertIn("retention", {g.kind for g in restored.state.gaps})
        self.assertTrue(restored.gap_covers(self.bob.state.basis[self.m][0]))
        self.assertEqual(self.goal([restored]), [])


class Limitations(Base):
    def test_limitation_dishonest_relay(self):
        self.w.relay_hides["app1"] = {"alice"}
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.relay_hides.clear()
        self.alice.sync()
        self.assertEqual(self.alice.state.own_alarms, set())
        self.assertEqual(self.alice.state.gaps, [])
        # Alice's cursor (a revision) never reaches the hidden commits, so the
        # goal fails by its deadline clause, strictly after 24 hours.
        self.w.now += LIVENESS_LIMIT + 1
        self.alice.sync()
        self.assertTrue(self.goal())

    def test_limitation_inviters_witness_dishonest(self):
        # Finding 9. The goal assumes only the relay and *Alice's*
        # application's witness are honest, but Bob decides on his own
        # application's witness. If that server lies, Bob accepts a commit the
        # relay never carried, and Alice's installations have nothing to see.
        liar = LyingWitness(self.w, "app3")
        dave = WitnessClient(self.w, self.w.add_device(B("dave", "d0")), liar)
        dave.sync()
        head = self.w.head["alice"]
        liar.lie(Commit("alice", head.rev + 1, head.devices | {self.m},
                        head.approvals | {Approval(self.m, self.a0)}, head.other))
        self.assertTrue(dave.accepted(self.m))
        self.hours(25, self.alice)
        self.assertEqual(self.alice.state.own_alarms, set())
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.goal(clients=[dave]))

    def test_limitation_malicious_host_admission(self):
        x0 = self.w.add_device(B("mallory", "x0"))
        self.w.admit(BOOK, "mallory")
        self.assertTrue(self.bob.accepted(x0))
        self.alice.sync()
        self.assertEqual(self.alice.state.own_alarms, set())
        self.assertEqual(goal_violations("mallory", [], [self.bob], {x0}, self.w.now), [])

    def test_limitation_no_installation_running(self):
        self.alice.stop()
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.w.now += 100
        self.assertEqual(self.alice.state.own_alarms, set())
        self.alice.start()  # and once one runs again, it alarms
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_limitation_inviters_disclosure_precedes_alarm(self):
        self.graft()
        self.bob.invite(BOOK, "alice")
        self.assertTrue(self.bob.standing(self.m, BOOK))  # Bob may grant at once
        self.assertFalse(self.carol.standing(self.m, BOOK))  # Carol holds
        self.assertEqual(self.alice.state.own_alarms, set())
        self.alice.sync()
        self.assertIn(self.m, self.alice.state.own_alarms)

    def test_limitation_clock_set_back_while_stopped(self):
        # Finding 4: the goal silently assumes honest clocks. A clock set
        # back by less than the downtime shortens the coverage age, and an
        # unreachable witness then produces no warning in time.
        self.alice.stop()
        self.app1.reachable = False
        self.w.now += 1
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.alice.clock_offset -= 20
        self.w.now += 29
        self.alice.start()
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.goal())


class Astra(Base):
    def test_unrelayed_commit_from_another_source_is_not_accepted(self):
        # Validly signed by Alice's PDS, never relayed, offered by a source
        # other than Bob's own witness; the PDS serves Bob its relayed head.
        head = self.w.head["alice"]
        c = Commit("alice", head.rev + 1, head.devices | {self.m},
                   head.approvals | {Approval(self.m, self.a0)})
        self.bob.consult(RogueWitness(c))
        self.assertFalse(self.bob.accepted(self.m))
        self.assertNotIn(self.m, self.bob.state.accepted)

    def test_replaced_sync_root_stays_a_gap_after_resync(self):
        self.w.withhold("app1", "alice")  # served to app2 only, as if replaced first
        self.graft(kind="sync")
        self.assertTrue(self.bob.accepted(self.m))
        self.alice.sync()
        n = len(self.alice.state.gaps)
        self.assertGreater(n, 0)
        self.w.withhold("app1", "alice", on=False)
        self.w.publish_sync("alice")  # resynchronizes app1 to a newer root
        self.ungraft()
        self.alice.sync()
        self.assertEqual(self.app1.state["alice"], self.w.head["alice"].root)
        self.assertGreaterEqual(len(self.alice.state.gaps), n)
        self.assertTrue(self.alice.gap_covers(self.bob.state.basis[self.m][0]))

    def test_restore_from_an_old_backup_replays_from_its_cursor(self):
        backup = self.alice.export_state()
        self.hours(20, self.alice)
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(2, self.alice)
        self.ungraft()
        self.hours(20)
        # Alice's device is wiped before it next syncs; she restores the old backup.
        restored = WitnessClient.restore(self.w, backup, self.app1)
        self.assertIn(self.m, restored.state.own_alarms)

    def test_snapshots_around_delete_and_recreate_record_a_gap(self):
        self.assertTrue(self.bob.accepted(self.a1))
        self.w.publish_sync("alice", delete=[self.a1])
        self.w.replace_sync("alice")
        self.w.add_device(self.a1)  # recreated before app2 fetched the deletion
        self.assertTrue(self.bob.accepted(self.a1))  # the missed-deletion limit
        self.assertTrue(self.bob.state.audit_gaps.get("alice"))

    def test_deadline_counts_from_the_frontier_not_the_check(self):
        # Impostor accepted at hour 0; Alice's check at hour 0.5 returns a
        # history ending at hour -0.5. She must warn by hour 24.
        self.alice.sync()  # hour -0.5
        self.app1.set_up(False)
        self.w.now += 0.5
        self.graft()  # hour 0
        self.assertTrue(self.bob.accepted(self.m))
        self.w.now += 0.5
        self.alice.sync()  # hour 0.5
        self.assertAlmostEqual(self.alice.coverage_age(), 1.0)
        self.hours(22.5, self.alice, step=0.5)
        self.assertFalse(self.alice.liveness_warning())  # hour 23
        self.hours(1, self.alice, step=0.5)
        self.assertAlmostEqual(self.w.now, 124.5)  # hour 24
        self.assertTrue(self.alice.liveness_warning())
        self.assertEqual(self.goal(), [])

    def test_one_unrecoverable_gap_does_not_fail_liveness_forever(self):
        self.w.withhold("app1", "alice")
        self.graft(kind="sync")
        self.alice.sync()
        self.assertTrue(self.alice.gap_warnings())
        self.w.withhold("app1", "alice", on=False)
        self.hours(48, self.alice)
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.alice.gap_warnings())

    def test_acknowledging_a_gap_suppresses_neither_new_gaps_nor_liveness(self):
        self.w.withhold("app1", "alice")
        self.graft(kind="sync")
        self.ungraft(kind="sync")
        self.alice.sync()
        g1, g2 = self.alice.gap_warnings()
        self.alice.acknowledge(g1)
        self.assertEqual(self.alice.gap_warnings(), [g2])  # only that gap
        self.w.publish_sync("alice")
        self.alice.sync()
        self.assertEqual(len(self.alice.gap_warnings()), 2)  # a later gap still warns
        for g in self.alice.gap_warnings():
            self.alice.acknowledge(g)
        self.app1.set_up(False)
        self.hours(25, self.alice)
        self.assertTrue(self.alice.liveness_warning())


class Revisions(Base):
    """Unrelayed commits served by the PDS, honest relay drops, and
    revisions far in the future or not increasing."""

    def integrity_alarms(self, c):
        return [a for a in c.state.alarms if a.startswith(("fork", "unrelayed", "revision"))]

    def test_unrelayed_commit_between_consecutive_reconstructions_alarms(self):
        before = self.w.head["alice"]
        hidden = self.graft(relay=False)
        self.w.serve("bob/b0", hidden)
        self.assertIs(self.bob.accepted(self.m), INCOMPLETE)  # above the witness's latest revision
        after = self.ungraft(prev="relayed")  # inverts to the relayed commit, hiding the one between
        self.assertFalse(self.bob.accepted(self.m))
        self.assertEqual(self.bob.state.unrelayed, [(before, hidden, after)])
        self.assertEqual(self.integrity_alarms(self.bob), [f"unrelayed alice rev {hidden.rev}"])
        self.assertTrue(self.base_bob.accepted(self.m))  # the baseline believes the PDS

    def test_unrelayed_commit_inside_a_recorded_gap_raises_nothing(self):
        hidden = self.graft(relay=False)
        self.ungraft()  # inverts to the unrelayed commit, so it fails inversion: a gap
        self.w.serve("bob/b0", hidden)
        self.assertFalse(self.bob.accepted(self.m))
        self.assertEqual(self.integrity_alarms(self.bob), [])
        self.alice.sync()
        self.assertTrue(self.alice.gap_covers(hidden.rev))

    def test_unrelayed_commit_above_the_latest_revision_is_incomplete(self):
        self.graft(relay=False)
        self.assertIs(self.bob.accepted(self.m), INCOMPLETE)
        self.assertEqual(self.integrity_alarms(self.bob), [])

    def test_commit_an_honest_relay_drops_is_a_gap_not_an_alarm(self):
        self.w.drop_next.add("alice")
        a2 = self.w.link(self.a0, B("alice", "a2"))  # dropped, e.g. under a rate limit
        self.legit.add(a2)
        dropped, = self.w.dropped
        self.assertIs(self.bob.accepted(a2), INCOMPLETE)
        self.w.post("alice")  # its operations fail inversion against the witness's state
        self.w.serve("bob/b0", dropped)  # a proof Bob fetched before the next commit
        self.assertTrue(self.bob.accepted(a2))  # in the resynchronized state
        self.assertEqual(self.integrity_alarms(self.bob), [])
        self.alice.sync()
        self.assertTrue(self.alice.gap_covers(dropped.rev))
        self.assertEqual(self.integrity_alarms(self.alice), [])
        self.assertEqual(self.app1.alarms, [])

    def _drop_unchanged(self):
        self.w.drop_next.add("alice")
        empty = self.w.commit("alice")  # changes no record
        self.w.post("alice")
        self.alice.sync()
        self.assertEqual(self.alice.state.gaps, [])
        return empty

    def test_dropped_commit_changing_nothing_raises_nothing(self):
        # A commit with the same data as the one before it (re-signed after a
        # signing-key rotation, say) leaves the next commit's operations
        # inverting to the witness's state when an honest relay drops it, so
        # its neighbours are consecutive; a commit that changes nothing hides
        # nothing, so serving it raises no alarm.
        empty = self._drop_unchanged()
        self.w.serve("bob/b0", empty)
        self.assertTrue(self.bob.accepted(self.a0))
        self.assertEqual(self.integrity_alarms(self.bob), [])

    def test_finding_dropped_commit_changing_nothing_alarmed_under_the_earlier_text(self):
        # Finding 13: without the exemption, PDS and relay both honest, a
        # client holding the dropped commit alarms.
        class NoExemption(WitnessClient):
            EXEMPT_UNCHANGED = False

        bob = NoExemption(self.w, self.b0, self.app2)
        empty = self._drop_unchanged()
        self.w.serve(bob.name, empty)
        bob.accepted(self.a0)
        self.assertEqual(self.integrity_alarms(bob), [f"unrelayed alice rev {empty.rev}"])

    def test_unrelayed_commit_with_changes_still_alarms_beside_an_unchanged_one(self):
        # The exemption compares data, not revisions: a hidden commit that
        # changes records still alarms.
        before = self.w.head["alice"]
        hidden = self.graft(relay=False)
        self.w.serve("bob/b0", hidden)
        self.ungraft(prev="relayed")
        self.bob.accepted(self.a0)
        self.assertNotEqual(hidden.root, before.root)
        self.assertEqual(self.integrity_alarms(self.bob), [f"unrelayed alice rev {hidden.rev}"])

    def test_sync_after_a_dropped_commit_raises_nothing(self):
        # A `#sync` carries no operations, so nothing shows the witness that
        # the relay dropped a commit before it: only a `#commit` that
        # inverted to the earlier reconstruction brackets an unrelayed one.
        dropped = self._drop_then_sync()
        self.assertEqual(self.integrity_alarms(self.bob), [])
        self.assertFalse(self.bob.state.unrelayed)
        self.assertIsNotNone(dropped)

    def test_finding_sync_after_a_dropped_commit_alarms_under_the_text(self):
        # Under the proposal's wording (any two consecutive reconstructions),
        # the honest relay drops a commit, the PDS's next event is a `#sync`
        # (after a migration, say), the witness fetches its exact root, and
        # a client holding the dropped commit alarms; PDS and relay honest.
        self.app2.CONSECUTIVE = "any"
        dropped = self._drop_then_sync()
        self.assertEqual(self.integrity_alarms(self.bob), [f"unrelayed alice rev {dropped.rev}"])

    def _drop_then_sync(self):
        self.w.drop_next.add("alice")
        dropped = self.w.post("alice")
        self.w.publish_sync("alice")
        self.w.serve("bob/b0", dropped)
        self.assertTrue(self.bob.accepted(self.a0))
        return dropped

    def test_finding_out_of_order_commit_is_called_unrelayed_while_the_witness_is_behind(self):
        # Finding 14. The relay publishes, after two consecutive commits, one
        # whose revision falls between them. Before Bob's witness reaches it
        # Bob calls it unrelayed; once it does, it is a non-increasing alarm.
        self.w.now += 1
        self.w.post("alice")
        self.w.now += 0.5
        later = self.w.post("alice")
        self.bob.sync()
        self.app2.lag = 0.25
        self.w.now += 0.1
        c = self.graft(rev=later.rev - 1000)
        self.assertFalse(self.bob.accepted(self.m))
        self.assertEqual(self.integrity_alarms(self.bob), [f"unrelayed alice rev {c.rev}"])
        self.assertIn(c, {e.commit for e in self.w.relay})  # though it was relayed
        self.app2.lag = 0
        self.bob.sync()
        self.assertEqual(self.app2.alarms[0][2], c)

    def test_far_future_revision_is_a_gap_without_alarm(self):
        latest = self.app1.max_rev("alice")
        far = rev_at(self.w.now + 1.0)  # the PDS's clock an hour ahead, once
        a2 = B("alice", "a2")
        self.legit.add(a2)
        c = self.w.pds_write("alice", add=[a2], approve=[(self.a0, a2)], rev=far)
        self.alice.sync()
        self.assertEqual(self.app1.max_rev("alice"), latest)  # the latest revision is not raised
        self.assertEqual(self.app1.last_rev["alice"], latest)
        self.assertEqual([g.kind for g in self.alice.gap_warnings()], ["future-rev"])
        self.assertEqual(self.integrity_alarms(self.alice), [])
        self.assertEqual(self.app1.alarms, [])
        self.assertIs(self.bob.accepted(a2), False)  # not in the history, but reported: no wait
        # Later commits, with honest revisions below the far one, are read
        # normally: the first as one after a gap, by a verified fetch (made
        # before the next write, or finding 8's race makes it a gap too).
        for _ in range(3):
            self.w.now += 0.1
            self.w.post("alice")
            self.alice.sync()
        a3 = self.w.link(a2, B("alice", "a3"))
        self.legit.add(a3)
        self.alice.sync()
        self.assertLess(self.w.head["alice"].rev, c.rev)
        self.assertEqual(self.app1.max_rev("alice"), self.w.head["alice"].rev)
        self.assertEqual(len(self.alice.state.gaps), 1)
        self.assertEqual(self.integrity_alarms(self.alice), [])
        self.assertTrue(self.bob.accepted(a3))
        self.assertEqual(self.integrity_alarms(self.bob), [])
        self.assertEqual(self.app2.alarms, [])

    def test_revision_within_the_allowance_is_accepted(self):
        a2 = B("alice", "a2")
        self.legit.add(a2)
        self.w.pds_clock["alice"] = 0.9 * REV_ALLOWANCE
        self.w.link(self.a0, a2)
        self.w.pds_clock["alice"] = 0.0
        self.w.post("alice")  # an honest PDS keeps revisions increasing after its clock is fixed
        self.alice.sync()
        self.assertEqual(self.alice.state.gaps, [])
        self.assertTrue(self.bob.accepted(a2))

    def test_pds_clock_ahead_beyond_the_allowance_gaps_every_commit(self):
        # A PDS whose clock stays ahead keeps every revision ahead (an honest
        # relay would reject them all): each is a gap, none an alarm.
        self.w.pds_clock["alice"] = 1.0
        for _ in range(3):
            self.w.post("alice")
        self.alice.sync()
        self.assertEqual([g.kind for g in self.alice.state.gaps], ["future-rev"] * 3)
        self.assertEqual(self.integrity_alarms(self.alice), [])

    def test_non_increasing_revision_is_a_gap_and_an_alarm(self):
        self.w.now += 1
        self.w.post("alice")
        self.alice.sync()
        latest = self.app1.max_rev("alice")
        c = self.graft(rev=latest - 1000)  # between two relayed revisions
        self.alice.sync()
        self.assertEqual(self.integrity_alarms(self.alice), [f"revision not increasing alice rev {c.rev}"])
        self.assertEqual([g.kind for g in self.alice.gap_warnings()], ["rev-not-increasing"])
        self.assertEqual(self.app1.max_rev("alice"), latest)
        self.assertNotIn(self.m, self.alice.state.seen_own)
        self.assertFalse(self.bob.accepted(self.m))  # published, reported as a gap: no extra alarm
        self.assertEqual(self.integrity_alarms(self.bob), [])
        self.ungraft()  # reconstructed as one after a gap
        self.alice.sync()
        self.assertEqual(self.app1.state["alice"], self.w.head["alice"].root)
        self.assertEqual(len(self.alice.state.gaps), 1)

    def test_non_increasing_revision_read_from_a_restored_cursor(self):
        # The cursor works only because the witness refuses to move it back.
        self.w.now += 1
        self.w.post("alice")
        self.alice.sync()
        backup = self.alice.export_state()
        c = self.graft(rev=self.app1.max_rev("alice") - 1000)  # below the backup's cursor
        self.w.now += 1
        restored = WitnessClient.restore(self.w, backup, self.app1)
        self.assertEqual(self.integrity_alarms(restored), [f"revision not increasing alice rev {c.rev}"])
        self.assertEqual([g.kind for g in restored.gap_warnings()], ["rev-not-increasing"])


class Findings(Base):
    def test_finding_witness_far_behind_the_relay_warns_by_event_time(self):
        # Finding 1. Alice's witness is replaying a 30-hour backlog (resumed
        # from its cursor after an outage within the relay's window, or a
        # slow consumer). It receives frames continuously, so the first
        # draft's rule (a frame within 60 seconds) called it live with
        # frontier age 0 while the impostor's commit was undelivered, and the
        # goal failed. The frontier is now the relay time of the newest event
        # processed, 30 hours old here, so Alice warns within 24 hours.
        self.app1.lag = 30
        self.w.now += 0.1
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.hours(24, self.alice)
        self.assertGreater(self.alice.coverage_age(), LIVENESS_LIMIT)
        self.assertNotIn(self.m, self.alice.state.own_alarms)
        self.assertTrue(self.alice.liveness_warning())
        self.assertEqual(self.goal(), [])

    def test_finding_backlog_drains_and_the_alarm_arrives(self):
        self.app1.lag = 30
        self.w.now += 0.1
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.ungraft()
        self.hours(10, self.alice)
        self.app1.lag = 0  # backlog drained
        self.alice.sync()
        self.assertIn(self.m, self.alice.state.own_alarms)
        self.assertFalse(self.alice.liveness_warning())

    def _late_enrollment(self, client_cls):
        rec = self.bob.invite(BOOK, "erin")
        self.assertTrue(rec.pending)
        em = self.w.add_device(B("erin", "m"))
        self.assertTrue(self.bob.accepted(em))
        self.w.delete_device(em)
        self.w.now += 30
        witness = Witness(self.w, "app4", from_now=True)  # starts following Erin now
        e0 = self.w.add_device(B("erin", "e0"))
        erin = client_cls(self.w, e0, witness)
        erin.sync()
        return goal_violations("erin", [erin], [self.bob], {e0}, self.w.now)

    def test_finding_fresh_enrollment_after_the_witness_history_starts(self):
        # Finding 2. A witness that began following Erin's account after the
        # impostor came and went (a new application, or one rebuilt from a
        # snapshot) has a clean start; under the earlier draft, fresh
        # enrollment replayed it, presented nothing, and recorded no gap.
        self.assertTrue(self._late_enrollment(NoFreshGap))

    def test_finding_fresh_enrollment_beyond_retention(self):
        rec = self.bob.invite(BOOK, "erin")
        em = self.w.add_device(B("erin", "m"))
        self.assertTrue(self.bob.accepted(em))
        self.w.delete_device(em)
        self.w.now += WITNESS_RETENTION + 1
        self.app1.poll()
        e0 = self.w.add_device(B("erin", "e0"))
        erin = NoFreshGap(self.w, e0, self.app1)
        erin.sync()
        self.assertEqual(erin.state.presented | erin.state.own_alarms, set())
        self.assertEqual(erin.state.gaps, [])
        self.assertTrue(goal_violations("erin", [erin], [self.bob], {e0}, self.w.now))
        self.assertTrue(rec.pending)
        fixed = WitnessClient(self.w, e0, self.app1)  # the rule now: a retention gap
        fixed.sync()
        self.assertEqual({g.kind for g in fixed.state.gaps}, {"retention"})
        self.assertEqual(goal_violations("erin", [fixed], [self.bob], {e0}, self.w.now), [])

    def test_finding_fresh_enrollment_gap_before_history_fixes_both(self):
        self.assertEqual(self._late_enrollment(WitnessClient), [])

    def test_finding_monotonic_clock_that_stops_in_suspend(self):
        # Finding 3. While "running", coverage age uses a monotonic clock;
        # on platforms whose monotonic clock stops during suspend, a phone
        # asleep for a day undercounts it, and with its witness unreachable
        # on waking it does not warn.
        class Suspending(WitnessClient):
            MONO_COUNTS_SUSPEND = False

        alice = Suspending(self.w, self.a0, self.app1)
        alice.pair(self.a1)
        alice.sync()
        self.w.now += 0.5
        alice.sync()
        self.app1.reachable = False
        self.graft()
        self.assertTrue(self.bob.accepted(self.m))
        self.w.now += 29.4
        alice.suspended += 29.4
        alice.sync()
        self.assertFalse(alice.liveness_warning())
        self.assertTrue(self.goal([alice]))
        self.alice.sync()  # an installation whose clock counts suspend warns
        self.assertTrue(self.alice.liveness_warning())

    def _stalling_mallory(self):
        x0 = self.w.add_device(B("mallory", "x0"))
        self.w.stall("app1", "mallory")
        for _ in range(30):
            self.w.publish_sync("mallory")
            self.w.now += 0.9
            self.alice.sync()
        return x0

    def test_finding_one_pds_stalling_fetches_stalls_every_accounts_frontier(self):
        # Finding 5. An earlier draft did not say how long a witness waits on
        # a `#sync` fetch. If a pending fetch holds the whole stream with no
        # bound, one PDS that stalls fetches keeps every account's frontier
        # back, and every user of the application sees a warning they cannot
        # dismiss.
        self.app1.PENDING = "stream"
        self.app1.FETCH_TIMEOUT = INF
        self.assertTrue(self._stalling_mallory())
        self.assertTrue(self.alice.liveness_warning())  # nothing happened to Alice

    def test_stalled_fetch_holds_only_its_own_accounts_frontier(self):
        self.app1.FETCH_TIMEOUT = INF
        self._stalling_mallory()
        self.assertFalse(self.alice.liveness_warning())
        self.assertGreater(self.app1.frontier_age("mallory"), LIVENESS_LIMIT)

    def test_finding_stalled_fetch_counted_as_processed_is_neither(self):
        # Finding 5, the other reading: if a stalled fetch waits aside while
        # the witness counts the event as processed and stays live, and
        # nothing bounds the wait, the commit Bob accepted is neither
        # reconstructed nor a gap in Alice's history, and her coverage stays
        # fresh. This answers the proposal's review question 4 with yes.
        self.app1.PENDING = "aside"
        self.app1.FETCH_TIMEOUT = INF
        self.w.stall("app1", "alice")
        self.graft(kind="sync")
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(25, self.alice)
        self.assertEqual(self.alice.state.gaps, [])
        self.assertFalse(self.alice.liveness_warning())
        self.assertTrue(self.goal())

    def test_finding_bounded_fetch_wait_makes_it_a_gap(self):
        self.app1.PENDING = "aside"  # a bounded wait aside is enough
        self.w.stall("app1", "alice")
        self.graft(kind="sync")
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(25, self.alice)
        self.assertTrue(self.alice.gap_warnings())
        self.assertEqual(self.goal(), [])

    def test_unbounded_fetch_wait_holding_the_frontier_still_warns(self):
        # Under the rule now, a commit awaiting a fetch holds its account's
        # frontier at its relay time, so even with no timeout the deadline
        # holds: the coverage age reaches 24 hours and Alice warns.
        self.app1.FETCH_TIMEOUT = INF
        self.w.stall("app1", "alice")
        self.graft(kind="sync")
        self.assertTrue(self.bob.accepted(self.m))
        self.hours(24.5, self.alice)
        self.assertEqual(self.alice.state.gaps, [])
        self.assertTrue(self.alice.liveness_warning())
        self.assertEqual(self.goal(), [])

    def test_finding_revoked_signer_impostor_is_only_a_notice(self):
        # Finding 6. A removed device's key approves an impostor beside a live
        # device. Alice's installation accepts it by approval, so the
        # proposal's "alarm" is only the baseline own-account notice, even
        # though her witnessed history shows the approval appearing after
        # its signer's removal, which no honest flow produces.
        self.w.delete_device(self.a1)
        self.alice.sync()
        self.assertTrue(self.bob.accepted(self.a0))
        self.w.link(self.a1, self.m)
        self.assertTrue(self.bob.accepted(self.m))
        self.alice.sync()
        self.assertIn(self.m, self.alice.state.notices)
        self.assertNotIn(self.m, self.alice.state.own_alarms)
        self.assertEqual(self.goal(), [])  # counted only because notices count

    def test_finding_honest_write_after_a_sync_is_a_gap(self):
        # Finding 8. A root covers the whole repo, and an honest PDS serves
        # only its current repo. Any honest write, in any collection, between
        # a `#sync` and the witness's fetch makes that root unfetchable: a
        # gap warning on an account nobody attacked.
        self.w.publish_sync("alice")  # e.g. after a migration
        self.w.post("alice")  # Alice posts before her witness fetches
        self.alice.sync()
        self.assertTrue(self.alice.gap_warnings())
        self.assertEqual(self.alice.state.own_alarms, set())

    def test_finding_unpublished_commit_below_the_witnessed_head_alarms(self):
        # Finding 7. Fork detection compared only same-revision commits, so a
        # PDS that served a client a signed commit at a revision the relay
        # never carried, then relayed later revisions, was never caught. The
        # rule now alarms on one between two consecutive reconstructions.
        f = self.w.fork("bob/b0", "alice", add=[self.m], approve=[(self.m, self.a0)])
        self.w.link(self.a0, B("alice", "a2"))
        self.assertFalse(self.bob.accepted(self.m))
        self.assertEqual(self.bob.state.forks, [])
        self.assertIn(f"unrelayed alice rev {f.rev}", self.bob.state.alarms)


if __name__ == "__main__":
    unittest.main()
