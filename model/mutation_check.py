"""Mutation check: break one rule of SpecClient or InviterClient at a time
and confirm a test in test_nbd_trust.py, test_inviters.py, or test_walks.py
fails; then break one rule of WitnessClient or its witness (nbd_witness.py)
at a time and confirm a test in test_witness.py or test_witness_walks.py
fails.

Run: python3 -I model/mutation_check.py   (--witness: only the witness mutations)
MISSED means no test notices that rule being broken.
"""

import os
import shutil
import subprocess
import sys
import tempfile

SRC = os.path.dirname(os.path.abspath(__file__))
SPEC = "class SpecClient:"

MUTATIONS = {
    "undirected reach": (
        "                if ap.signer == n and ap.target not in seen:\n                    seen.add(ap.target)\n                    frontier.append(ap.target)\n        return seen\n\n    def single_root_set",
        "                if ap.signer == n and ap.target not in seen:\n                    seen.add(ap.target)\n                    frontier.append(ap.target)\n                if ap.target == n and ap.signer not in seen:\n                    seen.add(ap.signer)\n                    frontier.append(ap.signer)\n        return seen\n\n    def single_root_set"),
    "record-less roots count as roots": (
        "roots = [p for p in present if p not in incoming]",
        "roots = [n for n in nodes if n not in incoming and self._reach(x, [n]) & present]"),
    "present root need not reach all": (
        "starts = roots or list(past)", "starts = roots + list(past)"),
    "only record-less roots start": (
        "past = nodes - present", "past = {n for n in nodes - present if n not in incoming}"),
    "completed holds kept": (
        "            if any(b.account == x for b in self.account_wide_set()):\n                del st.holds[x]",
        "            if False:\n                del st.holds[x]"),
    "cancelled holds kept": ("elif cand & st.revoked:", "elif False:"),
    "first use for known accounts": ("        if not self._knew(x):\n", "        if True:\n"),
    "approvals need an unrevoked signer": (
        "if ap.signer in st.accepted and ap.target not in st.accepted:",
        "if ap.signer in self.account_wide_set() and ap.target not in st.accepted:"),
    "no hold": ("if held[1] >= REENROLL_HOLD:", "if True:"),
    "hold not bound to candidate": ("if held is None or held[0] != key:", "if held is None:"),
    "replaced candidates not revoked": ("            st.candidates_seen |= key\n", ""),
    "imports merge any candidate": ("elif mine[0] == cand:", "else:"),
    "no takeover alarm": (
        "            self.state.alarms.append(msg)\n", "            pass\n"),
    "import skips takeover alarm": (
        "        # can end a hold; sync then alarms and reconciles.\n        self.sync()",
        "        self._reconcile_holds()"),
    "import ends holds before checking the repo": (
        "        # can end a hold; sync then alarms and reconciles.\n        self.sync()",
        "        self._reconcile_holds()\n        self.sync()"),
    "imports keep earliest checkpoint": (
        "(cand, max(credited, mine[1]), now)", "(cand, max(credited, mine[1]), min(_theirs, mine[2]))"),
    "imports credit storage time": ("st.holds[x] = (cand, credited, now)", "st.holds[x] = (cand, credited, _theirs)"),
    "paths stop at deleted devices": (
        "if ap.signer in st.accepted and ap.target not in st.accepted:",
        "if ap.signer in st.accepted and ap.target not in st.accepted and self._usable(ap.target):"),
    "paths stop at revoked devices": (
        "if ap.signer in st.accepted and ap.target not in st.accepted:",
        "if ap.signer in st.accepted and ap.target not in st.accepted and ap.target not in st.revoked:"),
    "deleted path targets stay usable": (
        "                        if not self.world.present(ap.target):\n                            st.revoked.add(ap.target)\n",
        ""),
    "approvals apply during re-enrollment": (
        "                if not any(b.account == x for b in self.account_wide_set()):\n                    continue",
        "                if False:\n                    continue"),
    "revoked stays usable": (
        "    def _usable(self, b: Binding) -> bool:\n        return b not in self.state.revoked and self.world.present(b)\n\n    def _knew",
        "    def _usable(self, b: Binding) -> bool:\n        return self.world.present(b)\n\n    def _knew"),
    # InviterClient: grant standing and invites.
    "vouch counts in every space": (
        "        if b in st.authorized.get(space, set()):",
        "        if any(b in v for v in st.authorized.values()):"),
    "a later vouch extends an older invite": (
        "        if b in st.authorized.get(space, set()):",
        "        if b in st.first_met and any(r.inviter == self.own.account and r.space == space\n                                   and r.account == b.account for r in self.world.invites):"),
    "invites authorize unvouched devices": (
        "frozenset(b for b in live if self._first_contact_line(b)), pending)", "frozenset(live), pending)"),
    "captures authorize nothing": (
        "frozenset(met), frozenset(met),\n", "frozenset(met), frozenset(),\n"),
    "abandoning keeps the pending invite": (
        "        if rec.pending:\n            st.abandoned.add", "        if False:\n            st.abandoned.add"),
    "abandoned invites still capture": (
        "if met and x in st.pending and (x, st.pending[x][0]) not in st.abandoned:",
        "if met and x in st.pending:"),
    "captures skip the published check": (
        "            elif rec.captures and not self._pending_published(rec):\n                return  # its pending invite must be published first\n",
        ""),
    "abandoning keeps queued captures": (
        "        st.outbox = [r for r in st.outbox\n                     if not (r.captures and r.account == rec.account and r.space == rec.space)]",
        "        pass"),
    "records jump the queue": (
        "if not queued and self.world.publish_invite(rec):", "if self.world.publish_invite(rec):"),
    "authorizes ignores descendants": (
        "            seen.add(b)\n            b = st.approvers.get(b)", "            seen.add(b)\n            b = None"),
    "adoption requires a direct vouch": (
        "            st.authorized.setdefault(rec.space, set()).update(\n                b for b in rec.authorizes if self._first_contact_line(b))",
        "            st.authorized.setdefault(rec.space, set()).update(\n                b for b in rec.authorizes if b in st.first_met)"),
    "imports require a direct vouch": (
        "                st.authorized.setdefault(sp, set()).update(b for b in bs if self._first_contact_line(b))",
        "                st.authorized.setdefault(sp, set()).update(b for b in bs if b in st.first_met)"),
    "imports restore pending invites": (
        "            st.abandoned |= other.abandoned\n            for x, (space, _cr, _ck) in list(st.pending.items()):\n                if (x, space) in st.abandoned:\n                    del st.pending[x]\n",
        "            st.pending.update(other.pending)\n"),
    "pinned installations adopt any authorization": (
        "                b for b in rec.authorizes if self._first_contact_line(b))", "                b for b in rec.authorizes)"),
    "only invites make first-contact roots": (
        "        st.first_met |= met  # every first contact can be authorized by a later invite\n", ""),
    "invites authorize a reset's devices": (
        "            if b in st.first_met:\n                return True",
        "            if b in st.first_met or st.accepted.get(b) == \"re-enrolled\":\n                return True"),
    "imported vouch ends a hold": (
        "                if b.account not in knew:\n                    st.first_met.add(b)",
        "                if True:\n                    st.first_met.add(b)"),
    "invite record ends a hold": (
        "            if not self._knew(rec.account):\n                for b in rec.authorizes:",
        "            if True:\n                for b in rec.authorizes:"),
    "invite for an existing member": (
        "        if self.world.eligible(account, space):\n            return None\n", ""),
    "retry re-derives the record": (
        "            if rec.space == space and rec.account == account and not rec.captures:\n                return rec",
        "            if False:\n                return rec"),
    "standing before publication": (
        "        self.state.outbox.append(rec)\n        if not queued",
        "        self.state.outbox.append(rec)\n        self._published(rec)\n        if not queued"),

    "stale records still published": (
        "            if not rec.captures and self.world.eligible(rec.account, rec.space):\n                self._abandon(rec)\n            elif",
        "            if False:\n                self._abandon(rec)\n            elif"),
    "no pending invites": (
        "if not met and not self.world.present_devices(account):", "if False:"),
    "pending invites never expire": ("            if credited >= PENDING_INVITE_TTL:", "            if False:"),
    "other installations capture": (
        "            if rec.inviter != self.own.account or not rec.authorizes:\n                continue",
        "            if rec.inviter == self.own.account and rec.pending and not self._knew(rec.account):\n                st.pending.setdefault(rec.account, (rec.space, 0.0, self.local_now()))\n            if rec.inviter != self.own.account or not rec.authorizes:\n                continue"),
    "first-contact hold keyed to the account": (
        "        fc = st.fc_holds.get(b)\n",
        "        fc = max((v for k, v in st.fc_holds.items() if k.account == b.account), default=None)\n"),
    "no first-contact hold": ("fc[0] >= REENROLL_HOLD:", "fc[0] >= 0:"),
    "approved devices start no hold": (
        "        self._start_fc_hold(ap.target)\n\n    def _own_invites", "\n    def _own_invites"),
    "approval does not pass on standing": (
        "return signer is not None and self._source(signer, space, seen)", "return False"),
    "revoked bindings keep crediting": (
        "            if b in st.revoked:\n                st.fc_holds[b] = (credited, now)",
        "            if False:\n                st.fc_holds[b] = (credited, now)"),
    "revocation before crediting": (
        "        self._tick()\n        super().sync()\n        self._own_invites()",
        "        super().sync()\n        self._own_invites()"),
    "imports credit first-contact storage time": (
        "(credited if mine is None else max(credited, mine[0]), now)",
        "(credited if mine is None else max(credited, mine[0]), _theirs)"),
}

# WitnessClient and Witness (nbd_witness.py): the relay-witness rules.
WITNESS_MUTATIONS = {
    "accept on PDS-served commit": (
        "        lr = self._c._latest(x)\n        return lr.root if lr else EMPTY",
        "        c = self._w.pds_serve(self._c.name, x)\n        return c.root if c else EMPTY"),
    "any-witness trust": (
        "            if src is not self.witness:\n                continue",
        "            if False:\n                continue"),
    "latest-only watching": (
        "        for e, pos in entries:",
        "        for e, pos in ([p for p in entries if p[0].reconstructed][-1:] if own else entries):"),
    "gap erased on resync": (
        "            if e.reconstructed:\n                st.obs[x], st.obs_rev[x] = e.root, e.hi",
        "            if e.reconstructed:\n                if e.kind == \"resync\" and own:\n"
        "                    st.gaps.clear()\n                st.obs[x], st.obs_rev[x] = e.root, e.hi"),
    "deadline reset at check completion": (
        "        age = age + (self.mono() - sent)", "        age = 0.0"),
    "restore from now instead of cursor": (
        "            st.read_from = st.cursors.get(own.account, 0)",
        "            st.cursors[own.account] = witness.last_rev.get(own.account, 0)\n"
        "            st.read_from = st.cursors.get(own.account, 0)"),
    "snapshot skipping for pinned accounts": (
        "        for e, pos in entries:",
        "        for e, pos in ([p for p in entries if p[0].reconstructed][-1:] if not own else entries):"),
    "gap ack suppresses liveness": (
        "        return self.running and self.coverage_age() > LIVENESS_LIMIT",
        "        return self.running and self.coverage_age() > LIVENESS_LIMIT and not any(\n"
        "            g.acknowledged for g in self.state.gaps)"),
    "ack covers every gap": (
        "        gap.acknowledged = True", "        for g in self.state.gaps:\n            g.acknowledged = True"),
    "backward clock across a restart credits zero": (
        "        st.cov_base = INF if d is None or d < 0 else st.cov_base + d",
        "        st.cov_base = INF if d is None else st.cov_base + max(0.0, d)"),
    "restart credits no downtime": (
        "        st.cov_base = INF if d is None or d < 0 else st.cov_base + d",
        "        st.cov_base = INF if d is None or d < 0 else st.cov_base"),
    "no gap for history the witness lacks": (
        "        if lacks is not None and (self.FRESH_HISTORY_GAP or not fresh):",
        "        if False:"),
    "no fork alarm": ("            if wc != c and (wc, c) not in self.state.forks:", "            if False:"),
    "alarm on any unreported lower revision": (
        "        around = self.witness.unrelayed_between(x, c.rev)",
        "        around = (c, c) if c.rev < self.witness.max_rev(x) else None"),
    "no alarm between consecutive reconstructions": (
        "        around = self.witness.unrelayed_between(x, c.rev)", "        around = None"),
    "witness: consecutiveness ignores since": (
        "    CONSECUTIVE = \"since\"", "    CONSECUTIVE = \"inverted\""),
    "a #sync brackets an unrelayed commit": (
        "    CONSECUTIVE = \"since\"", "    CONSECUTIVE = \"any\""),
    "served unplaced commit waits": (
        "        if self.witness.reports_unplaced(x, c):\n            return False", ""),
    "witness: future revision accepted into history": (
        "        if self._future(e):\n            self._unplaced", "        if False:\n            self._unplaced"),
    "witness: future revision raises the latest revision": (
        "            self._unplaced(a, e, \"future-rev\", None)",
        "            self._unplaced(a, e, \"future-rev\", None)\n            self.last_rev[a] = e.commit.rev"),
    "witness: future revision alarms": (
        "            self._unplaced(a, e, \"future-rev\", None)",
        "            self._unplaced(a, e, \"future-rev\", f\"revision far ahead {a}\")"),
    "witness: non-increasing revision accepted": (
        "        if e.commit.rev <= self.last_rev.get(a, 0):", "        if False:"),
    "witness: non-increasing revision without alarm": (
        "            self._unplaced(a, e, \"rev-not-increasing\", f\"revision not increasing {a} rev {e.commit.rev}\")",
        "            self._unplaced(a, e, \"rev-not-increasing\", None)"),
    "unreported commits decide": (
        "        return c.rev > self.witness.max_rev(x)", "        return False"),
    "absence before presence revokes": (
        "            elif b in st.proven and rev > st.proven[b]:", "            else:"),
    "fresh enrollment starts at the head": (
        "        st.cursors[x] = 0\n",
        "        st.cursors[x] = self.witness.last_rev.get(x, 0)\n"),
    "fresh enrollment presents nothing": (
        "            if fresh:\n                st.presented.add(b)", "            if fresh:\n                pass"),
    "unreachable witness decides": (
        "        if not self.witness.reachable:\n            return True",
        "        if False:\n            return True"),
    "cursor as a witness-local index": (
        "        return [(e, e.pos) for e in w.read(x, cur)]",
        "        return [(e, e.idx) for e in w.read(x, -1) if e.idx > cur]"),
    "witness: consecutiveness ignores root (since only)": (
        "        inverts = e.kind == \"commit\" and cur is not None and e.prev == cur",
        "        inverts = e.kind == \"commit\" and cur is not None"),
    "witness: since mismatch reconstructed by fetch": (
        "        if inverts:\n            if not follows:", "        if inverts and follows:\n            if not follows:"),
    "history start checked against any cursor": (
        "        if st.cursor_seq.get(x, INF) > after:\n            return", "        if False:\n            return"),
    "history starting below the cursor not alarmed": (
        "        below = cur > start.rev", "        below = False"),
    "history starting at the cursor with another commit not alarmed": (
        "        differs = cur == start.rev and", "        differs = False and"),
    "witness: rebuild gap bounded by the starting revision": (
        "        self.missing[a] = max(r, bound)", "        self.missing[a] = r - (1 if self.state[a] else 0)"),
    "witness: cursor moves to the rebuild gap's end": (
        "            self._gap(x, Gap(lo, hi, kind), merge=True)",
        "            self._gap(x, Gap(lo, hi, kind), merge=True)\n            st.cursors[x] = max(st.cursors[x], hi)"),
    "witness: rebuild gap not served at the starting revision": (
        "        if hi <= after:\n            return None",
        "        if hi <= after or (kind == \"before history\" and after >= self.started[account][0].rev):\n"
        "            return None"),
    "witness: later snapshot reconstructs an earlier root": (
        "        if res:\n            self._record(a, \"sync\", e, e.commit.root)\n        else:\n"
        "            self._gap(a, e)\n\n    def _drain(self)",
        "        if res:\n            self._record(a, \"sync\", e, e.commit.root)\n        else:\n"
        "            self._record(a, \"sync\", e, self.world.head[a].root)\n\n    def _drain(self)"),
    "witness: no stream gap": (
        "            self._stream_gap()  # the relay", "            pass  # the relay"),
    "witness: frontier from a successful answer": (
        "        if not self.up or not w.relay_up:\n            return\n        self._drain()",
        "        if not self.up or not w.relay_up:\n            self.stream_time = w.now\n"
        "            return\n        self._drain()"),
    "witness: frontier from delivery time": (
        "        self.stream_time = max(self.stream_time, w.stamp(None, horizon, self))",
        "        self.stream_time = max(self.stream_time, self.wnow())"),
    "witness: pending fetch does not hold the frontier": (
        "        if q and self.PENDING != \"aside\":", "        if False:"),
    "witness: skew fault ignored": (
        "        if self.skew_fault(account):\n            return INF", "        if False:\n            return INF"),
    "witness: same-revision stream gap exempt": (
        "                self._append(a, \"stream-gap\", cur + 1, max(cur + 1, r, bound), None, None,",
        "                if not (r == cur and held == last.commit):\n"
        "                    self._append(a, \"stream-gap\", cur + 1, max(cur + 1, r, bound), None, None,"),
    "witness: stream gap ends at the resync revision": (
        "max(cur + 1, r, bound), None, None,", "r, None, None,"),
    "witness: cursor moves to the end of a stream gap": (
        "self.wnow(), cursor=max(cur, r))", "self.wnow())"),
    "witness: a stream gap keeps reconstructions consecutive": (
        "        for e in self.hist.get(account, []):\n            if not e.reconstructed:",
        "        for e in self.hist.get(account, []):\n            if e.kind == \"stream-gap\":\n"
        "                continue\n            if not e.reconstructed:"),
    "relay: time stamped when sent": ("    STAMP = \"sequenced\"", "    STAMP = \"sent\""),
    "relay: PDS time passed on": ("    STAMP = \"sequenced\"", "    STAMP = \"pds\""),
    "coverage aged from the response's arrival": (
        "        age = age + (self.mono() - sent)", "        age = age + 0.0"),
    "coverage aged from the last page's request": (
        "self._advance(ans.frontier_age, req.first_sent)", "self._advance(ans.frontier_age, req.sent)"),
    "late answer moves coverage back": ("min(self.coverage_age(), age)", "age"),
    "response to a request before a restart processed": (
        "        if req.epoch != self._epoch or not self.running:", "        if not self.running:"),
    "witness: skew fault not latched": (
        "        return self.skewed or self.frontier(account) > self.wnow() + CLOCK_SKEW",
        "        return self.frontier(account) > self.wnow() + CLOCK_SKEW"),
}


def run(src_name, text, tests):
    d = tempfile.mkdtemp()
    for t in tests:
        shutil.copy(os.path.join(SRC, t), d)
    if src_name != "nbd_trust.py":
        shutil.copy(os.path.join(SRC, "nbd_trust.py"), d)
    with open(os.path.join(d, src_name), "w") as f:
        f.write(text)
    r = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", d],
                       capture_output=True, text=True)
    shutil.rmtree(d)
    return [ln.split(" (")[0].split(": ", 1)[1] for ln in r.stderr.splitlines()
            if ln.startswith(("FAIL:", "ERROR:"))]


def report(name, fails):
    shown = ", ".join(fails[:6]) + (f", +{len(fails) - 6} more" if len(fails) > 6 else "")
    print(f"{'CAUGHT' if fails else 'MISSED'} {name}: {shown or '-'}")


def main():
    only_witness = "--witness" in sys.argv
    base = open(os.path.join(SRC, "nbd_trust.py")).read()
    head, spec = base.split(SPEC, 1)
    if not only_witness:
        for name, (old, new) in MUTATIONS.items():
            assert old in spec, name
            report(name, run("nbd_trust.py", head + SPEC + spec.replace(old, new, 1),
                             ("test_nbd_trust.py", "test_inviters.py", "test_walks.py")))
    wsrc = open(os.path.join(SRC, "nbd_witness.py")).read()
    for name, (old, new) in WITNESS_MUTATIONS.items():
        assert wsrc.count(old) == 1, name
        report(name, run("nbd_witness.py", wsrc.replace(old, new, 1),
                         ("test_witness.py", "test_witness_walks.py")))


if __name__ == "__main__":
    main()
