"""Mutation check: break one rule of SpecClient or InviterClient at a time
and confirm a test in test_nbd_trust.py, test_inviters.py, or test_walks.py
fails.

Run: python3 -I model/mutation_check.py
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
    # InviterClient (proposal-inviters.md).
    "vouch counts in every space": (
        "        if b in st.authorized.get(space, set()):",
        "        if any(b in v for v in st.authorized.values()):"),
    "a later vouch extends an older invite": (
        "        if b in st.authorized.get(space, set()):",
        "        if b in st.vouched and any(r.inviter == self.own.account and r.space == space\n                                   and r.account == b.account for r in self.world.invites):"),
    "invites authorize unvouched devices": (
        "frozenset(live & st.vouched), pending)", "frozenset(live), pending)"),
    "captures authorize nothing": (
        "frozenset(met), frozenset(met),\n", "frozenset(met), frozenset(),\n"),
    "pinned installations adopt any authorization": (
        "update(rec.authorizes & st.vouched)", "update(rec.authorizes)"),
    "known account vouched": (
        "        if not knew:\n            met =", "        if True:\n            met ="),
    "imported vouch ends a hold": (
        "                if b.account not in knew:\n                    st.vouched.add(b)",
        "                if True:\n                    st.vouched.add(b)"),
    "invite record ends a hold": (
        "            if not self._knew(rec.account):\n                for b in rec.authorizes:",
        "            if True:\n                for b in rec.authorizes:"),
    "invite for an existing member": (
        "        if self.world.eligible(account, space):\n            return None\n", ""),
    "retry re-derives the record": (
        "            if rec.space == space and rec.account == account and not rec.captures:\n                return rec",
        "            if False:\n                return rec"),
    "standing before publication": (
        "        self.state.outbox.append(rec)\n        if self.world.publish_invite(rec):",
        "        self.state.outbox.append(rec)\n        self._published(rec)\n        if self.world.publish_invite(rec):"),

    "stale records still published": (
        "            if not rec.captures and self.world.eligible(rec.account, rec.space):\n                st.outbox.remove(rec)\n            elif",
        "            if False:\n                st.outbox.remove(rec)\n            elif"),
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


def main():
    base = open(os.path.join(SRC, "nbd_trust.py")).read()
    head, spec = base.split(SPEC, 1)
    for name, (old, new) in MUTATIONS.items():
        assert old in spec, name
        d = tempfile.mkdtemp()
        for t in ("test_nbd_trust.py", "test_inviters.py", "test_walks.py"):
            shutil.copy(os.path.join(SRC, t), d)
        with open(os.path.join(d, "nbd_trust.py"), "w") as f:
            f.write(head + SPEC + spec.replace(old, new, 1))
        r = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", d],
                           capture_output=True, text=True)
        fails = [ln.split(" (")[0].split(": ", 1)[1] for ln in r.stderr.splitlines()
                 if ln.startswith(("FAIL:", "ERROR:"))]
        print(f"{'CAUGHT' if fails else 'MISSED'} {name}: {', '.join(fails) or '-'}")
        shutil.rmtree(d)


if __name__ == "__main__":
    main()
