"""Mutation check: break one rule of SpecClient at a time and confirm a
test in test_peep_trust.py fails.

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
    "recordless roots counted separately": (
        "if len(present_roots) > 1:", "if len(live_roots) > 1:"),
    "present root need not reach all": (
        "starts = present_roots or live_roots", "starts = live_roots"),
    "first use for known accounts": ("        if not self._knew(x):\n", "        if True:\n"),
    "approvals need an unrevoked signer": (
        "if (ap.signer in st.accepted and ap.target not in st.accepted",
        "if (ap.signer in self.account_wide_set() and ap.target not in st.accepted"),
    "no hold": ("if held[1] >= REENROLL_HOLD:", "if True:"),
    "hold not bound to candidate": ("if held is None or held[0] != key:", "if held is None:"),
    "replaced candidates not revoked": ("            st.candidates_seen |= key\n", ""),
    "imports merge any candidate": ("elif mine[0] == cand:", "else:"),
    "no takeover alarm": (
        "            self.state.alarms.append(msg)\n", "            pass\n"),
    "import skips takeover alarm": (
        "observation.\n        self._own_removal_alarm()", "observation.\n"),
    "imports keep earliest checkpoint": (
        "(cand, max(credited, mine[1]), now)", "(cand, max(credited, mine[1]), min(_theirs, mine[2]))"),
    "imports credit storage time": ("st.holds[x] = (cand, credited, now)", "st.holds[x] = (cand, credited, _theirs)"),
    "revoked stays usable": (
        "    def _usable(self, b: Binding) -> bool:\n        return b not in self.state.revoked and self.world.present(b)\n\n    def _knew",
        "    def _usable(self, b: Binding) -> bool:\n        return self.world.present(b)\n\n    def _knew"),
}


def main():
    base = open(os.path.join(SRC, "peep_trust.py")).read()
    head, spec = base.split(SPEC, 1)
    for name, (old, new) in MUTATIONS.items():
        assert old in spec, name
        d = tempfile.mkdtemp()
        shutil.copy(os.path.join(SRC, "test_peep_trust.py"), d)
        with open(os.path.join(d, "peep_trust.py"), "w") as f:
            f.write(head + SPEC + spec.replace(old, new, 1))
        r = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", d],
                           capture_output=True, text=True)
        fails = [ln.split(" (")[0].split(": ", 1)[1] for ln in r.stderr.splitlines()
                 if ln.startswith(("FAIL:", "ERROR:"))]
        print(f"{'CAUGHT' if fails else 'MISSED'} {name}: {', '.join(fails) or '-'}")
        shutil.rmtree(d)


if __name__ == "__main__":
    main()
