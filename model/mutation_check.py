"""Mutation check: break one rule at a time and confirm a test fails.

Run: python3 -I model/mutation_check.py
MISSED means no test notices that rule being broken.
"""
import os, shutil, subprocess, sys, tempfile
src = os.path.dirname(os.path.abspath(__file__))
muts = {
 "undirected reach": ("if ap.signer == n and ap.target not in seen:\n                    seen.add(ap.target)\n                    frontier.append(ap.target)",
                      "if ap.signer == n and ap.target not in seen:\n                    seen.add(ap.target)\n                    frontier.append(ap.target)\n                if ap.target == n and ap.signer not in seen:\n                    seen.add(ap.signer)\n                    frontier.append(ap.signer)"),
 "witness need not be accepted": ("if (g.space == space and g.issuer in acc and", "if (g.space == space and"),
 "witness grant from any space": ("if (g.space == space and g.issuer in acc and", "if (g.issuer in acc and"),
 "witness eligibility ignored": ("\n                    and self.world.eligible(g.issuer.account, space)):", "):"),
 "dead roots counted": ("live_roots = [r for r in roots if self._reach(x, [r]) & present]", "live_roots = roots"),
 "witnesses for pinned accounts": ("if self._pinned_account_wide(x):\n                    continue", "pass"),
 "no hold": ("if self.world.now - start >= REENROLL_HOLD:", "if True:"),
 "revoked stays usable": ("return b not in self.state.revoked and self.world.present(b)", "return self.world.present(b)"),
 "scoped pins become account-wide": ("self._pin(cand, space if self.anchors_anywhere(x) else None)", "self._pin(cand, None)"),
 "no provenance anchors": ("found.add(cited.issuer)\n                    break", "break"),
}
base = open(os.path.join(src, "peep_trust.py")).read()
for name, (old, new) in muts.items():
    assert old in base, name
    d = tempfile.mkdtemp()
    shutil.copy(os.path.join(src, "test_peep_trust.py"), d)
    open(os.path.join(d, "peep_trust.py"), "w").write(base.replace(old, new, 1))
    r = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", d], capture_output=True, text=True)
    fails = [l.split(" (")[0].replace("FAIL: ", "").replace("ERROR: ", "") for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
    print(f"{'CAUGHT' if fails else 'MISSED'} {name}: {', '.join(fails) or '-'}")
    shutil.rmtree(d)
