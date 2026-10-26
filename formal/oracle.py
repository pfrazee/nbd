#!/usr/bin/python3 -I
"""Goal-ranking oracle for nbd.spthy (tamarin-prover --heuristic=o).

Tamarin passes the lemma name as the first argument and the open goals on
stdin, one per line as "N: goal". We print goal indices, best first.

The ranking keeps the search away from chains that never end: where an
issuer's copy of a space key came from (!Holds leads to an earlier grant,
and that to another), how live-binding counts were built up (LiveN and
Hold), how a client came to accept the signer of an approval (!Acc leads
to an earlier approval), and how the adversary learned a public key. Signature checks and adversary knowledge go
first, since they close most branches outright.

Under -D=INVITERS, how a binding got grant standing comes next, with the
approval that named it before where its signer's standing came from: the
approval's signature check usually closes the branch, while the signer's
standing leads to an earlier approval, and that to another.
"""

import re
import sys

# Best first. Signature checks settle a branch outright (an honest signer
# only ever signed what honest rules output), so they come before acceptance
# goals, which would otherwise walk back along approval chains.
RANKS = (
    ("Eq(", "verify"),
    ("!KU(", "KU("),
    ("!Dev(", "!Config(", "!Member("),
    ("!ApprovedBy(",),
    ("!Standing",),
    ("!Acc(",),
)
# Knowing a public key is never in doubt, but public keys appear in nearly
# every output, so solving "the adversary knows pk(x)" fans out into
# hundreds of irrelevant cases.
LAST = ("!Holds", "LiveN", "Hold(", "KU( pk(")


def rank(goal: str) -> int:
    if any(t in goal for t in LAST):
        return len(RANKS) + 1
    for r, tokens in enumerate(RANKS):
        if any(t in goal for t in tokens):
            return r
    return len(RANKS)


def main() -> None:
    goals = []
    for line in sys.stdin.read().splitlines():
        m = re.match(r"^(\d+):(.*)$", line)
        if m:
            goals.append((int(m.group(1)), m.group(2)))
    for i, _ in sorted(goals, key=lambda g: (rank(g[1]), g[0])):
        print(i)


if __name__ == "__main__":
    main()
