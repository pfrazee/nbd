#!/usr/bin/python3 -I
"""Goal-ranking oracle for the relay-witness lemmas (tamarin-prover --heuristic=o).

Tamarin passes the lemma name as the first argument and the open goals on
stdin, one per line as "N: goal". We print goal indices, best first.

The witness lemmas are about positions in an installation's history, so a
witness record (!WRec) goes first: where it came from fixes its two
positions by a short case split. The cursors (OwnCur, WitCur) go last:
solving either walks back one position at a time to the start, and the
reused witness_owner_step lemma already gives the step back. Adversary
knowledge goes last too, unlike in oracle.py: solving how the adversary
learned a relayed entry leads into the base model's public-key and grant
chains, which never bear on positions. Acceptance and live-binding goals
go last for the same reasons as in oracle.py.
"""

import re
import sys

# Best first.
RANKS = (
    ("!WRec(",),
    ("OwnerAt(", "OwnerSees(", "OwnerGap(", "Recon(", "Gap(", "UsesWitness(", "WitnessInit("),
    ("Eq(", "verify"),
    ("RelayAt(", "!Relayed("),
)
LAST = ("OwnCur(", "WitCur(", "KU(", "!Acc(", "!Holds", "LiveN", "Hold(")


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
