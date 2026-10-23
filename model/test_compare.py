"""Pin the variant comparison so model changes that shift it are noticed.

Run: python3 -I -m unittest discover -s model
"""

import unittest

import compare

C, H, D, S = "compromised", "hold", "declined", "safe"

# Columns: TOFU + approvals (spec), Warnings only, Account-wide anchors,
# Scoped witnesses.
EXPECTED = {
    "root_theft_with_honest_witness": (C, S, S, S),
    "unlinked_device_beside_live": (D, D, S, S),
    "reset_seen_by_newcomer": (C, H, H, H),
    "creator_reset_seen_by_newcomer": (C, H, H, H),
    "reset_seen_by_pinned_client": (H, H, H, H),
    "takeover_adds_device_for_existing_contact": (S, S, S, S),
    "colluding_accounts_same_pds": (C, S, S, S),
    "colluding_witness_cross_space": (C, C, C, S),
    "colluding_witness_cross_space_no_private_witness": (C, C, C, C),
    "single_pds_manufactures_witness": (C, C, C, S),
    "witness_chain": (C, C, C, S),
    "retire_only_anchored_branch": (S, H, H, H),
    "forged_witness_missing_binding": (S, H, H, H),
}


class Comparison(unittest.TestCase):
    def test_outcomes_match_expected_table(self):
        self.assertEqual({fn.__name__ for _, fn in compare.SCENARIOS}, set(EXPECTED))
        for _, fn in compare.SCENARIOS:
            got = tuple(fn(cls) for _, cls in compare.VARIANTS)
            self.assertEqual(got, EXPECTED[fn.__name__], fn.__name__)

    def test_spec_is_compromised_only_at_first_contact(self):
        for _, fn in compare.SCENARIOS:
            if fn(compare.SpecClient) == C:
                self.assertTrue(compare.FIRST_CONTACT.get(fn.__name__, True), fn.__name__)


if __name__ == "__main__":
    unittest.main()
