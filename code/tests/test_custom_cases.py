"""Custom scenario definitions are validated; actual agent outcomes remain pending."""
import unittest
from _support import ROOT
from evaluation.custom_cases import CUSTOM_CASES
from ghost_audit.models import Status


class CustomCaseStructureTests(unittest.TestCase):
    def test_three_independent_scenarios_are_defined(self):
        self.assertGreaterEqual(len(CUSTOM_CASES), 3)
        self.assertEqual(len({c.name for c in CUSTOM_CASES}), len(CUSTOM_CASES))
        for case in CUSTOM_CASES:
            self.assertIn(case.expected_status, {s.value for s in Status})
            self.assertTrue(case.request_text and case.setup and case.expected_checks and case.mutation)

    def test_required_custom_risks_are_covered(self):
        self.assertEqual({c.name for c in CUSTOM_CASES}, {"access_without_deletion", "tombstone_exposes_email", "sync_reintroduces_record"})

    def test_custom_agent_outcomes(self):
        from evaluation.custom_cases import run_independent_cases
        rows = run_independent_cases()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row[0]["passed"] for row in rows))
