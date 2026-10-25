"""Supplied policy-table parsing; condition interpretation remains pending."""
import tempfile
import unittest
from pathlib import Path
from _support import DATASET
from ghost_audit.models import PolicyAction
from ghost_audit.policy import read_policy_rules


class PolicyStructureTests(unittest.TestCase):
    def test_policy_rows_and_actions(self):
        rules = read_policy_rules(DATASET / "deletion_rules.csv")
        self.assertEqual(len(rules), 15)
        self.assertEqual({r.required_action for r in rules}, set(PolicyAction))
        self.assertTrue(all(r.rule_id and r.data_category and r.condition for r in rules))

    def test_retention_tombstone_and_backup_rules_present(self):
        by_category = {r.data_category: r for r in read_policy_rules(DATASET / "deletion_rules.csv")}
        for category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE"):
            self.assertEqual(by_category[category].required_action, PolicyAction.RETAIN)
        self.assertEqual(by_category["ACCOUNT_TOMBSTONE"].required_action, PolicyAction.REDACT)

    def test_policy_reader_rejects_invalid_rows(self):
        header = "rule_id,data_category,condition,required_action\n"
        for body in ("synthetic,USER_PROFILE,Always,INVENTED\n",
                     "synthetic,USER_PROFILE,,DELETE\n",
                     "synthetic,USER_PROFILE,Always,DELETE\nsynthetic,CACHE_ENTRY,Always,DELETE\n"):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "deletion_rules.csv"
                path.write_text(header + body, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_policy_rules(path)

    def test_policy_application(self):
        from test_phase4 import fixture, profile
        outcome, _, _ = fixture([profile()])
        self.assertFalse(outcome.decisions[0].compliant)
        self.assertEqual(outcome.decisions[0].rule.required_action, PolicyAction.DELETE)
        self.assertEqual(outcome.decisions[0].remediation, "DELETE_RECORD")
