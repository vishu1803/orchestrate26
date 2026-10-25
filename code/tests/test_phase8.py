"""Requested source-path diagnostics, isolated from golden outputs and inference."""
import unittest
from _support import ROOT
from evaluation.phase8_funnel import classify_loss, scrub
from ghost_audit.io import DatasetReader
from ghost_audit.pipeline import AuditPipeline


class FirstLossTests(unittest.TestCase):
    def test_claim_missing_ownership_and_future_binding_are_distinct(self):
        for reason in ("no_supplied_target_observation", "activity_claims_only_no_supplied_state_readback",
                       "admissible_candidate_not_linked_to_subject", "case_result_withheld_by_other_unresolved_requirements"):
            self.assertEqual(classify_loss({"reason": reason}), "INSUFFICIENT_GROUNDED_EVIDENCE")
        self.assertEqual(classify_loss({"reason": "admissible_candidate_not_linked_to_subject", "rejected_subject_binding": True}), "TIME_FILTER_REJECTED")
        self.assertEqual(classify_loss({"reason": "unsupported_or_unknown_rule_condition"}), "POLICY_CONDITION_UNKNOWN_OR_MISAPPLIED")

    def test_original_schema_nulls_stable_ids_and_private_values(self):
        raw={"subject_reference":"user_fixture", "email":None,"phone":"+44 1234 567890",
             "retention_until":None,"message":"fixture@example.test"}
        redacted=scrub(raw)
        self.assertEqual(redacted["subject_reference"],"user_fixture")
        self.assertIsNone(redacted["email"])
        self.assertIsNone(redacted["retention_until"])
        self.assertEqual(redacted["phone"],"[REDACTED]")
        self.assertNotIn("fixture@example",redacted["message"])


class ActualParticipantSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader=DatasetReader()
        cls.pipeline=AuditPipeline.from_dataset(cls.reader.root)
        cls.requests={r.case_id:r for r in cls.reader.requests(sample=True)}

    def outcome(self,case_id):
        return self.pipeline.audit(self.requests[case_id])

    def test_03_scoped_trace_404_has_grounded_owner(self):
        o=self.outcome("case_03")
        records=[r for r in o.report.resources if r.resource_id=="account_7566"]
        self.assertTrue(records)
        self.assertTrue(any(r.record_existence=="ABSENT" for r in records))
        self.assertTrue(any(m.field=="trace_id" for r in records for m in r.match_reasons))

    def test_05_failover_presence_survives_primary_gaps(self):
        o=self.outcome("case_05")
        self.assertTrue(any(r.resource_id=="account_005" and r.scope.topology=="failover_replica" and r.record_existence=="PRESENT" for r in o.report.resources))
        self.assertEqual(o.result.deletion_status,"INCOMPLETE")

    def test_10_historical_alias_is_used(self):
        r=self.requests["case_10"]
        identity=self.pipeline.index.identity_index.resolve_request(r.email,r.audit_at)
        self.assertTrue(identity.historical_email)
        self.assertTrue(any(x.resource_id=="support_002" for x in self.outcome("case_10").report.resources))

    def test_11_handover_parsed_and_linked_without_retention_guess(self):
        o=self.outcome("case_11")
        decisions=[d for d in o.decisions if d.resource.resource_id=="audit_record_9394"]
        self.assertTrue(decisions)
        self.assertEqual(o.report.user_id,"user_32")
        self.assertEqual(decisions[0].resource.record_existence,"PRESENT")
        self.assertIsNone(decisions[0].verification)
        self.assertEqual(decisions[0].reason,"unsupported_or_unknown_rule_condition")

    def test_26_anonymous_readback_and_future_ownership_do_not_merge(self):
        o=self.outcome("case_26")
        targets={r.resource_id for r in o.report.resources}
        self.assertNotIn("account_5684",targets)
        self.assertNotIn("analytics_4566",targets)
        self.assertTrue(any(d.resource.resource_id=="audit_record_5416" and d.verification=="VERIFY_RECORD_PRESENT" for d in o.decisions))

    def test_31_cleared_tombstone_has_obligation_while_case_withheld(self):
        o=self.outcome("case_31")
        self.assertTrue(any(d.resource.resource_id=="tombstone_440" and d.compliant is True and d.verification=="VERIFY_RECORD_REDACTED" for d in o.decisions))
        self.assertIsNone(o.result)

    def test_32_exposed_tombstone_preserves_stable_reference(self):
        o=self.outcome("case_32")
        decisions=[d for d in o.decisions if d.resource.resource_id=="tombstone_9178"]
        self.assertTrue(any(d.compliant is False and d.remediation=="REDACT_RECORD" for d in decisions))
        self.assertFalse(any(s.operation=="DELETE_RECORD" and s.resource_id=="tombstone_9178" for s in o.result.steps))


if __name__=="__main__":
    unittest.main()
