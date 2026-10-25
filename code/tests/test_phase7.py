"""Forensic diagnostics, closure and anti-overfitting regression fixtures."""
from dataclasses import replace
from datetime import timedelta
import json
import unittest
from _support import ROOT
from evaluation.forensics import analyze
from test_phase4 import fixture,profile,complete_records
from test_evidence_adapters import moment


class Phase7Tests(unittest.TestCase):
    def test_reference_hops_are_bounded_and_cross_system_collisions_blocked(self):
        from test_phase5 import pipeline,case
        from test_evidence_index import json_result,record
        parent=record("root",system_id="search_service",record_type="SEARCH_INDEX_ENTRY",email="new@example.test",source_resource_id="node-a",result="FOUND")
        nodes=[record("node-a",system_id="account_service",record_type="USER_PROFILE",source_resource_id="node-b",result="NOT_FOUND"),
               record("node-b",system_id="account_service",record_type="USER_PROFILE",source_resource_id="node-c",result="NOT_FOUND"),
               record("node-c",system_id="account_service",record_type="USER_PROFILE",result="NOT_FOUND")]
        outcome=pipeline([json_result({"records":[parent,*nodes]})]).audit(case())
        self.assertEqual({r.resource_id for r in outcome.report.resources},{"root","node-a","node-b"})
        collision=record("node-a",system_id="other_service",record_type="USER_PROFILE",result="NOT_FOUND")
        outcome=pipeline([json_result({"records":[parent,nodes[0],collision]})]).audit(case())
        self.assertNotIn("node-a",{r.resource_id for r in outcome.report.resources})
        self.assertTrue(any(g.code=="ambiguous_explicit_resource_reference" for g in outcome.blockers))

    def test_closure_includes_compliant_retained_and_noncompliant_scopes(self):
        from ghost_audit.planner import verification_closure,closure_inventory
        outcome,_,_=fixture([*complete_records(),profile(resource_id="remaining-profile")])
        keys=verification_closure(outcome.decisions)
        self.assertIn(("VERIFY_RECORD_PRESENT","security_service","fixture-audit"),keys)
        self.assertIn(("VERIFY_RECORD_ABSENT","account_service","remaining-profile"),keys)
        inventory=closure_inventory(outcome)
        self.assertTrue(all(x["emitted"] for x in inventory if x["verification"]))
        self.assertTrue(any(x["compliant"] is True for x in inventory))
        self.assertTrue(any(x["compliant"] is False for x in inventory))

    def test_closure_retains_known_obligations_even_when_verdict_withheld(self):
        from ghost_audit.planner import closure_inventory
        records=[x for x in complete_records() if x["record_type"]!="USER_PROFILE"]
        outcome,_,_=fixture(records)
        self.assertIsNone(outcome.result)
        inventory=closure_inventory(outcome)
        self.assertTrue(any(x["verification"]=="VERIFY_RECORD_PRESENT" for x in inventory))
        self.assertTrue(all(not x["emitted"] for x in inventory))

    def test_closure_is_source_order_invariant_and_unknown_condition_not_invented(self):
        from ghost_audit.planner import verification_closure
        outcome,_,_=fixture([*complete_records(),profile(resource_id="remaining-profile")])
        self.assertEqual(tuple(verification_closure(outcome.decisions)),tuple(verification_closure(tuple(reversed(outcome.decisions)))))
        outcome,_,_=fixture([{"resource_id":"retained-without-deadline","record_type":"SECURITY_AUDIT_LOG","system_id":"security_service"}])
        self.assertFalse(verification_closure(outcome.decisions))

    def test_explicit_reference_recovers_negative_but_not_claimed_absence(self):
        from test_phase5 import pipeline,case
        from test_evidence_index import json_result,record
        parent=record("linked-search",system_id="search_service",record_type="SEARCH_INDEX_ENTRY",email="new@example.test",source_resource_id="opaque-parent",result="FOUND")
        target=record("opaque-parent",system_id="account_service",record_type="USER_PROFILE",result="NOT_FOUND")
        out=pipeline([json_result({"records":[parent,target]})]).audit(case())
        self.assertIn("opaque-parent",{r.resource_id for r in out.report.resources})
        self.assertTrue(any(s.operation=="VERIFY_RECORD_ABSENT" and s.resource_id=="opaque-parent" for s in out.result.steps))
        out=pipeline([json_result({"records":[parent]})]).audit(case())
        self.assertTrue(any(g.code=="explicit_reference_without_state_readback" for g in out.blockers))
        self.assertFalse(any(s.resource_id=="opaque-parent" for s in out.result.steps))

    def test_explicit_reference_does_not_link_other_person_or_future(self):
        from test_phase5 import pipeline,case
        from test_evidence_index import json_result,record
        parent=record("linked-search",system_id="search_service",record_type="SEARCH_INDEX_ENTRY",email="new@example.test",source_resource_id="foreign",result="FOUND")
        target=record("foreign",system_id="account_service",record_type="USER_PROFILE",user_id="other-person",result="NOT_FOUND")
        out=pipeline([json_result({"records":[parent,target]})]).audit(case())
        self.assertNotIn("foreign",{r.resource_id for r in out.report.resources})
        target=record("foreign",system_id="account_service",record_type="USER_PROFILE",result="NOT_FOUND")
        out=pipeline([json_result(parent),json_result(target,"late-parent",6)]).audit(case())
        self.assertNotIn("foreign",{r.resource_id for r in out.report.resources})

    def test_reference_index_exact_values_scope_and_shuffled_order(self):
        from test_phase5 import pipeline,case
        from test_evidence_index import json_result,record
        records=[record("s",system_id="search_service",record_type="SEARCH_INDEX_ENTRY",email="new@example.test",source_resource_id="a",result="FOUND"),
                 record("a",system_id="account_service",record_type="USER_PROFILE",result="NOT_FOUND")]
        first=pipeline([json_result({"records":records})]);second=pipeline([json_result({"records":list(reversed(records))})])
        self.assertEqual(len(first.index.get_references("email"," NEW@EXAMPLE.TEST ",moment(5))),1)
        self.assertEqual(len(first.index.get_references("source_resource_id","a",moment(5))),1)
        from ghost_audit.output import result_row
        self.assertEqual(result_row(first.audit(case()).result),result_row(second.audit(case()).result))

    def test_trace_never_links_backward_or_across_declared_regions(self):
        from test_evidence_adapters import extract
        from test_phase5 import pipeline,case
        result=extract('.log','\n'.join([
            '2025-01-02T00:00:02Z service=account_service region=west event=profile_lookup_started trace_id=shared lookup_key=new@example.test',
            '2025-01-02T00:00:01Z service=account_service region=west event=profile_lookup_completed trace_id=shared resource_id=earlier rows=0 http_status=404',
            '2025-01-02T00:00:03Z service=account_service region=east event=profile_lookup_completed trace_id=shared resource_id=other-region rows=0 http_status=404',
            '2025-01-02T00:00:03Z service=account_service region=west event=profile_lookup_completed trace_id=shared resource_id=correct rows=0 http_status=404']))
        out=pipeline([result]).audit(case())
        self.assertEqual({r.resource_id for r in out.report.resources},{"correct"})

    @staticmethod
    def step(number=1,**values):
        return {"step_no":number,"phase":"VERIFICATION","system_id":"account_service","resource_id":"synthetic-profile",
                "operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":"proof",**values}

    def test_microscope_distinguishes_citation_state_and_position(self):
        a=self.step();b=self.step(2,resource_id="synthetic-other")
        actual=[{"case_id":"fixture","deletion_status":"COMPLETE","steps":[{**b,"step_no":1},{**a,"step_no":2,"evidence_id":"wrong"}]}]
        gold=[{"case_id":"fixture","deletion_status":"COMPLETE","steps":[a,b]}]
        report=analyze(actual,gold);case=report["cases"][0]
        self.assertEqual(case["progressive_matching"][0]["tp"],2)
        self.assertEqual(case["progressive_matching"][2]["tp"],1)
        self.assertEqual(case["progressive_matching"][3]["tp"],0)
        self.assertEqual(len(case["wrong_citations"]),1)
        self.assertEqual(case["first_divergence"]["position"],1)
        self.assertIn("wrong-order",case["tags"])
        changed=[{**actual[0],"steps":[{**a,"state":"PRESENT"}]}]
        self.assertTrue(analyze(changed,gold)["cases"][0]["wrong_states"])

    def test_microscope_flags_expected_future_source_without_licensing_it(self):
        from test_state import case
        request=case();step=self.step();row={"case_id":request.case_id,"deletion_status":"COMPLETE","steps":[step]}
        report=analyze([row],[row],source_times={"proof":request.audit_at+timedelta(seconds=1)},requests=[request])
        self.assertTrue(report["cases"][0]["exact_array"])
        self.assertEqual(len(report["cases"][0]["wrong_evidence_timing"]),2)
