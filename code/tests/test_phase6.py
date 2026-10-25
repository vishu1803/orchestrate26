"""Submission fallback and independent validation mutations, without public labels."""
import csv
import json
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from _support import ROOT
from test_phase4 import fixture, profile
from ghost_audit.models import Status
from ghost_audit.submission import submission_row, write_submission
from scripts.validate_output import inspect_csv


class Phase6Tests(unittest.TestCase):
    def test_actual_packaging_includes_ocr_and_reports_without_corpus(self):
        from scripts.package_submission import build_archive
        import zipfile
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            files={"README.md":"README", "code/main.py":"pass", "code/ghost_audit/windows_ocr.ps1":"# local OCR",
                   "code/evaluation/evaluation_report.md":"measured", "code/evaluation/usage_report.md":"measured",
                   "code/__pycache__/x.py":"excluded", "dataset/private.csv":"excluded", "code/nested.zip":"excluded"}
            for name,text in files.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding="utf-8")
            first=build_archive(root,root/"code.zip")
            with zipfile.ZipFile(root/"code.zip") as archive:
                names=archive.namelist()
                self.assertIn("code/ghost_audit/windows_ocr.ps1",names)
                self.assertIn("evaluation/usage_report.md",names)
                self.assertIn("code/evaluation/usage_report.md",names)
                self.assertFalse(any("dataset" in n or "__pycache__" in n or n.endswith(".zip") for n in names))
                self.assertIsNone(archive.testzip())
            self.assertEqual(first["sha256"],build_archive(root,root/"code.zip")["sha256"])

    def test_captured_profile_panel_is_not_dated_by_last_contact(self):
        from test_phase5 import Phase5Tests, pipeline
        from test_evidence_index import json_result, record
        from ghost_audit.documents import validated_ocr_observations
        from ghost_audit.state_facts import temporal_rejection
        from test_evidence_adapters import moment
        doc=Phase5Tests.visual([("Customer Operations",250,20),("user_fixture account_fixture",250,140),
                               ("Email",250,235),("new@example.test",250,255),
                               ("Last contact",1200,235),("01 Jan 2020 01:00 UTC",1200,255)])
        index=pipeline([json_result(record("account_fixture",system_id="account_service",record_type="USER_PROFILE"))]).index
        observations=validated_ocr_observations((doc,),index)
        self.assertEqual(len(observations),1)
        self.assertEqual(observations[0].observed_at,doc.source.available_at)
        self.assertNotIn("user_id",observations[0].attributes)
        self.assertIn("user_fixture",observations[0].attributes["document_text"])
        self.assertEqual(temporal_rejection(observations[0],moment(1)),"captured_after_cutoff")
        self.assertFalse(validated_ocr_observations((doc,),pipeline([]).index))
        from ghost_audit.normalization import freeze
        regions=list(doc.regions)
        regions[1]=freeze({"text":"user_ll account _fixture","words":[
            {"text":"user_ll","x":250,"y":140,"width":40,"height":12},
            {"text":"account","x":300,"y":140,"width":48,"height":12},
            {"text":"_fixture","x":350,"y":140,"width":50,"height":12}]})
        segmented=replace(doc,regions=tuple(regions))
        self.assertEqual(validated_ocr_observations((segmented,),index)[0].resource_id,"account_fixture")
        words=[dict(w) for w in regions[1]["words"]];words[-1]["text"]="_fixlure"
        regions[1]=freeze({"text":"user_ll account _fixlure","words":words})
        self.assertFalse(validated_ocr_observations((replace(doc,regions=tuple(regions)),),index))

    def test_order_content_establishes_shared_context_without_case_shortcut(self):
        raw={"resource_id":"synthetic-support", "system_id":"support_platform", "record_type":"SUPPORT_MESSAGE",
             "message_text":"Please send the delivery update to new@example.test. The affected order includes: a fictional item.",
             "email":"new@example.test"}
        outcome,_,_=fixture([raw])
        self.assertEqual(outcome.result.deletion_status,Status.INCOMPLETE)
        self.assertIn("REDACT_RECORD",{s.operation for s in outcome.result.steps})
        raw["message_text"]="Customer supplied contact details for a delivery query."
        outcome,_,_=fixture([raw])
        self.assertIsNone(outcome.result)
        self.assertTrue(any(g.code=="unsupported_or_unknown_rule_condition" for g in outcome.blockers))

    def test_unknown_authorized_is_conservative_without_invented_steps(self):
        outcome,pipeline,request=fixture([profile(result="UNKNOWN")])
        self.assertIsNone(outcome.result)
        row=submission_row(outcome)
        self.assertEqual(row["deletion_status"],"INCOMPLETE")
        self.assertEqual(json.loads(row["steps_json"]),[])
        self.assertTrue(outcome.blockers)

    def test_nondeletion_retains_empty_not_applicable(self):
        outcome,_,_=fixture([],text="Please export my account data.")
        self.assertEqual(submission_row(outcome)["deletion_status"],"NOT_APPLICABLE")
        self.assertEqual(submission_row(outcome)["steps_json"],"[]")

    def test_observed_incomplete_plan_preserves_all_evidence(self):
        outcome,_,_=fixture([profile()])
        row=submission_row(outcome)
        self.assertEqual(row["deletion_status"],"INCOMPLETE")
        steps=json.loads(row["steps_json"])
        self.assertEqual(len(steps),3)
        self.assertTrue(steps[0]["evidence_id"])
        self.assertTrue(all(s["evidence_id"]=="" for s in steps[1:]))

    def test_positive_complete_is_never_fallback(self):
        outcome,_,_=fixture([profile(result="NOT_FOUND")])
        self.assertEqual(outcome.result.deletion_status,Status.COMPLETE)
        self.assertEqual(submission_row(outcome)["deletion_status"],"COMPLETE")
        self.assertTrue(json.loads(submission_row(outcome)["steps_json"])[0]["evidence_id"])

    def inspect(self,row,request,times):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"candidate.csv"
            write_submission([row],p,[request.case_id])
            return inspect_csv(p,[request.case_id],times,[request])

    def test_independent_empty_fallback_and_not_complete(self):
        outcome,_,request=fixture([profile(result="UNKNOWN")])
        row=submission_row(outcome)
        self.assertEqual(len(self.inspect(row,request,{})),1)
        with self.assertRaisesRegex(ValueError,"invalid_steps_array"):
            self.inspect({**row,"deletion_status":"COMPLETE"},request,{})

    def test_independent_source_membership_and_future_capture(self):
        outcome,pipeline,request=fixture([profile()])
        row=submission_row(outcome)
        steps=json.loads(row["steps_json"]);source=steps[0]["evidence_id"]
        with self.assertRaisesRegex(ValueError,"unknown_or_future"):
            self.inspect(row,request,{})
        from datetime import timedelta
        with self.assertRaisesRegex(ValueError,"unknown_or_future"):
            self.inspect(row,request,{source:request.audit_at+timedelta(seconds=1)})
        self.assertEqual(len(self.inspect(row,request,{source:request.audit_at})),1)

    def test_independent_citation_order_and_pii_mutations(self):
        outcome,_,request=fixture([profile()]);row=submission_row(outcome)
        original=json.loads(row["steps_json"]);times={original[0]["evidence_id"]:request.audit_at}
        for kind in ("number","phase","future_citation","pii","duplicate"):
            steps=json.loads(row["steps_json"])
            if kind=="number":steps[0]["step_no"]=2
            if kind=="phase":steps[0]["phase"]="VERIFICATION"
            if kind=="future_citation":steps[1]["evidence_id"]=steps[0]["evidence_id"]
            if kind=="pii":steps[0]["resource_id"]="person@example.test"
            if kind=="duplicate":steps.append({**steps[-1],"step_no":4})
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                self.inspect({**row,"steps_json":json.dumps(steps)},request,times)

    def test_lexical_real_ids_not_numeric_sort(self):
        from ghost_audit.io import DatasetReader
        ids=[r.case_id for r in DatasetReader().requests()]
        rows=[{"case_id":k,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"} for k in reversed(ids)]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"rows.csv";write_submission(rows,path,ids)
            with path.open(encoding="utf-8",newline="") as handle:actual=[r["case_id"] for r in csv.DictReader(handle)]
            self.assertEqual(actual,sorted(ids));self.assertEqual(len(actual),518)
