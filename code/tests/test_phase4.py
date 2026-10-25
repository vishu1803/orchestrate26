"""Independent end-to-end decisions, condition, compiler, evaluator and mutation tests."""
from dataclasses import asdict, replace
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from _support import DATASET, ROOT
from test_evidence_adapters import moment
from test_evidence_index import json_result, record
from test_identity import snapshot, change
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.identity import IdentityIndex
from ghost_audit.intent import classify_intent
from ghost_audit.io import DatasetReader
from ghost_audit.models import AuditResult, OPERATION_CONTRACT, Status, Step
from ghost_audit.output import result_row, validate_case, validate_rows, validate_steps_contract, write_output
from ghost_audit.pipeline import AuditPipeline
from ghost_audit.planner import execution_order
from ghost_audit.policy import apply_policy
from ghost_audit.timeline import StateEngine
from test_state import case
from evaluation.metrics import score_predictions


def fixture(records, text="Please delete my account and personal data.", identity=None, rules=None):
    rows = []
    for n, raw in enumerate(records):
        rows.append(record(raw.get("resource_id", "fixture-r"), **{"system_id": "account_service", "user_id": "subject-a",
                                                                  **{k: v for k, v in raw.items() if k != "resource_id"}}))
    index = EvidenceIndex([json_result({"records": rows})], identity_index=identity or IdentityIndex([snapshot()], []))
    pipeline = AuditPipeline(StateEngine(index), rules if rules is not None else DatasetReader().rules())
    request = case()
    request = replace(request, request_text=text)
    return pipeline.audit(request), pipeline, request


def profile(**values):
    return {"resource_id": "fixture-profile", "record_type": "USER_PROFILE", "result": "FOUND", **values}


def support(**values):
    return {"resource_id": "fixture-support", "system_id": "support_platform", "record_type": "SUPPORT_MESSAGE",
            "shared_context": True, "email": "new@example.test", **values}


def complete_records():
    return [profile(result="NOT_FOUND"),
            support(email=None, name=None, phone=None, email_hash=None),
            {"resource_id": "fixture-analytics", "system_id": "analytics_platform", "record_type": "ANALYTICS_PROFILE",
             "result": "ANONYMIZED", "user_id": None, "query": {"email": "new@example.test"}, "email": None,
             "phone": None, "email_hash": None, "irreversibly_unlinked": True},
            {"resource_id": "fixture-audit", "system_id": "security_service", "record_type": "SECURITY_AUDIT_LOG", "retention_until": "2030-01-01T00:00:00Z"},
            {"resource_id": "fixture-flow", "system_id": "integration_service", "record_type": "DATA_FLOW", "enabled": False},
            {"resource_id": "fixture-backup", "system_id": "backup_service", "record_type": "BACKUP_ARCHIVE", "restore_allowed": False}]


class Phase4Tests(unittest.TestCase):
    def test_non_deletion_gates_before_identity_and_state(self):
        for text in ("Please export my account data.", "Correct my phone without deleting my records.",
                     "Please remove me from marketing lists only.", "What is the data retention policy?",
                     "Please change the email address used for this account.",
                     "The number is outdated. Please replace it and leave my account active."):
            out, pipeline, request = fixture([profile()], text)
            self.assertEqual(out.result.deletion_status, "NOT_APPLICABLE")
            self.assertEqual(out.result.steps, ())
            with patch.object(pipeline.state_engine, "reconstruct_case", side_effect=AssertionError("investigation")):
                self.assertEqual(pipeline.audit(request), out)

    def test_multilingual_positive_and_negative(self):
        positives = ("Please delete my account.", "Solicito la eliminación de mi cuenta.", "Solicito a exclusão da conta.",
                     "Je demande la suppression de mon compte.", "계정 삭제를 요청합니다.", "アカウントの削除を依頼します。")
        negatives = ("Do not delete my account.", "No quiero eliminar mi cuenta, solo una copia.", "Não quero excluir a conta.",
                     "Ne supprimez pas mon compte.", "계정을 삭제하지 마세요. 정보 열람만 요청합니다.", "アカウントを削除しないでください。開示だけお願いします。")
        self.assertTrue(all(classify_intent(t).authorization == "AUTHORIZED" for t in positives))
        self.assertTrue(all(classify_intent(t).authorization == "OTHER_REQUEST" for t in negatives))
        self.assertEqual(classify_intent("unclear unknown phrase").authorization, "UNRESOLVED")

    def test_mere_deletion_mention_is_not_authorization(self):
        for text in ("How can I delete my account?", "Please explain how deletion works.", "I am not asking for deletion.",
                     "My account was deleted. Please export my records.",
                     "I read about deletion of accounts. Please export my data.", "What does deleting my account do?"):
            self.assertNotEqual(classify_intent(text).authorization, "AUTHORIZED")

    def test_delete_account_but_preserve_retained_records(self):
        self.assertEqual(classify_intent("Delete my account, but do not delete security records.").authorization, "AUTHORIZED")
        for text in ("Please begin a permanent account-deletion request.", "I am requesting deletion of my account.",
                     "I would like it permanently deleted, including my account.",
                     "Could you verify that the profile is gone?", "Please delete that export file."):
            self.assertEqual(classify_intent(text).authorization, "AUTHORIZED")

    def test_ambiguous_intent_has_no_external_status(self):
        out, _, _ = fixture([profile()], "Maybe something should happen.")
        self.assertIsNone(out.result)
        self.assertTrue(any("intent" in g.code for g in out.blockers))

    def test_delete_emits_exact_three_steps(self):
        out, pipeline, request = fixture([profile()])
        self.assertEqual(out.result.deletion_status, "INCOMPLETE")
        self.assertEqual([s.operation for s in out.result.steps], ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])
        self.assertEqual([s.evidence_id for s in out.result.steps], ["fixture", "", ""])
        validate_case(out, request, pipeline.index, require_complete_coverage=True)

    def test_missing_policy_condition_does_not_default_delete(self):
        out, _, _ = fixture([profile(record_type="UNRECOGNIZED")])
        self.assertIsNone(out.result)
        self.assertTrue(out.blockers)
        out, _, _ = fixture([{**support(), "shared_context": None}], text="Delete my personal information.")
        self.assertIsNone(out.result)

    def test_support_redacts_and_keeps_record(self):
        out, _, _ = fixture([support()], text="Delete my personal information.")
        ops = {s.operation for s in out.result.steps}
        self.assertEqual(ops, {"REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"})
        self.assertTrue(out.decisions[0].preserve_record)

    def test_tombstone_hash_and_legal_hold_custom(self):
        from evaluation.custom_cases import run_independent_cases
        rows = run_independent_cases()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r[0]["passed"] for r in rows))
        out = rows[1][1]
        self.assertFalse(any(s.operation == "DELETE_RECORD" for s in out.result.steps))
        self.assertTrue(any(s.operation == "VERIFY_RECORD_PRESENT" for s in out.result.steps))

    def test_tombstone_stable_only_is_compliant(self):
        raw = {"record_type": "ACCOUNT_TOMBSTONE", "system_id": "identity_service", "account_status": "DELETED",
               "references_required": True, "name": None, "email": None, "phone": None, "email_hash": None}
        out, _, _ = fixture([raw], text="Remove my personal information.")
        self.assertEqual(out.result.deletion_status, "COMPLETE")
        self.assertEqual(out.result.steps[0].operation, "VERIFY_RECORD_REDACTED")

    def test_null_email_with_stable_analytics_reference_needs_anonymization(self):
        raw = {"record_type": "ANALYTICS_PROFILE", "system_id": "analytics_platform", "email": None, "phone": None, "email_hash": None}
        out, _, _ = fixture([raw], text="Remove my personal information.")
        self.assertTrue(any(s.operation == "ANONYMIZE_RECORD" for s in out.result.steps))

    def test_anonymized_marker_without_unlinking_proof_blocks(self):
        raw = {"record_type": "ANALYTICS_PROFILE", "system_id": "analytics_platform", "result": "ANONYMIZED", "user_id": None,
               "query": {"email": "new@example.test"}, "email": None}
        out, _, _ = fixture([raw], text="Remove my personal information.")
        self.assertIsNone(out.result)

    def test_active_flow_restore_and_archive_retention(self):
        from evaluation.custom_cases import run_independent_cases
        info, out, _, _ = run_independent_cases()[2]
        self.assertTrue(info["passed"])
        ops = [s.operation for s in out.result.steps if s.phase == "REMEDIATION"]
        self.assertEqual(ops, ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"])
        self.assertFalse(any(s.operation == "DELETE_RECORD" and s.resource_id == "fixture-backup" for s in out.result.steps))

    def test_complete_verifies_all_required_baselines(self):
        out, pipeline, request = fixture(complete_records())
        self.assertEqual(out.result.deletion_status, "COMPLETE")
        self.assertTrue(all(s.phase == "VERIFICATION" and s.evidence_id for s in out.result.steps))
        self.assertEqual({s.operation for s in out.result.steps}, {"VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                         "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"})
        validate_case(out, request, pipeline.index, require_complete_coverage=True)

    def test_incomplete_verifies_already_compliant_baselines(self):
        out, _, _ = fixture([*complete_records(), {"record_type": "USER_EXPORT", "system_id": "export_service", "resource_id": "fixture-export"}])
        self.assertEqual(out.result.deletion_status, "INCOMPLETE")
        checks = [s for s in out.result.steps if s.phase == "VERIFICATION"]
        self.assertTrue(all(not s.evidence_id for s in checks))
        self.assertEqual(len(checks), 8)

    def test_primary_absence_cannot_clear_failover(self):
        raw = {"snapshots": [{"topology": "primary", "records": [record("r", system_id="account_service", record_type="USER_PROFILE", user_id="subject-a", result="NOT_FOUND")]},
                             {"topology": "failover_replica", "records": [record("r", system_id="account_service", record_type="USER_PROFILE", user_id="subject-a", result="FOUND")]}]}
        index = EvidenceIndex([json_result(raw)], identity_index=IdentityIndex([snapshot()], []))
        out = AuditPipeline(StateEngine(index), DatasetReader().rules()).audit(replace(case(), request_text="Delete my account."))
        self.assertEqual(out.result.deletion_status, "INCOMPLETE")
        self.assertEqual({r.scope.topology: r.record_existence for r in out.report.resources}, {"primary": "ABSENT", "failover_replica": "PRESENT"})
        self.assertTrue(any(s.operation == "REPORT_REMAINING_RECORD" for s in out.result.steps))

    def test_future_evidence_is_never_cited(self):
        out, pipeline, request = fixture([profile(observed_at=moment(6).isoformat())])
        self.assertIsNone(out.result)
        self.assertTrue(out.blockers)

    def test_empty_partial_scope_and_missing_account_block_complete(self):
        out, _, _ = fixture([{"record_type": "SECURITY_AUDIT_LOG", "retention_until": "2030-01-01T00:00:00Z"}])
        self.assertIsNone(out.result)
        self.assertTrue(any(g.code == "requested_account_scope_not_established" for g in out.blockers))

    def test_unknown_only_does_not_get_incomplete_label(self):
        out, _, _ = fixture([profile(result="UNSUPPORTED")])
        self.assertIsNone(out.result)

    def test_all_operations_and_states_are_exercised(self):
        from evaluation.custom_cases import run_independent_cases
        outcomes = [r[1] for r in run_independent_cases()]
        outcomes += [fixture(complete_records())[0], fixture([support()], text="Delete my personal information.")[0],
                     fixture([{"record_type": "ANALYTICS_PROFILE", "email": "new@example.test"}], text="Delete my personal information.")[0]]
        observed = {s.operation: (s.phase, s.state) for out in outcomes for s in out.result.steps}
        self.assertEqual(observed, OPERATION_CONTRACT)

    def test_retention_deadline_and_legal_hold_are_not_assumed(self):
        for raw in ({"record_type": "SECURITY_AUDIT_LOG", "retention_until": "2024-01-01T00:00:00Z"},
                    {"record_type": "LEGAL_HOLD_RECORD", "hold_active": False},
                    {"record_type": "SUPPORT_ATTACHMENT"}):
            out, _, _ = fixture([raw], text="Delete my personal information.")
            self.assertIsNone(out.result)
            self.assertFalse(any(d.remediation == "DELETE_RECORD" for d in out.decisions))

    def test_csv_condition_is_loaded_not_just_category_action(self):
        rules = [replace(r, condition="Undocumented future condition") if r.data_category == "USER_PROFILE" else r for r in DatasetReader().rules()]
        out, _, _ = fixture([profile()], rules=rules)
        self.assertIsNone(out.result)

    def test_citation_mutation_and_missing_verification_rejected(self):
        out, pipeline, request = fixture([profile()])
        bad = replace(out.result.steps[0], evidence_id="invented")
        mutant = replace(out, result=replace(out.result, steps=(bad, *out.result.steps[1:])))
        with self.assertRaises(ValueError):
            validate_case(mutant, request, pipeline.index)
        mutant = replace(out, result=replace(out.result, steps=out.result.steps[:-1]))
        with self.assertRaises(ValueError):
            validate_case(mutant, request, pipeline.index)

    def test_unsupported_complete_and_retained_delete_rejected(self):
        out, pipeline, request = fixture([profile()])
        mutant = replace(out, result=replace(out.result, deletion_status=Status.COMPLETE))
        with self.assertRaises(ValueError):
            validate_case(mutant, request, pipeline.index)

    def test_duplicate_conflicting_actions_and_numbering_rejected(self):
        out, _, _ = fixture([profile()])
        rows = json.loads(result_row(out.result)["steps_json"])
        duplicate = [rows[0], {**rows[0], "step_no": 2}, *[{**s, "step_no": s["step_no"] + 1} for s in rows[1:]]]
        with self.assertRaises(ValueError):
            validate_steps_contract("INCOMPLETE", duplicate)
        rows[1]["step_no"] = 99
        with self.assertRaises(ValueError):
            validate_steps_contract("INCOMPLETE", rows)

    def test_sort_order_and_deterministic_batch_reuse(self):
        out, pipeline, request = fixture([profile(), {"record_type": "USER_EXPORT", "resource_id": "aaa", "system_id": "export_service"}])
        with patch("ghost_audit.evidence.parse_evidence", side_effect=AssertionError("reparse")):
            again = pipeline.audit(request)
        self.assertEqual(result_row(out.result), result_row(again.result))
        self.assertEqual([s.step_no for s in out.result.steps], list(range(1, len(out.result.steps) + 1)))

    def test_execution_dependencies_preserve_official_wire_order(self):
        records = [profile(), {"resource_id": "fixture-search", "system_id": "search_service", "record_type": "SEARCH_INDEX_ENTRY",
                               "source_resource_id": "fixture-profile"}]
        out, _, _ = fixture(records)
        remediation = {s.resource_id: s.step_no for s in out.result.steps if s.phase == "REMEDIATION"}
        self.assertLess(remediation["fixture-profile"], remediation["fixture-search"])
        self.assertLess(out.execution_order.index(remediation["fixture-search"]), out.execution_order.index(remediation["fixture-profile"]))

    def test_readiness_rejects_partial_but_responsible_incomplete_is_visible(self):
        out, pipeline, request = fixture([profile(), {"record_type": "UNMAPPED", "resource_id": "other"}])
        self.assertEqual(out.result.deletion_status, "INCOMPLETE")
        self.assertTrue(out.blockers)
        with self.assertRaises(ValueError):
            validate_case(out, request, pipeline.index, require_complete_coverage=True)

    def test_historical_alias_and_opaque_hash_lookup(self):
        identity = IdentityIndex([snapshot()], [change()])
        out, _, _ = fixture([profile(user_id=None, lookup_key="OpaqueHash")], identity=identity)
        self.assertEqual(out.result.deletion_status, "INCOMPLETE")
        self.assertTrue(any(m.field == "opaque_reference" for r in out.report.resources for m in r.match_reasons))

    def test_index_query_nested_documents_are_target_specific(self):
        raw = {"record_type": "SEARCH_INDEX_ENTRY", "resource_id": "target", "hits": {"total": 1, "documents": [{"resource_id": "target", "email": "new@example.test"}]}}
        out, _, _ = fixture([raw], text="Delete my personal information.")
        # Generic fixtures are SNAPSHOTs; actual service queries are independently
        # tested through the explicit adapter schema below.
        index = EvidenceIndex([json_result({"service_exports": {"search_service": {"index_queries": [{**record("target"), "query": "new@example.test", "hits": raw['hits']}]}}})], identity_index=IdentityIndex([snapshot()], []))
        outcome = AuditPipeline(StateEngine(index), DatasetReader().rules()).audit(replace(case(), request_text="Delete my personal information."))
        self.assertEqual(outcome.result.deletion_status, "INCOMPLETE")

    def test_wire_row_coverage_uses_requested_case_set(self):
        results = [AuditResult(f"synthetic-{n:04}", Status.NOT_APPLICABLE, ()) for n in range(518)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "candidate.csv"
            write_output(results, path, [r.case_id for r in results])
            with path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            validate_rows(rows, [r.case_id for r in results])
            with self.assertRaises(ValueError):
                validate_rows(rows[:-1], [r.case_id for r in results])
            with self.assertRaises(ValueError):
                validate_rows(rows, ["different"])

    def test_metrics_multisets_fields_missing_and_order_are_independent(self):
        step = {"step_no": 1, "phase": "VERIFICATION", "system_id": "s", "resource_id": "a", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e"}
        other = {**step, "step_no": 2, "resource_id": "b"}
        labels = [{"case_id": "x", "deletion_status": "COMPLETE", "steps": [step, other]}]
        perfect = score_predictions(labels, labels)
        self.assertEqual(perfect["status"]["accuracy"], 1)
        self.assertEqual(perfect["steps"]["true_positive"], 2)
        swapped = score_predictions([{**labels[0], "steps": [{**other, "step_no": 1}, {**step, "step_no": 2}]}], labels)
        self.assertEqual(swapped["steps"]["f1"], 1)
        self.assertEqual(swapped["sequence"]["accuracy"], 0)
        self.assertEqual(swapped["fields"]["step_no"]["correct"], 0)
        missing = score_predictions([], labels)
        self.assertEqual(missing["status"]["accuracy"], 0)
        self.assertIsNone(missing["steps"]["precision"])
        duplicate = score_predictions([{**labels[0], "steps": [step, step, other]}], labels)
        self.assertEqual(duplicate["steps"]["false_positive"], 1)

    def test_metrics_reject_duplicate_cases_and_extra_rows(self):
        row = {"case_id": "x", "deletion_status": "NOT_APPLICABLE", "steps": []}
        with self.assertRaises(ValueError):
            score_predictions([row, row], [row])
        with self.assertRaises(ValueError):
            score_predictions([row], [])

    def test_no_root_prediction_or_zip(self):
        # Phase6 explicitly authorizes local artifacts; no hidden/extra outputs.
        if (ROOT / "output.csv").exists():
            import csv
            with (ROOT / "output.csv").open(encoding="utf-8",newline="") as handle:
                output=list(csv.DictReader(handle))
            self.assertEqual(len(output),518)
            self.assertEqual({r["case_id"] for r in output},{r.case_id for r in DatasetReader().requests()})
        self.assertFalse((ROOT / "agent-trace.zip").exists())

    def test_document_fields_use_actual_labeled_clock_and_page(self):
        from ghost_audit.documents import validated_document_observations
        from ghost_audit.models import VisualDocument, SourceRef
        text = "COMPLIANCE JOURNAL - SIGNED RECORD EXTRACT\nissued 02 Jan 2025 09 30 UTC\nEvent reference audit_record_fixture\nsubject reference user_fixture\nrecorded 01 Jan 2025 04 00 UTC\nretain until 01 Jan 2026 04 00 UTC"
        doc = VisualDocument(SourceRef("participant_pdf", moment(3), "page:1", "evidence/fiction.pdf", "security_service", "fixture-digest"),
                             "text_extracted", text, (), (), (), None, True, "pdftotext:-raw", ())
        observations = validated_document_observations((doc,))
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].resource_id, "audit_record_fixture")
        self.assertEqual(observations[0].observed_at.hour, 9)
        self.assertTrue(observations[0].source.locator.startswith("page:1/text:"))
        changed = replace(doc, raw_text=text.replace("09 30 UTC", "unreadable"))
        self.assertFalse(validated_document_observations((changed,)))
        ocr = replace(doc, backend="Windows.Media.Ocr")
        self.assertFalse(validated_document_observations((ocr,)))

    def test_document_attachment_presence_does_not_invent_exclusivity(self):
        from ghost_audit.documents import validated_document_observations
        from ghost_audit.models import VisualDocument, SourceRef
        text = "DELIVERY ADDRESS CORRECTION REQUEST\nSupport reference CS-FIXTURE / support_fixture\nfixture@example.invalid\nAttachment properties and upload history\ncaptured 02 Jan 2025 09 30 UTC"
        doc = VisualDocument(SourceRef("participant_pdf", moment(3), "page:1", "evidence/fiction.pdf", "support_platform", "fixture-digest"),
                             "text_extracted", text, (), (), (), None, True, "pdftotext:-raw", ())
        observations = validated_document_observations((doc,))
        self.assertEqual(observations[0].data_category, "SUPPORT_ATTACHMENT")
        self.assertNotIn("exclusive_subject", observations[0].attributes)
        page_one = replace(doc, raw_text="DELIVERY ADDRESS CORRECTION REQUEST\nSupport reference CS-FIXTURE / support_fixture\nfixture@example.invalid")
        page_two = replace(doc, source=replace(doc.source, locator="page:2"),
                           raw_text="Attachment properties and upload history\ncaptured 02 Jan 2025 09 30 UTC")
        combined = validated_document_observations((page_one, page_two))[0]
        self.assertIn("page:2/text:0:", combined.source.locator)
        self.assertEqual(len(combined.context["document_text_spans"]), 2)

    def test_opaque_reference_cross_person_collision_is_not_merged(self):
        identity = IdentityIndex([snapshot(), snapshot("b", "other@example.test", email_hash="Different", phone="OpaqueHash")], [])
        out, _, _ = fixture([profile(user_id=None, lookup_key="OpaqueHash")], identity=identity)
        self.assertIsNone(out.result)

    def test_email_delivery_redaction_and_exclusive_attachment_delete(self):
        out, _, _ = fixture([{"record_type": "EMAIL_DELIVERY_LOG", "email": "new@example.test"}], text="Remove my personal information.")
        self.assertEqual(out.result.steps[0].operation, "REPORT_EXPOSED_PII")
        self.assertTrue(any(s.operation == "REDACT_RECORD" for s in out.result.steps))
        out, _, _ = fixture([{"record_type": "SUPPORT_ATTACHMENT", "exclusive_subject": True}], text="Remove my personal information.")
        self.assertEqual(out.result.steps[1].operation, "DELETE_RECORD")

    def test_malformed_hold_condition_stays_visible_as_blocker(self):
        out, _, _ = fixture([{"record_type": "LEGAL_HOLD_RECORD", "hold_status": {"unreadable": True}}],
                            text="Remove my personal information.")
        self.assertIsNone(out.result)
        self.assertIn("unsupported_or_unknown_rule_condition", {g.code for g in out.blockers})
        self.assertEqual(out.report.resources[0].observations[0].attributes["hold_status"], {"unreadable": True})

    def test_every_supplied_rule_has_executable_applicability_coverage(self):
        fields = {"SUPPORT_MESSAGE": {"shared_context": True},
                  "SUPPORT_ATTACHMENT": {"exclusive_subject": True},
                  "SECURITY_AUDIT_LOG": {"retention_until": "2030-01-01T00:00:00Z"},
                  "LEGAL_HOLD_RECORD": {"hold_active": True},
                  "BACKUP_ARCHIVE": {"restore_allowed": True},
                  "ACCOUNT_TOMBSTONE": {"account_status": "DELETED", "references_required": True}}
        rules = DatasetReader().rules()
        for rule in rules:
            with self.subTest(rule=rule.rule_id):
                out, _, _ = fixture([{"record_type": rule.data_category, "email": "new@example.test",
                                      **fields.get(rule.data_category, {})}], text="Remove my personal information.")
                record_decisions = [d for d in out.decisions if d.component == "record"]
                self.assertEqual(len(record_decisions), 1)
                self.assertEqual(record_decisions[0].rule, rule)
                self.assertEqual(out.blockers, ())
                self.assertEqual(record_decisions[0].preserve_record, rule.required_action != "DELETE")
                self.assertIsNotNone(out.result)
