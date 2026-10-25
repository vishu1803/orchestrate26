"""Independent factual state fixtures, never golden-answer or policy lookups."""
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from _support import ROOT
from test_evidence_adapters import extract, moment, source
from test_evidence_index import json_result, record
from test_identity import snapshot, change
from ghost_audit.diagnostics import aggregate_diagnostics, case_diagnostic, serialize_diagnostic
from ghost_audit.documents import LocalDocumentExtractor, candidates
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.identity import IdentityIndex
from ghost_audit.models import Request
from ghost_audit.normalization import make_observation
from ghost_audit.state_facts import normalize_facts
from ghost_audit.timeline import StateEngine, reconstruct


def observation(identifier="read", day=2, capture=3, kind="READBACK", **attrs):
    raw = {"system_id": "account_service", "resource_id": "resource-a",
           "observed_at": moment(day).isoformat(), **attrs}
    return make_observation(raw, replace(source(identifier, capture), locator="/record"), kind=kind)[0]


def case(email="new@example.test", day=5, case_id="fixture-case"):
    return Request(case_id, email, moment(1), "COMPLETE", moment(2), moment(day), "synthetic text")


def engine(records, identity=None, documents=None):
    identity = identity or IdentityIndex([snapshot()], [])
    return StateEngine(EvidenceIndex(records, identity_index=identity), document_extractor=documents)


class StateTests(unittest.TestCase):
    def state(self, *observations, cutoff=5):
        return reconstruct(observations, moment(cutoff))[0]

    def test_exact_cutoff_and_event_after(self):
        included = observation(day=5, capture=5, result="FOUND")
        later = observation("later", day=6, capture=5, result="NOT_FOUND")
        state = self.state(included, later)
        self.assertEqual(state.record_existence, "PRESENT")
        self.assertTrue(any(t.reason.endswith("after_cutoff") for t in state.get("record_existence").rejected))
        created_later = observation("future-created", result="FOUND", created_at=moment(6).isoformat())
        self.assertEqual(self.state(created_later).record_existence, "UNKNOWN")

    def test_late_capture_even_when_event_is_old(self):
        state = self.state(observation(day=2, capture=6, result="FOUND"))
        self.assertEqual(state.record_existence, "UNKNOWN")
        self.assertIn("captured_after_cutoff", state.gaps)

    def test_delete_success_claim_cannot_override_presence(self):
        present = observation(result="FOUND")
        delete = observation("delete", day=4, kind="CLAIM", event="DELETE_RECORD", reported_result="SUCCESS")
        self.assertEqual(self.state(present, delete).record_existence, "PRESENT")
        self.assertEqual(self.state(delete).record_existence, "UNKNOWN")

    def test_primary_absent_and_failover_present_are_distinct(self):
        primary = replace(observation("primary", result="NOT_FOUND"), topology="primary")
        replica = replace(observation("replica", result="FOUND"), topology="failover_replica")
        states = reconstruct([primary, replica], moment(5))
        self.assertEqual({s.scope.topology: s.record_existence for s in states}, {"primary": "ABSENT", "failover_replica": "PRESENT"})

    def test_exact_negative_versus_partial_empty_snapshot(self):
        self.assertEqual(self.state(observation(status_code=404, profile=None)).record_existence, "ABSENT")
        empty = observation(kind="SNAPSHOT", empty_collection=True, records=[])
        self.assertEqual(self.state(empty).record_existence, "UNKNOWN")
        self.assertIn("partial_empty_scope_not_absence", self.state(empty).gaps)

    def test_observed_reappearance_and_sync_success_are_separate(self):
        absent = observation("a", result="NOT_FOUND")
        sync = observation("sync", day=3, kind="CLAIM", event="SYNC", reported_result="SUCCESS")
        positive = observation("b", day=4, result="FOUND")
        self.assertFalse(self.state(absent, sync).recreation)
        state = self.state(absent, sync, positive)
        self.assertEqual(state.record_existence, "PRESENT")
        self.assertEqual(state.recreation[0].kind, "OBSERVED_REAPPEARANCE")
        self.assertEqual(state.recreation[0].before[0].source.evidence_id, "a")
        self.assertEqual(state.recreation[0].after[0].source.evidence_id, "b")

    def test_connector_timeline_uses_observed_flag_not_delivery_status(self):
        active = observation("a", enabled=True, last_delivery_status="FAILED")
        disabled = observation("b", day=4, enabled=False, last_delivery_status="SUCCESS")
        self.assertEqual(self.state(active, disabled).data_flow, "DISABLED")
        self.assertEqual(self.state(active).data_flow, "ACTIVE")

    def test_archive_existence_is_independent_of_restore_permission(self):
        blocked = observation(kind="SNAPSHOT", restore_allowed=False, archive_key="opaque-archive")
        state = self.state(blocked)
        self.assertEqual((state.record_existence, state.restore_access), ("PRESENT", "BLOCKED"))
        self.assertEqual(self.state(observation(restore_allowed=True)).restore_access, "ACTIVE")
        self.assertEqual(self.state(observation(result="BLOCKED", record_type="BACKUP_ARCHIVE")).record_existence, "UNKNOWN")

    def test_tombstone_stable_reference_and_direct_fields_separate(self):
        stable = observation(kind="SNAPSHOT", record_type="ACCOUNT_TOMBSTONE", user_id="subject-a", email=None, name="", phone=None, email_hash=None)
        state = self.state(stable)
        self.assertEqual(state.get("stable_reference:user_id").value, "PRESENT")
        self.assertEqual(state.get("direct_identifier:email").value, "CLEARED")
        self.assertEqual(state.identifiability, "UNKNOWN")
        exposed = replace(stable, attributes={**stable.attributes, "email": "new@example.test"})
        self.assertEqual(self.state(exposed).identifiability, "IDENTIFIABLE")

    def test_security_and_legal_existence_has_no_policy_decision(self):
        for category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
            state = self.state(observation(kind="SNAPSHOT", record_type=category, subject_reference="user_demo", retention_until="2030-01-01"))
            self.assertEqual(state.record_existence, "PRESENT")
            self.assertEqual(state.data_category, category)
            self.assertFalse(hasattr(state, "compliant"))

    def test_historical_alias_hash_case_and_collision(self):
        identity = IdentityIndex([snapshot(), replace(snapshot("other", "someone@example.test"), email_hash="DifferentHash")], [change()])
        e = engine([json_result({"records": [record("old", system_id="account_service", email=" OLD@EXAMPLE.TEST "),
                                             record("hash", system_id="account_service", email_hash="OpaqueHash"),
                                             record("wrong", system_id="account_service", user_id="other", email="new@example.test") ]})], identity)
        report = e.reconstruct_case(case("old@example.test"))
        self.assertEqual({r.resource_id for r in report.resources}, {"old", "hash"})
        self.assertTrue(any(m.identity_sources for r in report.resources for m in r.match_reasons))

    def test_same_time_conflict_retains_both_citations(self):
        state = self.state(observation("a", result="FOUND"), observation("b", result="NOT_FOUND"))
        self.assertEqual(state.record_existence, "UNKNOWN")
        self.assertEqual(state.get("record_existence").epistemic, "CONFLICT")
        self.assertEqual({f.source.evidence_id for f in state.get("record_existence").supporting}, {"a", "b"})

    def test_decoy_and_started_trace_does_not_prove_existence(self):
        lines = '2025-01-02T00:00:00Z service=account_service trace_id=t event=profile_lookup_started resource_id=resource-a lookup_key=new@example.test\n2025-01-02T00:00:00Z service=account_service trace_id=t event=profile_lookup_completed resource_id=wrong lookup_key=someone@example.test rows=1'
        e = engine([extract(".log", lines)])
        report = e.reconstruct_case(case())
        self.assertEqual({r.resource_id for r in report.resources}, {"resource-a"})
        self.assertEqual(report.resources[0].record_existence, "UNKNOWN")

    def test_sql_and_nested_json_locators_and_scope_survive(self):
        sql = "-- Captured at: 2025-01-02T00:00:00Z\nCREATE TABLE customer_profiles_failover_replica(resource_id TEXT,user_id TEXT,email TEXT); INSERT INTO customer_profiles_failover_replica VALUES('resource-a','subject-a','new@example.test');"
        nested = {"service_exports": {"account_service": {"profile_lookups": [record("resource-a", query={"email": "new@example.test"}, status_code=404)]}}}
        e = engine([extract(".sql", sql, source("sql")), json_result(nested, "json")])
        report = e.reconstruct_case(case())
        self.assertTrue(any(r.scope.table == "customer_profiles_failover_replica" and r.record_existence == "PRESENT" for r in report.resources))
        locators = {f.source.locator for r in report.resources for d in r.dimensions for f in d.supporting}
        self.assertIn("/service_exports/account_service/profile_lookups/0", locators)
        self.assertIn("table:customer_profiles_failover_replica/row:1", locators)
        self.assertTrue(report.comparisons)

    def test_pdf_page_and_image_only_gap_without_model(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"Event reference audit_record_9 subject reference user_demo\f\f", stderr=b"")
        with patch("ghost_audit.adapters.visual_adapter.shutil.which", return_value="pdftotext"), patch("ghost_audit.adapters.visual_adapter.subprocess.run", return_value=completed):
            result = extract(".pdf", b"%PDF-1.4 fixture")
        docs = LocalDocumentExtractor(enable_ocr=False).extract(result)
        self.assertEqual([d.source.locator for d in docs], ["page:1", "page:2"])
        self.assertEqual([d.coverage for d in docs], ["text_extracted", "review_required"])
        self.assertTrue(all(d.needs_review for d in docs))
        self.assertEqual(docs[0].candidates[0].field, "resource_id")
        self.assertEqual(docs[1].confidence, None)

    def test_malformed_missing_clocks_and_unsupported_states_unknown(self):
        for attrs in ({"result": "SUCCESS"}, {"result": ["FOUND"]}, {"enabled": "yes"}, {"status_code": True}):
            self.assertEqual(self.state(observation(**attrs)).record_existence, "UNKNOWN")
        missing = replace(observation(result="FOUND"), observed_at=None, timestamps=())
        self.assertEqual(self.state(missing).record_existence, "UNKNOWN")
        unavailable = replace(observation(result="FOUND"), source=replace(source(), available_at=None, locator="/record"))
        self.assertEqual(self.state(unavailable).record_existence, "UNKNOWN")
        failed = extract(".json", "{broken")
        self.assertEqual(failed.status, "failed")

    def test_repeated_batch_is_identical_and_does_not_reparse(self):
        e = engine([json_result(record("r", system_id="account_service", user_id="subject-a", result="FOUND"))])
        with patch("ghost_audit.evidence.parse_evidence", side_effect=AssertionError("reparse")), patch.object(e.identity_index, "__init__", side_effect=AssertionError("rebuild")):
            first = e.reconstruct_cases([case(case_id="b"), case(case_id="a")])
            second = e.reconstruct_cases([case(case_id="a"), case(case_id="b")])
        self.assertEqual(serialize_diagnostic([case_diagnostic(r) for r in first]), serialize_diagnostic([case_diagnostic(r) for r in second]))
        self.assertEqual(len(e.index.results), 1)

    def test_missing_field_is_not_redaction_and_query_is_not_stored_pii(self):
        query = observation(status_code=404, query={"email": "new@example.test"})
        self.assertEqual(self.state(query).get("direct_identifier:email").value, "UNKNOWN")
        marker = self.state(observation(result="REDACTED"))
        self.assertEqual(marker.get("direct_identifier:email").value, "UNKNOWN")
        self.assertIn("redaction_marker_without_field_proof", marker.gaps)

    def test_anonymized_marker_with_pii_is_conflict(self):
        state = self.state(observation(result="ANONYMIZED", email="new@example.test"))
        self.assertEqual(state.get("identifiability").epistemic, "CONFLICT")

    def test_latest_absence_does_not_expose_old_field_as_current(self):
        state = self.state(observation("a", result="FOUND", email="new@example.test"), observation("b", day=4, result="NOT_FOUND"))
        self.assertEqual(state.get("direct_identifier:email").value, "UNKNOWN")
        self.assertEqual(state.record_existence, "ABSENT")

    def test_report_is_immutable_and_raw_values_retained(self):
        state = self.state(observation(result="FOUND", email="new@example.test"))
        self.assertEqual(state.get("direct_identifier:email").supporting[0].raw_value, "new@example.test")
        with self.assertRaises(FrozenInstanceError):
            state.as_of = moment(6)

    def test_future_scope_cannot_create_resource_scope(self):
        old = json_result(record("r", system_id="account_service", user_id="subject-a", result="FOUND"), "old")
        future = json_result(record("r", system_id="account_service", user_id="subject-a", result="NOT_FOUND", region="future-region"), "later", capture=6)
        report = engine([old, future]).reconstruct_case(case())
        self.assertEqual(len(report.resources), 1)
        self.assertTrue(any(t.reason == "captured_after_cutoff" for t in report.explanations))

    def test_pdf_gap_selectively_matches_subject_not_all_cases(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"Subject user_demo Event reference audit_record_9\f", stderr=b"")
        with patch("ghost_audit.adapters.visual_adapter.shutil.which", return_value="pdftotext"), patch("ghost_audit.adapters.visual_adapter.subprocess.run", return_value=completed):
            pdf = extract(".pdf", b"%PDF-1.4 fixture")
        e = engine([pdf], IdentityIndex([snapshot("user_demo"), snapshot("user_other", "other@example.test")], []))
        yes = e.reconstruct_case(case())
        no = e.reconstruct_case(case("other@example.test"))
        self.assertTrue(any("visual" in g.code for g in yes.gaps))
        self.assertFalse(any("visual" in g.code for g in no.gaps))

    def test_ocr_identifier_repairs_are_not_guessed(self):
        self.assertFalse(any(i.field == "user_id" for i in candidates("Customer key user 17", "image:full")))

    def test_observed_collection_schemas_cover_classes_without_inventing_absent_class(self):
        e = engine([json_result({"collection": "customer_profiles", "captured_at": moment(2).isoformat(), "records": [record("r", user_id="subject-a")]})])
        diag = aggregate_diagnostics(e, e.reconstruct_cases([case()]))
        self.assertIn("CACHE_ENTRY", diag["aggregate"]["classes_without_observed_schema"])
        self.assertEqual(diag["aggregate"]["linked_record_classes"], {"USER_PROFILE": 1})

    def test_sql_json_flags_and_field_pointers(self):
        sql = '''-- Captured at: 2025-01-02T00:00:00Z
CREATE TABLE customer_data_read_replica(resource_id TEXT,origin_system TEXT,collection_name TEXT,record_json TEXT);
INSERT INTO customer_data_read_replica VALUES('resource-a','backup_service','backup_catalog','{"restore_allowed":false,"email":"new@example.test"}');'''
        state = reconstruct(extract(".sql", sql).observations, moment(5))[0]
        self.assertEqual(state.restore_access, "BLOCKED")
        self.assertTrue(state.get("direct_identifier:email").supporting[0].locator.endswith("/record_json#/email"))

    def test_json_root_region_survives_into_physical_scope(self):
        e = engine([json_result({"region": "region-a", "service_exports": {"account_service": {"profile_lookups": [record("r", query={"email": "new@example.test"}, status_code=404)]}}})])
        self.assertEqual(e.reconstruct_case(case()).resources[0].scope.region, "region-a")

    def test_restore_decision_and_candidate_flags_are_not_archive_absence(self):
        denied = self.state(observation(event="restore_authorization_completed", decision="deny"))
        self.assertEqual((denied.record_existence, denied.restore_access), ("UNKNOWN", "BLOCKED"))
        allowed = self.state(observation(event="restore_candidate_evaluated", eligible="true", deletion_block="false"))
        self.assertEqual((allowed.record_existence, allowed.restore_access), ("UNKNOWN", "ACTIVE"))

    def test_claim_identity_link_can_locate_but_never_prove_state(self):
        link = observation(kind="CLAIM", system_id="data_catalog", target_system="account_service", event_type="LINK_RESOURCE_IDENTITY",
                           identity_link={"resource_id": "resource-a", "user_id": "subject-a", "email": "new@example.test"})
        from ghost_audit.models import ExtractionResult, ExtractionStatus
        result = ExtractionResult(link.source, ".log", ExtractionStatus.PARSED, (link,), (), {})
        report = engine([result]).reconstruct_case(case())
        self.assertEqual(report.resources[0].system_id, "account_service")
        self.assertEqual(report.resources[0].record_existence, "UNKNOWN")

    def test_untimed_identity_link_is_visible_as_unknown(self):
        e = engine([json_result({"system_id": "account_service", "resource_id": "r", "email": "new@example.test"})])
        report = e.reconstruct_case(case())
        self.assertEqual(report.resources[0].record_existence, "UNKNOWN")
        self.assertTrue(any(g.code == "missing_or_invalid_observation_time" for g in report.gaps))

    def test_typed_readback_pii_fields_prove_presence_but_query_does_not(self):
        present = self.state(observation(event="support_ticket_read_completed", requester_email="new@example.test"))
        self.assertEqual(present.record_existence, "PRESENT")
        scanned = self.state(observation(event="attachment_pii_scan", matched_value="new@example.test"))
        self.assertEqual((scanned.record_existence, scanned.identifiability), ("PRESENT", "IDENTIFIABLE"))

    def test_ocr_missing_backend_is_explicit_and_not_state(self):
        from ghost_audit.models import ExtractionResult, ExtractionStatus
        ref = replace(source(), locator="image:full", file_path="evidence/missing.png")
        result = ExtractionResult(ref, ".png", ExtractionStatus.METADATA_ONLY, (), (), {})
        docs = LocalDocumentExtractor(enable_ocr=False).extract(result)
        self.assertTrue(docs[0].needs_review)
        self.assertEqual(docs[0].coverage, "review_required")
        self.assertFalse(docs[0].candidates)

    def test_reported_claim_changes_do_not_change_selected_facts(self):
        a = observation("proof", result="FOUND")
        b = observation("claim", day=4, kind="CLAIM", reported_result="SUCCESS")
        c = replace(b, attributes={**b.attributes, "reported_result": "FAILED"})
        self.assertEqual(self.state(a, b).get("record_existence").supporting,
                         self.state(a, c).get("record_existence").supporting)

    def test_cross_subject_resource_collision_does_not_attribute_anonymous_negative(self):
        identity = IdentityIndex([snapshot(), snapshot("subject-b", "other@example.test", email_hash="OtherHash", phone="other-phone")], [])
        records = {"records": [record("r", system_id="account_service", user_id="subject-a", result="FOUND"),
                               record("r", system_id="account_service", user_id="subject-b", result="FOUND"),
                               record("r", system_id="account_service", result="NOT_FOUND", observed_at=moment(4).isoformat())]}
        report = engine([json_result(records)], identity).reconstruct_case(case())
        self.assertEqual(report.resources[0].record_existence, "PRESENT")
        self.assertTrue(any(g.code == "ambiguous_resource_ownership" for g in report.gaps))
        self.assertTrue(any(t.reason == "resource_only_link_ambiguous" for t in report.explanations))

    def test_mixed_subject_anchor_is_rejected_before_resource_expansion(self):
        identity = IdentityIndex([snapshot(), snapshot("subject-b", "other@example.test", email_hash="OtherHash", phone="other-phone")], [])
        records = {"records": [record("r", system_id="account_service", user_id="subject-a", email="other@example.test", result="FOUND"),
                               record("r", system_id="account_service", result="NOT_FOUND")]}
        report = engine([json_result(records)], identity).reconstruct_case(case())
        self.assertFalse(report.resources)
        self.assertTrue(any(g.code == "conflicting_identity_anchor" for g in report.gaps))

    def test_index_cache_and_archive_storage_scopes_remain_distinct(self):
        a = observation("a", result="FOUND", index="index-a")
        b = observation("b", result="NOT_FOUND", index="index-b")
        states = reconstruct([a, b], moment(5))
        self.assertEqual(len(states), 2)
        self.assertEqual({s.scope.data_store for s in states}, {"index-a", "index-b"})

    def test_unknown_boolean_and_zero_scan_do_not_claim_identifiable(self):
        state = self.state(observation(event="analytics_identity_scan", matched_value="not-an-identifier", direct_identifiers=0, enabled="yes", restore_allowed="NO"))
        self.assertEqual(state.identifiability, "UNKNOWN")
        self.assertEqual((state.data_flow, state.restore_access), ("UNKNOWN", "UNKNOWN"))

    def test_export_of_history_preserves_distinct_event_times(self):
        history = {"exported_at": moment(5).isoformat(), "records": [
            {"resource_id": "r", "system": "account_service", "record_type": "USER_PROFILE", "recorded_at": moment(2).isoformat(), "result": "FOUND"},
            {"resource_id": "r", "system": "account_service", "record_type": "USER_PROFILE", "recorded_at": moment(4).isoformat(), "result": "NOT_FOUND"}]}
        state = reconstruct(json_result(history, capture=5).observations, moment(5))[0]
        self.assertEqual(state.record_existence, "ABSENT")
        self.assertEqual(state.get("record_existence").supporting[0].observed_at, moment(4))
        self.assertNotEqual(state.get("record_existence").epistemic, "CONFLICT")

    def test_record_class_does_not_depend_on_claim_or_source_id_order(self):
        claim = observation("a-claim", kind="CLAIM")
        proof = observation("z-proof", record_type="ACCOUNT_TOMBSTONE", result="FOUND")
        self.assertEqual(self.state(claim, proof).data_category, "ACCOUNT_TOMBSTONE")
        contradictory = observation("other-proof", record_type="USER_PROFILE", result="FOUND")
        state = self.state(proof, contradictory)
        self.assertEqual(state.data_category, "")
        self.assertIn("conflicting_record_classes", state.gaps)
