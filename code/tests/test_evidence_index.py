"""Collision-aware identity linkage, temporal candidate queries and real ingestion smoke."""
from dataclasses import replace
from datetime import timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from _support import DATASET
from test_evidence_adapters import extract, moment, source
from test_identity import change, snapshot
from ghost_audit.evidence import EvidenceIndex, EvidenceSourceError, ingest_evidence
from ghost_audit.identity import IdentityIndex
from ghost_audit.io import DatasetReader, InputError
from ghost_audit.models import SourceRef
from ghost_audit.parsers import parse_evidence


def record(resource="r", **values):
    return {"resource_id": resource, "observed_at": "2025-01-02T00:00:00Z", **values}


def json_result(raw, source_id="fixture", capture=3):
    return extract(".json", json.dumps(raw), source(source_id, capture))


class EvidenceIndexTests(unittest.TestCase):
    def identity(self):
        return IdentityIndex([snapshot()], [change()])

    def test_current_historical_email_hash_phone_and_stable_user_matches(self):
        identity = self.identity()
        result = json_result({"records": [record("current", email="new@example.test"),
                                          record("historical", email="old@example.test"),
                                          record("hash", email_hash="OpaqueHash"),
                                          record("phone", phone="+1 (555) 0100"),
                                          record("stable", user_id="subject-a")]})
        index = EvidenceIndex([result], identity_index=identity)
        resolution = identity.resolve_request("old@example.test", moment(4))
        matches = index.find_subject_evidence(resolution, moment(4))
        self.assertEqual({m.observation.resource_id for m in matches.matches}, {"current", "historical", "hash", "phone", "stable"})
        self.assertTrue(all(m.reasons and m.reasons[0].observation_source.evidence_id == "fixture" for m in matches.matches))
        self.assertTrue(any(reason.identity_sources for m in matches.matches for reason in m.reasons))

    def test_collision_wrong_subject_decoy_and_anonymized_records_not_merged(self):
        identity = IdentityIndex([snapshot(), snapshot("subject-b", "other@example.test")], [])
        result = json_result({"records": [record("correct", email="new@example.test"),
                                          record("wrong", user_id="subject-b", email="new@example.test"),
                                          record("phone-shared", phone="+1 (555) 0100"),
                                          record("decoy", email="other@example.test"),
                                          record("anonymous", email=None, user_id=None),
                                          record("body", text="Mention new@example.test in prose")]})
        index = EvidenceIndex([result], identity_index=identity)
        linked = index.find_subject_evidence(identity.resolve_request("new@example.test", moment(4)), moment(4))
        self.assertEqual({m.observation.resource_id for m in linked.matches}, {"correct"})
        self.assertEqual(len(index.get_observations("anonymous")), 1)
        self.assertIn("shared_identifier_not_used:phone", linked.issues)

    def test_reused_email_resolution_ambiguity_has_no_subject_matches(self):
        identity = IdentityIndex([snapshot(), snapshot("subject-b", "new@example.test")], [])
        index = EvidenceIndex([json_result(record(email="new@example.test"))], identity_index=identity)
        linked = index.find_subject_evidence(identity.resolve_request("new@example.test", moment(4)), moment(4))
        self.assertIsNone(linked.user_id)
        self.assertFalse(linked.matches)
        self.assertIn("identity_not_unique_at_query_cutoff", linked.issues)

    def test_query_does_not_reuse_future_identity_aliases(self):
        identity = IdentityIndex([snapshot(email="anchor@example.test")], [change(day=6)])
        index = EvidenceIndex([json_result(record(email="old@example.test"))], identity_index=identity)
        resolution = identity.resolve_request("old@example.test", moment(7))
        self.assertFalse(index.find_subject_evidence(resolution, moment(4)).matches)

    def test_future_capture_rejects_embedded_past_event(self):
        result = json_result(record(), capture=6)
        index = EvidenceIndex([result])
        self.assertEqual(len(index.get_observations("r")), 1)
        self.assertEqual(index.get_observations("r", moment(5)), ())
        self.assertEqual(len(index.get_observations("r", moment(6))), 1)

    def test_future_record_snapshot_export_and_nested_payload_times_excluded(self):
        examples = [record(observed_at="2025-01-06T00:00:00Z"),
                    {"captured_at": "2025-01-06T00:00:00Z", "records": [record()]},
                    {"exported_at": "2025-01-06T00:00:00Z", "records": [record()]},
                    record(document={"observed_at": "2025-01-06T00:00:00Z"}),
                    {"captured_at": "2025-01-06T00:00:00Z", "snapshots": [{"captured_at": "2025-01-02T00:00:00Z", "records": [record()]}]}]
        for raw in examples:
            with self.subTest(shape=type(raw).__name__):
                index = EvidenceIndex([json_result(raw)])
                self.assertEqual(index.get_observations("r", moment(5)), ())

    def test_sql_scope_capture_and_log_inner_timestamp_do_not_leak(self):
        sql = '''CREATE TABLE snapshot_scope(origin_system TEXT,captured_at TEXT);
INSERT INTO snapshot_scope VALUES('account_service','2025-01-06T00:00:00Z');
CREATE TABLE profiles(resource_id TEXT,origin_system TEXT,updated_at TEXT);
INSERT INTO profiles VALUES('r','account_service','2025-01-02T00:00:00Z');'''
        index = EvidenceIndex([extract(".sql", sql)])
        self.assertEqual(index.get_observations("r", moment(5)), ())
        line = '2025-01-02T00:00:00Z {"event":"profile_lookup_completed","timestamp":"2025-01-06T00:00:00Z","resource_id":"r"}'
        result = extract(".log", line)
        self.assertEqual(result.observations[0].raw_fields["timestamp"], "2025-01-06T00:00:00Z")
        self.assertEqual(EvidenceIndex([result]).get_observations("r", moment(5)), ())

    def test_unknown_or_malformed_structured_time_not_earlier_state_proof(self):
        for raw in ({"resource_id": "r"}, record(observed_at="invalid")):
            index = EvidenceIndex([json_result(raw)])
            self.assertEqual(index.get_observations("r", moment(4)), ())

    def test_primary_replica_and_conflicting_sources_kept_separate(self):
        left = json_result(record(email="one@example.test"), "file-a")
        right = extract(".sql", "-- Captured at: 2025-01-02T00:00:00Z\nCREATE TABLE profiles_failover_replica(resource_id TEXT,email TEXT); INSERT INTO profiles_failover_replica VALUES('r','other@example.test');", source("file-b"))
        index = EvidenceIndex([right, left])
        observations = index.get_observations("r", moment(4))
        self.assertEqual(len(observations), 2)
        self.assertEqual([o.source.evidence_id for o in observations], ["file-a", "file-b"])
        self.assertEqual(observations[1].topology, "failover_replica")

    def test_trace_started_completed_grounding_and_future_line(self):
        identity = self.identity()
        lines = ['2025-01-02T00:00:00Z level=INFO service=account_service trace_id=tr-a event=profile_lookup_started lookup_key="old@example.test"',
                 '2025-01-04T00:00:00Z level=INFO service=account_service trace_id=tr-a event=profile_lookup_completed resource_id=r http_status=404']
        result = extract(".log", "\n".join(lines))
        index = EvidenceIndex([result], identity_index=identity)
        resolution = identity.resolve_request("old@example.test", moment(5))
        earlier = index.find_subject_evidence(resolution, moment(3))
        self.assertEqual(len(earlier.matches), 1)
        later = index.find_subject_evidence(resolution, moment(5))
        self.assertEqual(len(later.matches), 2)
        completed = next(m for m in later.matches if m.observation.resource_id == "r")
        self.assertEqual(completed.observation.source.locator, "line:2")
        self.assertEqual(completed.reasons[0].observation_source.locator, "line:1")
        self.assertEqual(len(index.get_by_trace("tr-a", moment(5))), 2)

    def test_trace_collision_with_other_identifier_does_not_merge(self):
        identity = IdentityIndex([snapshot(), snapshot("subject-b", "other@example.test")], [])
        result = extract(".log", '2025-01-02T00:00:00Z service=account_service event=profile_lookup_started trace_id=shared lookup_key=new@example.test\n2025-01-02T00:00:00Z service=account_service event=profile_lookup_completed trace_id=shared resource_id=wrong lookup_key=other@example.test')
        index = EvidenceIndex([result], identity_index=identity)
        linked = index.find_subject_evidence(identity.resolve_request("new@example.test", moment(4)), moment(4))
        self.assertEqual(len(linked.matches), 1)
        self.assertNotEqual(linked.matches[0].observation.resource_id, "wrong")
        self.assertIn("trace_identifier_conflict", linked.issues)

    def test_index_order_idempotence_time_index_and_source_scope(self):
        a, b = json_result(record(), "a"), json_result(record(), "b")
        left, right = EvidenceIndex([a, b]), EvidenceIndex([b, a])
        self.assertEqual(left.get_observations("r", moment(4)), right.get_observations("r", moment(4)))
        self.assertEqual(len(left.observations_as_of(moment(4))), 2)
        self.assertEqual(left.get_by_source("a")[0].source.evidence_id, "a")
        with self.assertRaises(ValueError):
            left.get_observations("r", moment(4).replace(tzinfo=None))

    def test_failure_coverage_and_source_error_cannot_be_empty_readback(self):
        failed = extract(".json", "{bad", source("broken"))
        partial = extract(".log", "unrecognized", source("partial"))
        index = EvidenceIndex([failed, partial])
        self.assertEqual(index.coverage_report()["formats"][".json"]["statuses"], {"failed": 1})
        with self.assertRaises(EvidenceSourceError) as caught:
            index.get_by_source("broken")
        self.assertTrue(caught.exception.result.issues)
        self.assertEqual(len(index.get_by_source("partial")), 1)

    def test_duplicate_source_ids_rejected(self):
        result = json_result(record())
        with self.assertRaises(ValueError):
            EvidenceIndex([result, result])

    def test_adding_manifest_entry_missing_duplicate_and_inventory_disagreement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "evidence").mkdir()
            (root / "system_activity.csv").write_text("activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n", encoding="utf-8")
            manifest = root / "evidence_files.csv"
            header = "file_id,file_path,origin,captured_at\n"
            entries = []
            for number in range(2):
                path = root / f"evidence/extra{number}.json"
                path.write_text(json.dumps(record(resource=f"extra-{number}")), encoding="utf-8")
                entries.append(f"extra-{number},evidence/{path.name},fixture,2025-01-03T00:00:00Z\n")
                manifest.write_text(header + "".join(entries), encoding="utf-8")
                index = ingest_evidence(root, identity_index=self.identity())
                self.assertEqual(len(index.results), number + 1)
            typed = DatasetReader(root).manifest()
            with self.assertRaises(ValueError):
                ingest_evidence(root, manifest=[typed[0], typed[0]], identity_index=self.identity())
            with self.assertRaises(ValueError):
                ingest_evidence(root, manifest=typed[:1], identity_index=self.identity())
            manifest.write_text(header + "missing,evidence/missing.json,fixture,2025-01-03T00:00:00Z\n", encoding="utf-8")
            with self.assertRaises(InputError):
                ingest_evidence(root, identity_index=self.identity())


class RealIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in DATASET.rglob("*") if p.is_file()}
        cls.index = ingest_evidence(DATASET)
        cls.preserved = all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in before.items())

    def test_actual_94_sources_accounted_for_without_failed_or_unsupported_files(self):
        report = self.index.coverage_report()
        self.assertEqual(report["manifest_files"], 94)
        self.assertEqual({k: v["files"] for k, v in report["formats"].items()}, {".sql": 24, ".json": 28, ".log": 26, ".png": 11, ".pdf": 4, ".txt": 1})
        self.assertFalse(any(r.status in {"failed", "unsupported", "partially_parsed"} for r in self.index.results))
        self.assertEqual(report["formats"][".png"]["statuses"], {"metadata_only": 11})
        self.assertEqual(report["formats"][".png"]["deferred_visual_files"], 11)
        self.assertTrue(all(r.source.content_sha256 for r in self.index.results))
        self.assertTrue(all(r.source.captured_at_raw.endswith("Z") for r in self.index.results))
        self.assertTrue(all(r.source.manifest_locator.startswith("evidence_files.csv:row:") for r in self.index.results))

    def test_activity_claims_remain_distinct_and_raw_times_preserved(self):
        activities = [o for o in self.index.observations if o.source.source_kind == "ACTIVITY"]
        self.assertEqual(len(activities), 4011)
        self.assertTrue(all(o.kind == "CLAIM" for o in activities))
        self.assertTrue(activities[0].raw_fields["event_time"].endswith("Z"))
        shared = next(o.resource_id for o in activities if any(x.source.source_kind == "FILE" for x in self.index.get_observations(o.resource_id)))
        self.assertTrue(self.index.get_activity(shared))
        self.assertTrue(any(o.source.source_kind == "FILE" for o in self.index.get_observations(shared)))

    def test_source_dataset_is_unchanged(self):
        self.assertTrue(self.preserved)

    def test_phase3_all_requests_reuse_index_and_keep_temporal_provenance(self):
        from unittest.mock import patch
        from ghost_audit.timeline import StateEngine
        from ghost_audit.diagnostics import case_diagnostic, serialize_diagnostic
        reader = DatasetReader()
        engine = StateEngine(self.index)
        cases = reader.requests() + reader.requests(sample=True)
        with patch("ghost_audit.evidence.parse_evidence", side_effect=AssertionError("per-case reparse")):
            reports = engine.reconstruct_cases(cases)
            repeated = engine.reconstruct_cases(cases)
        self.assertEqual(len(reports), 550)
        self.assertTrue(all(p.user_id for p in reports))
        self.assertEqual(serialize_diagnostic([case_diagnostic(p) for p in reports]),
                         serialize_diagnostic([case_diagnostic(p) for p in repeated]))
        for p in reports:
            for r in p.resources:
                for d in r.dimensions:
                    for f in d.supporting:
                        self.assertLessEqual(f.observed_at, p.audit_at)
                        self.assertLessEqual(f.source.available_at, p.audit_at)
                        self.assertTrue(f.source.content_sha256)
                        self.assertTrue(f.source.locator)
        self.assertTrue(any(p.comparisons for p in reports))
        self.assertTrue(any(r.recreation for p in reports for r in p.resources))

    def test_phase3_cli_outside_repository_with_real_local_ocr(self):
        import subprocess
        import sys
        from _support import ROOT
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(ROOT / "code/main.py"), "state-diagnostics", "--sample"],
                                    cwd=folder, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["aggregate"]["cases"], 32)
        self.assertEqual(report["ingestion"]["manifest_files"], 94)
        self.assertEqual(len({r["file_id"] for r in report["visual_inventory"]}), 15)
        self.assertTrue(all(r["needs_review"] for r in report["visual_inventory"]))
