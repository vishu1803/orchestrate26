"""Independent structured/visual fixtures, source fidelity and extraction failures."""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

from _support import ROOT
from ghost_audit.models import SourceRef
from ghost_audit.parsers import parse_evidence


def moment(day):
    return datetime(2025, 1, day, tzinfo=timezone.utc)


def source(source_id="fixture", day=3):
    return SourceRef(source_id, moment(day), "", "evidence/fixture", "synthetic-origin")


def extract(suffix, content, source_ref=None):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / ("fixture" + suffix)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return parse_evidence(path, source_ref or source())


def png_bytes():
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))


class AdapterTests(unittest.TestCase):
    def test_nested_json_pointer_null_false_empty_and_raw(self):
        raw = {"exported_at": "2025-01-03T00:00:00Z", "snapshots": [{"captured_at": "2025-01-02T00:00:00Z", "collection": "contacts", "data_store": "regional-store", "records": [{"resource_id": "r", "email": None, "enabled": False, "restore_allowed": True, "empty": "", "document": {"phone": None}}]}]}
        result = extract(".json", json.dumps(raw))
        self.assertEqual(result.status, "parsed")
        observation = result.observations[0]
        self.assertEqual(observation.source.locator, "/snapshots/0/records/0")
        self.assertEqual(observation.collection, "contacts")
        self.assertEqual(observation.context["data_store"], "regional-store")
        self.assertIsNone(observation.raw_fields["email"])
        self.assertIs(observation.raw_fields["enabled"], False)
        self.assertIs(observation.raw_fields["restore_allowed"], True)
        self.assertEqual(observation.raw_fields["empty"], "")
        self.assertNotIn("missing", observation.raw_fields)
        self.assertEqual(observation.observed_at, moment(2))
        self.assertEqual(len(observation.source.content_sha256), 64)
        with self.assertRaises(TypeError):
            observation.raw_fields["document"]["phone"] = "changed"

    def test_empty_scoped_snapshot_is_an_observation_not_global_absence(self):
        result = extract(".json", '{"captured_at":"2025-01-02T00:00:00Z","collection":"profiles","records":[]}')
        self.assertEqual(len(result.observations), 1)
        self.assertTrue(result.observations[0].attributes["empty_collection"])
        self.assertEqual(result.observations[0].raw_fields, ())
        self.assertIsNone(result.observations[0].resource_id)
        self.assertEqual(result.observations[0].source.locator, "/records")

    def test_service_negative_readback_retains_query_and_profile(self):
        raw = {"service_exports": {"account_service": {"profile_lookups": [{"resource_id": "r", "observed_at": "2025-01-02T00:00:00Z", "query": {"email": "old@example.test"}, "status_code": 404, "profile": None}]}}}
        result = extract(".json", json.dumps(raw))
        observation = result.observations[0]
        self.assertEqual(observation.kind, "READBACK")
        self.assertEqual(observation.system_id, "account_service")
        self.assertEqual(observation.attributes["status_code"], 404)
        self.assertIsNone(observation.raw_fields["profile"])
        self.assertEqual(observation.identifiers[0].locator, "/service_exports/account_service/profile_lookups/0/query/email")

    def test_json_pointer_escaping_and_generic_nested_resource(self):
        result = extract(".json", '{"a/b~c":{"resource_id":"r","email":"one@example.test"}}')
        self.assertEqual(result.observations[0].source.locator, "/a~1b~0c")

    def test_nested_profile_explicit_resource_and_clock_are_not_lost(self):
        result = extract(".json", '{"service_exports":{"accounts":{"profile_lookups":[{"status_code":200,"profile":{"resource_id":"nested-r","email":"one@example.test","updated_at":"2025-01-02T00:00:00Z"}}]}}}')
        observation = result.observations[0]
        self.assertEqual(observation.resource_id, "nested-r")
        self.assertNotIn("resource_id", observation.raw_fields)
        self.assertEqual(observation.observed_at, moment(2))

    def test_malformed_duplicate_keys_and_nonstandard_json_fail_explicitly(self):
        for raw in ('{"x":', '{"resource_id":"one","resource_id":"two"}', '{"x":NaN}'):
            result = extract(".json", raw)
            self.assertEqual(result.status, "failed")
            self.assertTrue(result.issues)

    def test_invalid_record_time_is_partial_not_silently_dropped(self):
        result = extract(".json", '{"resource_id":"r","observed_at":"invalid"}')
        self.assertEqual(result.status, "partially_parsed")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].raw_fields["observed_at"], "invalid")

    def test_direct_sql_primary_replica_empty_and_row_provenance(self):
        sql = '''-- Captured at: 2025-01-02T00:00:00Z
BEGIN TRANSACTION;
CREATE TABLE profiles_primary(resource_id TEXT PRIMARY KEY, email TEXT);
CREATE TABLE profiles_failover_replica(resource_id TEXT PRIMARY KEY,email TEXT);
INSERT INTO profiles_failover_replica VALUES('r','owner@example.test');
COMMIT;'''
        result = extract(".sql", sql)
        self.assertEqual(result.status, "parsed", result.issues)
        by_topology = {o.topology: o for o in result.observations}
        self.assertTrue(by_topology["primary"].attributes["empty_table"])
        self.assertEqual(dict(by_topology["primary"].raw_fields), {})
        self.assertEqual(by_topology["failover_replica"].resource_id, "r")
        self.assertEqual(by_topology["failover_replica"].source.locator, "table:profiles_failover_replica/row:1")
        self.assertEqual(by_topology["failover_replica"].context["primary_key"]["resource_id"], "r")

    def test_sql_json_blob_preserves_raw_string_and_separate_parsed_document(self):
        payload = '{"email":"old@example.test","enabled":false,"phone":null}'
        sql = "CREATE TABLE customer_data_read_replica(resource_id TEXT,record_json TEXT); INSERT INTO customer_data_read_replica VALUES('r','" + payload + "');"
        result = extract(".sql", sql)
        self.assertEqual(result.status, "parsed", result.issues)
        observation = result.observations[0]
        self.assertEqual(observation.raw_fields["record_json"], payload)
        self.assertNotIn("document", observation.raw_fields)
        self.assertIs(observation.attributes["document"]["enabled"], False)
        self.assertTrue(observation.identifiers[0].locator.endswith("/record_json#/email"))

    def test_malformed_sql_json_is_partial_with_retained_row(self):
        result = extract(".sql", "CREATE TABLE t(resource_id TEXT,record_json TEXT); INSERT INTO t VALUES('r','bad json');")
        self.assertEqual(result.status, "partially_parsed")
        self.assertEqual(result.observations[0].raw_fields["record_json"], "bad json")
        self.assertIn("invalid_record_json", {i.code for i in result.issues})

    def test_sql_safe_dump_pragmas_indexes_and_json_check(self):
        sql = '''PRAGMA foreign_keys=ON; CREATE TABLE t(resource_id TEXT PRIMARY KEY, record_json TEXT CHECK(json_valid(record_json))); INSERT INTO t VALUES('r','{}'); CREATE INDEX idx_t ON t(resource_id);'''
        self.assertEqual(extract(".sql", sql).status, "parsed")

    def test_sql_denies_attach_extension_writes_triggers_and_arbitrary_pragmas(self):
        with tempfile.TemporaryDirectory() as folder:
            external = Path(folder) / "must_not_exist.db"
            for sql in (f"ATTACH DATABASE '{external.as_posix()}' AS host;", "PRAGMA journal_mode=WAL;",
                        "CREATE TABLE t(x); INSERT INTO t VALUES(load_extension('blocked'));",
                        "CREATE TABLE t(x); CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT 1; END;",
                        "CREATE TABLE t(x); UPDATE t SET x=1;", "CREATE TABLE t AS SELECT 1;"):
                self.assertEqual(extract(".sql", sql).status, "failed")
            self.assertFalse(external.exists())

    def test_log_wrappers_and_readback_vs_claim(self):
        lines = [
            '2025-01-02T00:00:00Z {"service":"account_service","event":"profile_lookup_completed","trace_id":"tr-a","resource_id":"r","http_status":404}',
            '2025-01-02T00:00:00Z level=INFO service=account_service trace_id=tr-a event=profile_lookup_started lookup_key="old@example.test"',
            '2025-01-02T00:00:00Z [INFO] [account_service] [tr-a] profile_lookup_completed: resource_id="r" rows="0"',
            '2025-01-02T00:00:00Z | INFO | account_service | tr-a | profile_lookup_completed | resource_id="r" rows="0"',
            '2025-01-02T00:00:00Z <15>1 host account_service tr-a - - event="profile_lookup_completed" resource_id="r" rows="0"',
            '2025-01-02T00:00:00Z requestId=tr-a level=INFO function=account_service message="event=profile_lookup_completed resource_id=r rows=0"',
            '2025-01-02T00:00:00Z level=INFO service=account_service event=delete_completed reported_result=SUCCESS resource_id=r',
        ]
        result = extract(".log", "\r\n".join(lines))
        self.assertEqual(result.status, "parsed", result.issues)
        self.assertEqual(len(result.observations), 7)
        self.assertEqual(result.observations[0].kind, "READBACK")
        self.assertEqual(result.observations[1].kind, "CLAIM")
        self.assertEqual(result.observations[-1].kind, "CLAIM")
        self.assertEqual(result.observations[2].raw_fields["rows"], "0")
        self.assertEqual(result.observations[2].attributes["rows"], 0)
        for number, observation in enumerate(result.observations, 1):
            self.assertEqual(observation.source.locator, f"line:{number}")
            self.assertEqual(observation.raw_fields["raw_line"], lines[number - 1])

    def test_malformed_and_unrelated_log_lines_retained(self):
        result = extract(".log", 'prose with unrelated@example.test\n2025-01-02T00:00:00Z {broken\n\n')
        self.assertEqual(result.status, "partially_parsed")
        self.assertEqual(len(result.observations), 3)
        self.assertEqual(len(result.issues), 2)
        self.assertTrue(all(not o.identifiers for o in result.observations))

    def test_txt_handover_and_no_direct_identifier(self):
        result = extract(".txt", 'Handover\n- 2025-01-02T00:00:00Z | account_service | r | USER_PROFILE | NOT_FOUND | no direct identifier\n')
        self.assertEqual(result.status, "parsed")
        self.assertEqual(result.observations[1].resource_id, "r")
        self.assertEqual(result.observations[1].identifiers, ())
        self.assertEqual(result.observations[0].kind, "RAW")

    def test_pdf_page_text_and_image_only_fallback(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"Selectable text\f\f", stderr=b"")
        with patch("ghost_audit.adapters.visual_adapter.shutil.which", return_value="local-pdftotext"), patch("ghost_audit.adapters.visual_adapter.subprocess.run", return_value=completed):
            result = extract(".pdf", b"%PDF-1.4 fixture")
        self.assertEqual(result.status, "partially_parsed")
        self.assertEqual(result.metadata["pages"], 2)
        self.assertEqual([o.source.locator for o in result.observations], ["page:1", "page:2"])
        self.assertEqual(result.issues[0].code, "visual_extraction_required")
        self.assertEqual(result.observations[0].raw_fields["text"], "Selectable text")

    def test_png_validated_metadata_is_not_semantic_extraction(self):
        result = extract(".png", png_bytes())
        self.assertEqual(result.status, "metadata_only", result.issues)
        self.assertEqual((result.metadata["width"], result.metadata["height"]), (1, 1))
        self.assertEqual(result.issues[0].code, "visual_extraction_deferred")
        self.assertFalse(result.observations[0].identifiers)

    def test_corrupt_images_pdf_and_missing_dependencies_fail_explicitly(self):
        self.assertEqual(extract(".png", b"broken").status, "failed")
        self.assertEqual(extract(".pdf", b"broken").status, "failed")
        with patch("ghost_audit.adapters.visual_adapter.decode_png", side_effect=ModuleNotFoundError("decoder_missing")):
            result = extract(".png", png_bytes())
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.issues)

    def test_unsupported_format_accounted_for(self):
        self.assertEqual(extract(".unknown", "raw").status, "unsupported")
