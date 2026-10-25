"""Typed ingestion with independent CSV fixtures, malformed inputs and path tests."""
import csv
from datetime import timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from _support import CODE, DATASET
from ghost_audit.io import (CSV_COLUMNS, DatasetReader, InputError, load_activity,
                            load_history, load_identities, load_manifest, load_requests,
                            read_contract_csv, utc_timestamp, validate_manifest_path)


class IngestionTests(unittest.TestCase):
    def write_csv(self, folder, name, records, *, header=None):
        path = Path(folder) / name
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\r\n")
            writer.writerow(header or CSV_COLUMNS[name])
            writer.writerows(records)
        return path

    def test_all_typed_readers_real_input_counts(self):
        reader = DatasetReader()
        self.assertEqual(len(reader.requests()), 518)
        self.assertEqual(len(reader.requests(sample=True)), 32)
        self.assertEqual(len(reader.identities()), 850)
        self.assertEqual(len(reader.history()), 306)
        self.assertEqual(len(reader.activity()), 4011)
        self.assertEqual(len(reader.rules()), 15)
        self.assertEqual(len(reader.manifest()), 94)

    def test_unicode_commas_multiline_crlf_and_lineage(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "deletion_requests.csv", [["synthetic", "unicode@example.test", "2025-01-01T05:30:00+05:30", "COMPLETE", "2025-01-01T01:00:00Z", "2025-01-02T00:00:00Z", "\u0938\u093e\u0930\u093e \u0921\u0947\u091f\u093e,\nplease retain punctuation"]])
            request = load_requests(path)[0]
            self.assertIn(",\n", request.request_text)
            self.assertEqual(request.requested_at.hour, 0)
            self.assertEqual(request.requested_at.tzinfo, timezone.utc)
            self.assertEqual(request.lineage.row_number, 3)
            self.assertEqual(request.lineage.source_id, "synthetic")

    def test_nullable_identity_values_preserve_raw_and_unicode(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_identities.csv", [["synthetic", "Zo\u00eb, \u674e", "  user@example.test  ", "", "", "2025-01-01T00:00:00Z"]])
            identity = load_identities(path)[0]
            self.assertEqual(identity.name, "Zo\u00eb, \u674e")
            self.assertEqual(identity.email, "  user@example.test  ")
            self.assertEqual(identity.phone, "")
            self.assertEqual(identity.email_hash, "")

    def test_null_like_text_is_not_silently_coerced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_identities.csv", [["synthetic", "Null", "", "NULL", "null", "2025-01-01T00:00:00Z"]])
            identity = load_identities(path)[0]
            self.assertEqual((identity.name, identity.phone, identity.email_hash), ("Null", "NULL", "null"))

    def test_legal_empty_history_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_audit_log.csv", [["synthetic", "subject", "2025-01-01T00:00:00Z", "email", "", "new@example.test"]])
            self.assertEqual(load_history(path)[0].old_value, "")

    def test_activity_allows_nullable_targets_and_details(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "system_activity.csv", [["synthetic", "2025-01-01T00:00:00Z", "EVENT", "source", "", "", "", ""]])
            self.assertEqual(load_activity(path)[0].target_system, "")

    def test_missing_column_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_identities.csv", [], header=["user_id", "email"])
            with self.assertRaises(InputError) as caught:
                load_identities(path)
            self.assertEqual(caught.exception.row, 1)
            self.assertEqual(caught.exception.field, "header")
            self.assertIn(str(path), str(caught.exception))

    def test_wrong_known_file_for_typed_reader_has_actionable_error(self):
        with self.assertRaises(InputError) as caught:
            load_requests(DATASET / "user_identities.csv")
        self.assertEqual(caught.exception.code, "wrong_input_contract_for_reader")

    def test_empty_required_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_identities.csv", [["", "", "", "", "", "2025-01-01T00:00:00Z"]])
            with self.assertRaises(InputError) as caught:
                load_identities(path)
            self.assertEqual(caught.exception.code, "invalid_required_id")

    def test_non_utf8_data_is_an_actionable_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "user_identities.csv"
            path.write_bytes(b"\xff\xfe\x00\x00")
            with self.assertRaises(InputError) as caught:
                load_identities(path)
            self.assertEqual(caught.exception.code, "UnicodeDecodeError")
            self.assertEqual(caught.exception.row, 1)

    def test_invalid_timestamps_and_naive_date_rejected(self):
        for value in ("2025-02-30T00:00:00Z", "2025-01-01", "2025-01-01T00:00:00", "not a date", "2025-01-01T24:00:00Z"):
            with self.subTest(value=value), self.assertRaises(InputError) as caught:
                utc_timestamp(value, "synthetic.csv", 9, "event_time")
            self.assertEqual(caught.exception.row, 9)
            self.assertEqual(caught.exception.field, "event_time")

    def test_loader_timestamp_error_has_row_without_pii_value(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_identities.csv", [["synthetic", "Private fixture name", "private@example.test", "", "", "invalid"]])
            with self.assertRaises(InputError) as caught:
                load_identities(path)
            self.assertEqual((caught.exception.row, caught.exception.field), (2, "updated_at"))
            self.assertNotIn("Private fixture name", str(caught.exception))
            self.assertNotIn("private@example.test", str(caught.exception))

    def test_duplicate_required_ids_rejected_for_every_contract(self):
        for name, columns in CSV_COLUMNS.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                path = self.write_csv(folder, name, [["same"] * len(columns), ["same"] * len(columns)])
                with self.assertRaises(InputError) as caught:
                    read_contract_csv(path)
                self.assertEqual(caught.exception.code, "duplicate_required_id")
                self.assertEqual(caught.exception.row, 3)

    def test_duplicate_emails_are_not_rejected_as_duplicate_users(self):
        with tempfile.TemporaryDirectory() as folder:
            base = ["name", "shared@example.test", "", "", "2025-01-01T00:00:00Z"]
            path = self.write_csv(folder, "user_identities.csv", [["subject-a", *base], ["subject-b", *base]])
            self.assertEqual(len(load_identities(path)), 2)

    def test_corrupt_csv_rows_rejected(self):
        for suffix in ('x,too,few\n', 'x,"unterminated', 'x,a,b,c,d,e,extra\n', 'x,a\0,b,c,d,e\n'):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "user_identities.csv"
                path.write_text(",".join(CSV_COLUMNS[path.name]) + "\n" + suffix, encoding="utf-8")
                with self.assertRaises(InputError):
                    load_identities(path)

    def test_unknown_field_variant_rejected_instead_of_guessed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "user_audit_log.csv", [["synthetic", "subject", "2025-01-01T00:00:00Z", "email_address", "a", "b"]])
            with self.assertRaises(InputError) as caught:
                load_history(path)
            self.assertEqual(caught.exception.field, "field_name")

    def test_paths_work_outside_repo_and_windows_relative_style(self):
        self.assertEqual(DatasetReader(r".\dataset").root, DATASET.resolve())
        self.assertEqual(DatasetReader(DATASET.resolve()).root, DATASET.resolve())
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(CODE / "main.py"), "identity-coverage", "--dataset-dir", str(DATASET)], cwd=folder, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["evaluation_requests"]["requests"], 518)
        self.assertEqual(report["sample_requests"]["requests"], 32)
        self.assertNotIn("deletion_status", result.stdout)

    def test_missing_dataset_and_missing_file_actionable(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(InputError):
                DatasetReader(Path(folder) / "missing")
            with self.assertRaises(InputError) as caught:
                load_identities(Path(folder) / "user_identities.csv")
            self.assertEqual(caught.exception.row, 1)

    def test_manifest_path_no_double_dataset_and_no_binary_reads(self):
        original = Path.open

        def guarded(path, *args, **kwargs):
            if "evidence" in path.parts or path.name == "sample_output.csv":
                raise AssertionError("Ingestion opened an evidence asset or evaluation labels")
            return original(path, *args, **kwargs)

        with patch.object(Path, "open", guarded):
            reader = DatasetReader()
            reader.identities(); reader.history(); reader.requests(); reader.requests(sample=True)
            manifest = reader.manifest()
        self.assertTrue(all(p.resolved_path.is_relative_to(DATASET / "evidence") for p in manifest))

    def test_manifest_error_has_location(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_csv(folder, "evidence_files.csv", [["synthetic", "../outside.txt", "source", "2025-01-01T00:00:00Z"]])
            with self.assertRaises(InputError) as caught:
                load_manifest(path)
            self.assertEqual((caught.exception.row, caught.exception.field), (2, "file_path"))

    def test_resolved_symlink_escape_is_rejected_without_symlink_privileges(self):
        original = Path.resolve
        escaped = DATASET.parent / "AGENTS.md"
        candidate = DATASET / "evidence" / "link.txt"

        def resolve(path, *args, **kwargs):
            return escaped if path == candidate else original(path, *args, **kwargs)

        with patch.object(Path, "resolve", resolve), self.assertRaises(ValueError):
            validate_manifest_path(DATASET, "evidence/link.txt")
