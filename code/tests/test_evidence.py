"""Manifest and format smoke tests, not parser accuracy tests."""
from collections import Counter
import json
import sqlite3
import unittest
from _support import DATASET, rows
from ghost_audit.io import validate_manifest_path
from ghost_audit.parsers import FORMAT_CANDIDATES


class EvidenceStructureTests(unittest.TestCase):
    def test_manifest_coverage_and_ids(self):
        manifest = rows("evidence_files.csv")
        self.assertEqual(len(manifest), 94)
        self.assertEqual(len({r["file_id"] for r in manifest}), 94)
        listed = {validate_manifest_path(DATASET, r["file_path"]) for r in manifest}
        actual = {p.resolve() for p in (DATASET / "evidence").rglob("*") if p.is_file()}
        self.assertEqual(listed, actual)

    def test_manifest_rejects_unsafe_or_missing_paths(self):
        for path in ("../AGENTS.md", "/etc/passwd", "C:/Windows/file", "evidence/../../AGENTS.md", "evidence/missing.txt", "deletion_requests.csv", "evidence\\missing.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_manifest_path(DATASET, path)

    def test_format_counts_and_dispatch_contract(self):
        counts = Counter(p.suffix for p in (DATASET / "evidence").rglob("*") if p.is_file())
        self.assertEqual(counts, {".json": 28, ".log": 26, ".sql": 24, ".png": 11, ".pdf": 4, ".txt": 1})
        self.assertEqual(set(FORMAT_CANDIDATES), set(counts))

    def test_json_parses_and_observed_layouts(self):
        layouts = Counter()
        for path in (DATASET / "evidence").rglob("*.json"):
            obj = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsInstance(obj, dict)
            layouts[tuple(obj)] += 1
        self.assertEqual(sorted(layouts.values()), [2, 3, 11, 12])

    def test_sql_exports_integrity(self):
        for path in (DATASET / "evidence").rglob("*.sql"):
            with self.subTest(file=path.name):
                connection = sqlite3.connect(":memory:")
                try:
                    connection.executescript(path.read_text(encoding="utf-8"))
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                finally:
                    connection.close()

    def test_multiformat_extraction_and_decoys(self):
        from test_evidence_adapters import extract
        result = extract(".json", '{"resource_id":"synthetic","email":null}')
        self.assertEqual(result.status, "parsed")
        self.assertEqual(result.observations[0].source.locator, "")
        self.assertFalse(result.observations[0].identifiers)
