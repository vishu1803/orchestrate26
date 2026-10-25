"""Sample labels are used only for independent wire-contract checks here."""
import ast
import json
import re
import unittest
from _support import CODE, rows
from ghost_audit.output import validate_steps_contract


class SampleStructureTests(unittest.TestCase):
    def test_sample_case_ids_match(self):
        requests, labels = rows("sample_deletion_requests.csv"), rows("sample_output.csv")
        self.assertEqual(len(requests), 32)
        self.assertEqual(len(labels), 32)
        self.assertEqual(len({r["case_id"] for r in labels}), 32)
        self.assertEqual({r["case_id"] for r in requests}, {r["case_id"] for r in labels})

    def test_all_public_labels_follow_wire_contract(self):
        for row in rows("sample_output.csv"):
            with self.subTest(case_id=row["case_id"]):
                validate_steps_contract(row["deletion_status"], json.loads(row["steps_json"]))

    def test_inference_has_no_sample_labels_or_evaluation_imports(self):
        for path in (CODE / "ghost_audit").glob("*.py"):
            source = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\bcase_\d+\b", source))
            if path.name != "io.py":  # schema constant only, no prediction lookup
                self.assertNotIn("sample_output.csv", source)
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Import):
                    names = [n.name for n in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                self.assertFalse(any(n.startswith("evaluation") for n in names))

    def test_sample_prediction_accuracy(self):
        from pathlib import Path
        from unittest.mock import patch
        from ghost_audit.io import DatasetReader
        from ghost_audit.pipeline import AuditPipeline
        from ghost_audit.output import result_row
        from evaluation.metrics import score_predictions
        reader = DatasetReader()
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path.name == "sample_output.csv":
                raise AssertionError("production tried to read public labels")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", guarded):
            pipeline = AuditPipeline.from_dataset(reader.root)
            outcomes = pipeline.audit_cases(reader.requests(sample=True))
            repeated = pipeline.audit_cases(reader.requests(sample=True))
        reviewed = [row for row in pipeline.document_ledger if row["state_promoted"] and not row["needs_review"]]
        self.assertTrue(reviewed)
        self.assertTrue(all(not d.needs_review for d in pipeline.state_engine.documents
                            if d.source.evidence_id in {row["file_id"] for row in reviewed}))
        predictions = [result_row(o.result) for o in outcomes if o.result]
        self.assertEqual(predictions, [result_row(o.result) for o in repeated if o.result])
        metrics = score_predictions(predictions, rows("sample_output.csv"))
        self.assertEqual(metrics["cases"], 32)
        self.assertEqual(metrics["status"]["total"], 32)
        self.assertEqual(metrics["steps"]["true_positive"] + metrics["steps"]["false_negative"], metrics["steps"]["expected"])
        self.assertGreaterEqual(metrics["status"]["correct"], 0)
        self.assertLessEqual(metrics["status"]["correct"], 32)
