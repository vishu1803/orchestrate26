"""Phase 0 structure, preservation, CLI, logging and packaging checks."""
import importlib
import pkgutil
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _support import CODE, DATASET, ROOT, rows
from ghost_audit.io import CSV_COLUMNS
from ghost_audit.models import OUTPUT_COLUMNS, OPERATION_CONTRACT, Phase, State, Status
from scripts.package_submission import package_plan


class ContractTests(unittest.TestCase):
    def test_all_csv_schemas(self):
        self.assertEqual(len(CSV_COLUMNS), 9)
        for name in CSV_COLUMNS:
            with self.subTest(name=name):
                self.assertIsInstance(rows(name), list)

    def test_request_count_and_unique_ids(self):
        requests = rows("deletion_requests.csv")
        self.assertEqual(len(requests), 518)
        self.assertEqual(len({r["case_id"] for r in requests}), 518)

    def test_output_header_and_blank_template(self):
        self.assertEqual(OUTPUT_COLUMNS, ("case_id", "deletion_status", "steps_json"))
        self.assertEqual(rows("output.csv"), [])

    def test_status_phase_state_enums(self):
        self.assertEqual({s.value for s in Status}, {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
        self.assertEqual([p.value for p in Phase], ["FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual({s.value for s in State}, {"PRESENT", "ACTIVE", "DISABLED", "BLOCKED", "ABSENT", "REDACTED", "ANONYMIZED"})

    def test_operation_contract_matches_organizer_table(self):
        source = (ROOT / "problem_statement.md").read_text(encoding="utf-8")
        triples = re.findall(r"\|\s*`(FINDING|REMEDIATION|VERIFICATION)`\s*\|\s*`([A-Z_]+)`\s*\|\s*`([A-Z_]+)`", source)
        self.assertEqual(len(triples), 15)
        self.assertEqual([(op, phase, state) for phase, op, state in triples],
                         [(op, phase.value, state.value) for op, (phase, state) in OPERATION_CONTRACT.items()])

    def test_required_scaffold_files(self):
        groups = {
            "": ["main.py", "requirements.txt", "README.md"],
            "ghost_audit": ["__init__.py", "models.py", "io.py", "intent.py", "identity.py", "evidence.py", "parsers.py", "timeline.py", "policy.py", "planner.py", "output.py", "ai_fallback.py", "usage.py"],
            "evaluation": ["main.py", "metrics.py", "custom_cases.py", "evaluation_report.md", "usage_report.md"],
            "tests": [f"test_{n}.py" for n in ("contract", "identity", "evidence", "timeline", "policy", "planner", "samples", "custom_cases")],
            "prompts": ["intent_classifier.md", "evidence_extractor.md"],
            "docs": ["architecture.md", "requirements_matrix.md", "evidence_inventory.md", "assumptions_and_risks.md", "decision_log.md", "progress.md"],
            "scripts": ["validate_output.py", "package_submission.py"],
        }
        for folder, names in groups.items():
            for name in names:
                with self.subTest(path=f"{folder}/{name}"):
                    self.assertTrue((CODE / folder / name).is_file())
                    self.assertTrue((CODE / folder / name).read_text(encoding="utf-8").strip())

    def test_all_application_modules_import(self):
        for package in ("ghost_audit", "evaluation", "scripts"):
            imported = importlib.import_module(package)
            for module in pkgutil.iter_modules(imported.__path__):
                with self.subTest(module=module.name):
                    importlib.import_module(f"{package}.{module.name}")

    def test_entrypoint_help(self):
        for path in ("main.py", "evaluation/main.py", "scripts/validate_output.py", "scripts/package_submission.py"):
            with self.subTest(path=path):
                result = subprocess.run([sys.executable, str(CODE / path), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)
                self.assertIn("Phase 0", result.stdout)

    def test_unimplemented_entrypoints_do_not_succeed(self):
        for path in ("main.py", "evaluation/main.py", "scripts/validate_output.py"):
            result = subprocess.run([sys.executable, str(CODE / path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Phase 0", result.stderr)

    def test_original_sources_and_data_have_no_git_diff(self):
        result = subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", "AGENTS.md", "CLAUDE.md", "README.md", "problem_statement.md", "agent_trace_instructions.md", "dataset"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((ROOT / "docs/phase0_repository_inspection.md").is_file())

    def test_no_prediction_or_submission_created(self):
        # Historical Phase0 absence gate evolves under explicit Phase6 authority.
        # Created artifacts must instead satisfy independent structural checks.
        if (ROOT / "output.csv").exists():
            from scripts.validate_output import inspect_csv
            from ghost_audit.io import DatasetReader
            reader=DatasetReader()
            times={x.file_id:x.captured_at for x in reader.manifest()}
            times.update({x.activity_id:x.event_time for x in reader.activity()})
            times.update({x.audit_id:x.event_time for x in reader.history()})
            self.assertEqual(len(inspect_csv(ROOT / "output.csv",[r.case_id for r in reader.requests()],times,reader.requests())),518)
        self.assertFalse((ROOT / "agent-trace.zip").exists())

    def test_report_templates_pending(self):
        report = (CODE / "evaluation/evaluation_report.md").read_text(encoding="utf-8")
        usage = (CODE / "evaluation/usage_report.md").read_text(encoding="utf-8")
        self.assertTrue("**PENDING" in report or "**NOT CERTIFIED**" in report)
        self.assertTrue("**PENDING" in usage or "Final full 518-request production run" in usage)
        for term in ("Case-level", "Step precision", "Field-level", "Exact sequence", "Participant-created", "Failures"):
            self.assertIn(term, report)
        for term in ("Provider", "Exact model", "Calls", "Input tokens", "Output tokens", "Average", "cost per request", "Overall"):
            self.assertIn(term, usage)

    def test_code_hygiene_and_environment_template(self):
        forbidden = {".csv", ".tsv", ".json", ".jsonl", ".sql", ".log", ".png", ".pdf", ".zip", ".key", ".pem"}
        for path in CODE.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                self.assertNotIn(path.suffix.lower(), forbidden, str(path))
                self.assertNotEqual(path.name, ".env")
                self.assertFalse(re.search(r"sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----", path.read_text(encoding="utf-8")))
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            self.assertRegex(line, r"^[A-Z][A-Z0-9_]*$")

    def test_log_entry_structure(self):
        raw = (ROOT / "log.txt").read_bytes()
        self.assertNotIn(b"\r\n", raw)
        entries = re.findall(r"(?ms)^## \[([^\n]+)\] ([^\n]+)\n(.*?)(?=^## \[|\Z)", raw.decode("utf-8"))
        self.assertTrue(entries)
        for timestamp, title, body in entries:
            self.assertLessEqual(len(title), 80)
            if title == "SESSION START":
                context = body
            else:
                for section in ("User Prompt (verbatim, secrets redacted):", "Agent Response Summary:", "Actions:", "Context:"):
                    self.assertIn(section, body)
                context = body.rsplit("\nContext:\n", 1)[1]
            for key in ("tool", "model"):
                values = re.findall(rf"(?m)^{key}=(.+)$", context)
                self.assertEqual(len(values), 1)
                self.assertNotIn(values[0].lower(), {"unknown", "ai", "codex", "gpt", "gpt-6", "<exact_runtime_model_name>"})
                self.assertNotIn("<", values[0])

    def test_gitignore_preserves_transcript(self):
        result = subprocess.run(["git", "check-ignore", "log.txt"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        for name in (".env", "output.csv", "code.zip", "code/__pycache__/cache.pyc"):
            result = subprocess.run(["git", "check-ignore", name], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, name)

    def test_package_plan_paths_and_exclusions(self):
        included, excluded = package_plan(ROOT)
        targets = dict(included)
        self.assertEqual(targets["code/README.md"], "README.md")
        self.assertEqual(targets["code/evaluation/evaluation_report.md"], "evaluation/evaluation_report.md")
        self.assertEqual(targets["code/evaluation/usage_report.md"], "evaluation/usage_report.md")
        self.assertEqual(len(set(targets.values())), len(included))
        self.assertIn("log.txt", excluded)
        self.assertTrue(all(not source.startswith("dataset/") for source, _ in included))

    def test_package_excludes_unsafe_fixture_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            names = ["code/main.py", "code/README.md", "dataset/input.csv", "code/.env", "code/secret.key", "code/nested.zip", "code/__pycache__/x.py", "log.txt"]
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic fixture", encoding="utf-8")
            included, excluded = package_plan(root)
            self.assertEqual({s for s, _ in included}, {"code/main.py", "code/README.md"})
            self.assertEqual(len(excluded), 6)

    def test_package_dry_run_writes_nothing(self):
        before = {p.relative_to(ROOT) for p in ROOT.rglob("*.zip")}
        result = subprocess.run([sys.executable, str(CODE / "scripts/package_submission.py"), "--dry-run"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DRY RUN ONLY", result.stdout)
        self.assertIn("EXCLUDE dataset/deletion_requests.csv", result.stdout)
        self.assertEqual(before, {p.relative_to(ROOT) for p in ROOT.rglob("*.zip")})
