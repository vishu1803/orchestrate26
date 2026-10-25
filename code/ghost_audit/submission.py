"""Conservative submission serialization; uncertainty never creates evidence."""
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

from .io import DatasetReader
from .models import AuditResult, OUTPUT_COLUMNS, Status
from .output import result_row, validate_case
from .pipeline import AuditPipeline, coverage_diagnostics
from .planner import closure_inventory


def submission_row(outcome):
    """A missing strict verdict cannot certify completeness or authorize actions.

    Phase 6 explicitly permits conservative INCOMPLETE/[] with uncertainty in a
    separate report. Existing grounded plans and NOT_APPLICABLE are preserved.
    """
    result = outcome.result or AuditResult(outcome.case_id, Status.INCOMPLETE, ())
    return result_row(result, allow_partial=True)


def write_submission(rows, path, expected_ids):
    rows = sorted(rows, key=lambda r: r["case_id"])
    if [r["case_id"] for r in rows] != sorted(expected_ids):
        raise ValueError("submission_case_coverage")
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def generate(dataset_dir, output, report):
    start = time.perf_counter()
    reader = DatasetReader(dataset_dir)
    pipeline = AuditPipeline.from_dataset(reader.root)
    requests = reader.requests()
    outcomes = pipeline.audit_cases(requests)
    for request, outcome in zip(sorted(requests, key=lambda r:r.case_id), outcomes):
        if outcome.result is not None:
            validate_case(outcome, request, pipeline.index)
    rows = [submission_row(o) for o in outcomes]
    write_submission(rows, output, [r.case_id for r in requests])
    source_root = Path(__file__).resolve().parents[1]
    source_hash = hashlib.sha256(b"".join(p.relative_to(source_root).as_posix().encode()+p.read_bytes()
                                for p in sorted(source_root.rglob("*.py")))).hexdigest()
    metadata = {"utc": datetime.now(timezone.utc).isoformat(),
                "command_argv": [sys.executable, *sys.argv], "code_sha256": source_hash,
                "output_sha256": hashlib.sha256(Path(output).read_bytes()).hexdigest(),
                "output_bytes": Path(output).stat().st_size, "rows": len(rows),
                "status_counts": dict(sorted(Counter(r["deletion_status"] for r in rows).items())),
                "strict_investigation": coverage_diagnostics(outcomes),
                "resource_verification_inventory": [{"case_id":o.case_id,"resources":closure_inventory(o)} for o in outcomes],
                "conservative_fallback_cases": [o.case_id for o in outcomes if o.result is None],
                "empty_incomplete_cases": [r["case_id"] for r in rows if r["deletion_status"]=="INCOMPLETE" and r["steps_json"]=="[]"],
                "document_extraction": pipeline.state_engine.extraction_measurement,
                "model_usage": {"provider": None, "model": None, "calls": 0, "input_tokens": 0,
                                "output_tokens": 0, "total_tokens": 0, "estimated_provider_cost_usd": 0},
                "input_sha256": {p.relative_to(reader.root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sorted([*(reader.root/n for n in ("deletion_requests.csv", "deletion_rules.csv",
                                     "evidence_files.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv")),
                                     *(p for p in (reader.root/"evidence").rglob("*") if p.is_file())])},
                "elapsed_seconds": time.perf_counter()-start}
    body = "# Full production submission run\n\nStructural validity does not prove semantic completeness. Conservative INCOMPLETE is not an evidence-backed finding.\n\n```json\n"+json.dumps(metadata,indent=2,sort_keys=True)+"\n```\n"
    Path(report).write_text(body,encoding="utf-8",newline="\n")
    return metadata
