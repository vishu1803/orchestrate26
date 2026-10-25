"""Phase 6 submission and diagnostics; Phase 0 source contracts preserved."""
import argparse
import json
import time
import tracemalloc

from ghost_audit.evidence import ingest_evidence
from ghost_audit.identity import IdentityIndex, coverage_summary
from ghost_audit.io import DatasetReader, InputError
from ghost_audit.timeline import StateEngine
from ghost_audit.diagnostics import aggregate_diagnostics
from ghost_audit.pipeline import AuditPipeline, coverage_diagnostics
from ghost_audit.state_facts import RESOURCE_CLASSES


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    coverage = commands.add_parser("identity-coverage", help="Profile identity resolution only, without predictions or PII")
    coverage.add_argument("--dataset-dir", help="Dataset directory; relative paths resolve from repository root")
    evidence = commands.add_parser("evidence-smoke", help="Ingest all manifest assets and report coverage/gaps without verdicts")
    evidence.add_argument("--dataset-dir", help="Dataset directory; relative paths resolve from repository root")
    evidence.add_argument("--measure", action="store_true", help="Measure wall time and peak Python-traced allocations (excludes native/child memory)")
    state = commands.add_parser("state-diagnostics", help="Reconstruct factual resource scopes for all requests; no compliance decisions")
    state.add_argument("--dataset-dir", help="Dataset directory; relative paths resolve from repository root")
    state.add_argument("--case-id", action="append", default=[], help="Include detailed diagnostics for this case; repeatable")
    state.add_argument("--sample", action="store_true", help="Use sample requests only; never sample labels")
    state.add_argument("--measure", action="store_true", help="Measure runtime and Python allocations; excludes native/child memory")
    audit = commands.add_parser("audit-diagnostics", help="Run production decisions and report blockers/counts only; never writes predictions")
    audit.add_argument("--dataset-dir")
    audit.add_argument("--sample", action="store_true")
    audit.add_argument("--measure", action="store_true")
    run = commands.add_parser("run", help="Generate all 518 conservative submission rows and a separate uncertainty report")
    run.add_argument("--dataset-dir")
    run.add_argument("--output", help="Output CSV; default repository-root output.csv")
    run.add_argument("--report", help="Run/uncertainty Markdown; default code/evaluation/full_run_report.md")
    args = parser.parse_args()
    if args.command == "run":
        from pathlib import Path
        from ghost_audit.submission import generate
        root = Path(__file__).resolve().parents[1]
        report = generate(args.dataset_dir, args.output or root / "output.csv",
                          args.report or Path(__file__).resolve().parent / "evaluation/full_run_report.md")
        print(json.dumps({k:report[k] for k in ("rows", "status_counts", "output_sha256", "elapsed_seconds")},sort_keys=True,indent=2))
        return
    if args.command not in {"identity-coverage", "evidence-smoke", "state-diagnostics", "audit-diagnostics"}:
        parser.error("Phase 0 source contracts preserved; select an explicit diagnostic command. No predictions were written.")
    try:
        reader = DatasetReader(args.dataset_dir)
        if args.command == "identity-coverage":
            index = IdentityIndex(reader.identities(), reader.history())
            report = {"kind": "IDENTITY_COVERAGE_ONLY", "evaluation_requests": coverage_summary(index, reader.requests()),
                      "sample_requests": coverage_summary(index, reader.requests(sample=True))}
        else:
            if args.measure:
                tracemalloc.start()
            start = time.perf_counter()
            if args.command == "audit-diagnostics":
                pipeline = AuditPipeline.from_dataset(reader.root)
                outcomes = pipeline.audit_cases(reader.requests(sample=args.sample))
                report = {"kind": "DECISION_DIAGNOSTICS_NOT_SUBMISSION", **coverage_diagnostics(outcomes),
                          "document_ledger": pipeline.document_ledger,
                          "uncategorized_structured_classes": sorted(set(RESOURCE_CLASSES) - set(pipeline.state_engine.class_counts))}
                if args.measure:
                    report["measurement"] = {"elapsed_seconds": time.perf_counter() - start,
                                             "peak_traced_python_bytes": tracemalloc.get_traced_memory()[1]}
                    tracemalloc.stop()
                print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
                return
            evidence_index = ingest_evidence(reader.root)
            if args.command == "state-diagnostics":
                cases = reader.requests(sample=args.sample)
                if set(args.case_id) - {c.case_id for c in cases}:
                    raise ValueError("unknown_selected_case_id")
                engine = StateEngine(evidence_index, reader.root)
                reports = engine.reconstruct_cases(cases)
                selected = args.case_id or [c.case_id for c in sorted(cases, key=lambda c: c.case_id)[:3]]
                report = aggregate_diagnostics(engine, reports, selected)
            else:
                report = {"kind": "EVIDENCE_INGESTION_ONLY", **evidence_index.coverage_report()}
            if args.measure:
                report["measurement"] = {"elapsed_seconds": time.perf_counter() - start,
                                         "peak_traced_python_bytes": tracemalloc.get_traced_memory()[1]}
                if args.command == "state-diagnostics":
                    report["measurement"]["document_extraction"] = engine.extraction_measurement
                tracemalloc.stop()
    except (InputError, ValueError) as exc:
        parser.exit(2, f"Input validation failed (bad_rows >= 1; fail-fast): {exc}\n")
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
    if args.command in {"evidence-smoke", "state-diagnostics"} and any(r.status.value in {"failed", "unsupported"} for r in evidence_index.results):
        parser.exit(1, "Evidence ingestion has explicit failures; see coverage diagnostics.\n")


if __name__ == "__main__":
    main()
