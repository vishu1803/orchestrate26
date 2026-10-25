"""Phase 4 sample evaluation; preserves the Phase 0 independent-label boundary."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.custom_cases import run_independent_cases
from evaluation.metrics import categorize_mismatches, score_predictions
from evaluation.localization import write_ledgers
from ghost_audit.io import DatasetReader, read_contract_csv
from ghost_audit.output import result_row
from ghost_audit.pipeline import AuditPipeline, coverage_diagnostics
from ghost_audit.planner import closure_inventory
from ghost_audit.state_facts import RESOURCE_CLASSES


def evaluate_samples(pipeline, reader, submission=False):
    # Production inference finishes before the evaluator loads expected outputs.
    outcomes = pipeline.audit_cases(reader.requests(sample=True))
    if submission:
        from ghost_audit.submission import submission_row
        predictions = [submission_row(o) for o in outcomes]
    else:
        predictions = [result_row(o.result) for o in outcomes if o.result is not None]
    labels = read_contract_csv(reader.root / "sample_output.csv")
    metrics = score_predictions(predictions, labels)
    metrics["error_categories"] = categorize_mismatches(metrics, outcomes)
    return outcomes, metrics


def _percent(value):
    return "N/A" if value is None else f"{100 * value:.4f}%"


def write_reports(directory, reader, pipeline, outcomes, metrics, custom, measurement, diagnostics=None, submission_mode=False):
    directory.mkdir(parents=True, exist_ok=True)
    code_root = Path(__file__).resolve().parents[1]
    code_hash = hashlib.sha256(b"".join(p.relative_to(code_root).as_posix().encode() + p.read_bytes() for p in sorted(code_root.rglob("*.py")))).hexdigest()
    hashes = {name: hashlib.sha256((reader.root / name).read_bytes()).hexdigest() for name in ("sample_deletion_requests.csv", "sample_output.csv", "deletion_rules.csv", "evidence_files.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv")}
    coverage = coverage_diagnostics(outcomes)
    sample_facts = [f for o in outcomes if o.report for r in o.report.resources for d in r.dimensions for f in d.supporting]
    metadata = {"utc": datetime.now(timezone.utc).isoformat(), "command_argv": [sys.executable, *sys.argv],
                "prediction_mode": "conservative_submission" if submission_mode else "strict_investigation",
                "code_sha256": code_hash, "input_sha256": hashes, "measurement": measurement,
                "evidence_content_sha256": hashlib.sha256("".join(r.source.evidence_id + r.source.content_sha256 for r in pipeline.index.results).encode()).hexdigest(),
                "sample_coverage": coverage, "full_diagnostic_coverage": diagnostics,
                "verification_closure": [{"case_id":o.case_id,"inventory":closure_inventory(o)} for o in outcomes],
                "document_extraction": pipeline.state_engine.extraction_measurement,
                "ingestion": pipeline.index.coverage_report(),
                "structured_category_counts": dict(sorted(pipeline.state_engine.class_counts.items())),
                "uncategorized_structured_classes": sorted(set(RESOURCE_CLASSES) - set(pipeline.state_engine.class_counts)),
                "sample_selected_fact_supports": len(sample_facts),
                "sample_unique_selected_observations": len({(f.source.evidence_id,f.source.locator) for f in sample_facts})}
    status, sequence, steps = metrics["status"], metrics["sequence"], metrics["steps"]
    text = f'''# Evaluation report - Phase 7 measured public-sample run

Whole-dataset semantic completeness: **NOT CERTIFIED**. These are public-sample
results; hidden-dataset accuracy is unknown. No expected labels
enter production inference; the evaluator loads them after production outcomes.
Strict investigative blockers remain separate from conservative submission rows.
Prediction mode: {metadata['prediction_mode']}. All 32 labels remain in the denominator.

| Metric | Actual result |
| --- | --- |
| Case-level deletion-status accuracy | {status['correct']}/{status['total']} = {_percent(status['accuracy'])} |
| Exact sequence accuracy | {sequence['correct']}/{sequence['total']} = {_percent(sequence['accuracy'])} |
| Exact row accuracy | {metrics['exact_row']['correct']}/{metrics['exact_row']['total']} = {_percent(metrics['exact_row']['accuracy'])} |
| Step precision | {steps['true_positive']}/{steps['predicted']} = {_percent(steps['precision'])} |
| Step recall | {steps['true_positive']}/{steps['expected']} = {_percent(steps['recall'])} |
| Step F1 | {_percent(steps['f1'])} |
| Order-aware per-index exact step match | {metrics['order_aware_steps']['correct']}/{metrics['order_aware_steps']['total']} = {_percent(metrics['order_aware_steps']['accuracy'])} |
| Field-level overall accuracy | {metrics['field_overall']['correct']}/{metrics['field_overall']['total']} = {_percent(metrics['field_overall']['accuracy'])} |
| Emitted / blocked without status | {metrics['emitted_cases']} / {len(metrics['missing_cases'])} |
| Sample cases with unresolved evidence/condition blockers | {coverage['cases_with_blockers']}/32 |

| Field-level field | Correct / aligned union | Accuracy |
| --- | ---: | ---: |
'''
    for field, value in metrics["fields"].items():
        text += f"| {field} | {value['correct']}/{value['total']} | {_percent(value['accuracy'])} |\n"
    text += f'''
Step precision/recall use per-case multiset tuples on all six non-number fields,
including evidence_id. Duplicates count. Field alignment groups by
(phase, system_id, resource_id, operation), then pairs duplicate occurrences in
sequence order. Missing/extra aligned steps count incorrect for every field.
Per-index matching compares all seven fields at each index up to the longer array.
Whole-array equality ignores JSON key order/whitespace, preserves array order,
and missing case rows fail. Zero denominators are N/A, never invented perfect scores.
Metrics implementation: {metrics['algorithm']}.

Public label status counts: {json.dumps(metrics['label_status_counts'], sort_keys=True)}.
If NOT_APPLICABLE has no public examples, its coverage comes from independently
authored synthetic negatives below, not invented public labels.

## Failures and measured mismatch categories

Counts are cases per symptom and may overlap. Policy/verification/citation
differences are measured against public serialization. Decoy, alias, physical-scope
and cutoff error causes are not guessed from an omitted canonical step; zero means
not independently attributed here. Blocker diagnostics remain separate from statuses.

| Category | Mismatched cases |
| --- | ---: |
'''
    text += ''.join(f"| {key} | {value} |\n" for key, value in sorted(metrics["error_categories"].items(), key=lambda kv: (-kv[1], kv[0])))
    text += '''
Complete per-case structured missing/extra steps and observed blockers are in
[sample_mismatch_report.md](sample_mismatch_report.md). No acceptance test requires
a fabricated perfect public score. Remaining weaknesses block submission readiness;
no case-ID branches or expected answers enter inference. The controlled experiment
history is in phase5_experiments.md and docs/phase5_implementation.md.

## Participant-created independent executable cases

These are newly implemented synthetic fixtures in custom_cases.py, using the
production pipeline and actual supplied rule grammars. They contain no public
case data. Each validates expected status, the independent operation set,
provenance, required retained records and absence of blockers.

| Custom case | Expected | Actual | Passed |
| --- | --- | --- | --- |
'''
    text += ''.join(f"| {c['name']} | {c['expected_status']} | {c['actual_status']} | {c['passed']} |\n" for c in custom)
    text += '''
The tombstone fixture exposes only a prohibited hash and preserves a legal-held
record. The flow/restore fixture disables a connector and blocks restore before
profile cleanup, retains the archive, and verifies all final obligations. The
non-deletion fixture requests export and authorizes no deletion investigation.
Additional unit mutations cover all 15 operation/state pairs and multilingual
positives/negatives, unknown-only states, aliases/collisions and source cutoffs.
'''
    text += "\n## Step recall by phase, operation and system\n\nMatching uses the same per-case six-field multiset accounting as overall scores.\n\n"
    for dimension, groups in metrics["grouped_steps"].items():
        text += f"\n| {dimension} | Correct / expected | Recall |\n| --- | ---: | ---: |\n"
        for name, count in groups.items():
            text += f"| {name} | {count['true_positive']}/{count['expected']} | {_percent(count['recall'])} |\n"
    text += "\n## Actual run metadata and remaining coverage\n\n```json\n"+json.dumps(metadata, indent=2, sort_keys=True)+"\n```\n"
    text += '''
Runtime memory is peak tracemalloc Python allocations, excluding native/child
memory. Runtime measures preparation, reasoning, scoring and synthetic cases;
report/ledger serialization after measurement is excluded. Provider calls/tokens/cost for this deterministic sample pipeline are zero;
local OCR/Poppler are local tools. Coding-assistant usage is separate, unmeasured
here. Actual full-output run usage is recorded separately in usage_report.md. The document ledger
below records every image/page, including review-required unsupported semantics.
This evaluator writes reports; production artifact generation/validation runs separately.
'''
    (directory / "evaluation_report.md").write_text(text, encoding="utf-8", newline="\n")
    mismatch = "# Public sample mismatches - evaluation only\n\nThese comparisons never enter production inference.\n\n"
    by_case = {o.case_id: o for o in outcomes}
    for item in metrics["mismatches"]:
        mismatch += f"## {item['case_id']}\n\n"
        item = {**item, "blockers": sorted({g.code for g in by_case[item['case_id']].blockers})}
        mismatch += "```json\n" + json.dumps(item, sort_keys=True, indent=2) + "\n```\n\n"
    (directory / "sample_mismatch_report.md").write_text(mismatch, encoding="utf-8", newline="\n")
    ledger = "# Phase 7 document extraction ledger\n\nAll source IDs are participant-visible; proposals are distinct from promoted facts.\nConfidence null means uncalibrated, not zero certainty.\n\n```json\n" + json.dumps(pipeline.document_ledger, indent=2, sort_keys=True) + "\n```\n"
    (directory / "document_extraction_report.md").write_text(ledger, encoding="utf-8", newline="\n")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", action="store_true", help="Run production sample pipeline, then independently load public labels")
    parser.add_argument("--dataset-dir")
    parser.add_argument("--submission", action="store_true", help="Score actual conservative submission serialization; strict diagnostic counts remain separate")
    parser.add_argument("--reports-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--diagnose-all", action="store_true", help="Include 518-case blockers/counts, never a final prediction export")
    args = parser.parse_args()
    if not args.samples:
        parser.error("Phase 0 evaluator now requires explicit --samples; no final artifacts are written")
    if args.measure:
        tracemalloc.start()
    start = time.perf_counter()
    reader = DatasetReader(args.dataset_dir)
    pipeline = AuditPipeline.from_dataset(reader.root)
    prepared = time.perf_counter()
    outcomes, metrics = evaluate_samples(pipeline, reader, submission=args.submission)
    sampled = time.perf_counter()
    custom = [row[0] for row in run_independent_cases()]
    full_outcomes = pipeline.audit_cases(reader.requests()) if args.diagnose_all else None
    diagnostics = coverage_diagnostics(full_outcomes) if full_outcomes is not None else None
    measurement = {"elapsed_seconds": time.perf_counter() - start, "preparation_seconds": prepared - start,
                   "sample_pipeline_and_scoring_seconds": sampled - prepared}
    if args.measure:
        measurement["peak_traced_python_bytes"] = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    metadata = write_reports(args.reports_dir, reader, pipeline, outcomes, metrics, custom, measurement, diagnostics, args.submission)
    write_ledgers(args.reports_dir, metrics, outcomes, reader.requests(sample=True), pipeline, reader.root, full_outcomes)
    from evaluation.forensics import write_forensics
    from ghost_audit.submission import submission_row
    predictions = [submission_row(o) for o in outcomes] if args.submission else [result_row(o.result) for o in outcomes if o.result]
    write_forensics(args.reports_dir, predictions, read_contract_csv(reader.root / "sample_output.csv"), outcomes, reader, pipeline)
    print(json.dumps({"metrics": {k: v for k, v in metrics.items() if k != "mismatches"}, "metadata": metadata,
                      "custom_cases": custom}, sort_keys=True, indent=2))
    if not all(c["passed"] for c in custom):
        parser.exit(1, "Independent custom acceptance cases failed; reports preserve actual results.\n")


if __name__ == "__main__":
    main()
