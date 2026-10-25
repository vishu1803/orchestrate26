"""Phase 6 independent CSV contract checks plus regenerated evidence certificates.

Phase 0 help boundary preserved. Structural acceptance is distinct from complete
semantic coverage; --strict-coverage additionally rejects unresolved diagnostics.
"""
import argparse
import csv
from dataclasses import asdict, replace
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ghost_audit.io import DatasetReader
from ghost_audit.models import OPERATION_CONTRACT, OUTPUT_COLUMNS, AuditResult, Status, Step
from ghost_audit.output import validate_case
from ghost_audit.pipeline import AuditPipeline


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def inspect_csv(path, expected_ids, evidence_times, requests):
    """Independent checks; no producer serializer, planner or expected labels."""
    with Path(path).open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        if tuple(reader.fieldnames or ()) != OUTPUT_COLUMNS:
            raise ValueError("exact_header_required")
        rows = list(reader)
    ids = [r.get("case_id") for r in rows]
    if len(ids) != len(expected_ids) or ids != sorted(expected_ids) or len(set(ids)) != len(ids):
        raise ValueError("case_count_keys_or_lexical_order")
    fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    request_map = {r.case_id:r for r in requests}
    for row in rows:
        if set(row)!=set(OUTPUT_COLUMNS) or any(not isinstance(v,str) for v in row.values()):
            raise ValueError("malformed_csv_row")
        status = row["deletion_status"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError("invalid_status")
        steps = json.loads(row["steps_json"], object_pairs_hook=unique_object,
                           parse_constant=lambda x: (_ for _ in ()).throw(ValueError("non_json_constant")))
        if not isinstance(steps,list) or (status=="NOT_APPLICABLE" and steps) or (status=="COMPLETE" and not steps):
            raise ValueError("invalid_steps_array")
        ordering = []
        for number, step in enumerate(steps,1):
            if not isinstance(step,dict) or set(step)!=fields or type(step["step_no"]) is not int or step["step_no"]!=number:
                raise ValueError("step_schema_or_numbering")
            if any(not isinstance(step[k],str) for k in fields-{"step_no"}):
                raise ValueError("step_value_types")
            operation=step["operation"]
            if OPERATION_CONTRACT.get(operation)!=(step["phase"],step["state"]):
                raise ValueError("operation_phase_state")
            if not all(re.fullmatch(r"[A-Za-z0-9_.:/-]+",step[k]) for k in ("system_id","resource_id")):
                raise ValueError("unsafe_or_pii_resource_identifier")
            if status=="COMPLETE" and step["phase"]!="VERIFICATION":
                raise ValueError("complete_non_verification")
            cited=step["phase"]=="FINDING" or status=="COMPLETE"
            if bool(step["evidence_id"])!=cited:
                raise ValueError("citation_placement")
            if cited:
                observed=evidence_times.get(step["evidence_id"])
                if observed is None or observed>request_map[row["case_id"]].audit_at:
                    raise ValueError("unknown_or_future_source_id")
            ordering.append((phase_order[step["phase"]],list(OPERATION_CONTRACT).index(operation),step["system_id"],step["resource_id"]))
        if ordering!=sorted(ordering) or len(ordering)!=len(set(ordering)):
            raise ValueError("step_order_or_duplicate")
    return rows


def validate_submission(path, reader, *, sample=False, strict=False):
    requests=reader.requests(sample=sample)
    times={x.file_id:x.captured_at for x in reader.manifest()}
    times.update({x.activity_id:x.event_time for x in reader.activity()})
    times.update({x.audit_id:x.event_time for x in reader.history()})
    rows=inspect_csv(path,[r.case_id for r in requests],times,requests)
    pipeline=AuditPipeline.from_dataset(reader.root)
    candidates={r["case_id"]:r for r in rows}
    unresolved=0
    for request in requests:
        baseline=pipeline.audit(request)
        row=candidates[request.case_id]
        steps=tuple(Step(**s) for s in json.loads(row["steps_json"]))
        if baseline.result is None:
            unresolved+=1
            if strict or row["deletion_status"]!="INCOMPLETE" or steps:
                raise ValueError("unresolved_case_only_conservative_empty_allowed")
            continue
        candidate=replace(baseline,result=AuditResult(request.case_id,Status(row["deletion_status"]),steps))
        if candidate.result.deletion_status!=baseline.result.deletion_status:
            raise ValueError("status_not_supported_by_current_proof")
        validate_case(candidate,request,pipeline.index,require_complete_coverage=strict)
        # Bindings are regenerated, never supplied by the CSV. Exact checks also
        # reject omitted baselines and additional unbound/fabricated future work.
        if [asdict(s) for s in candidate.result.steps]!=[asdict(s) for s in baseline.result.steps]:
            raise ValueError("candidate_differs_from_grounded_plan")
    return {"rows":len(rows),"conservative_fallbacks":unresolved,"structural_and_source_checks":"PASS",
            "semantic_completeness":"NOT_CERTIFIED"}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path)
    parser.add_argument("--dataset-dir")
    parser.add_argument("--sample",action="store_true")
    parser.add_argument("--strict-coverage",action="store_true")
    args=parser.parse_args()
    if not args.input:
        parser.error("Phase 0 help boundary preserved; --input is required")
    try:
        result=validate_submission(args.input,DatasetReader(args.dataset_dir),sample=args.sample,strict=args.strict_coverage)
    except (ValueError,OSError,csv.Error,TypeError,KeyError) as exc:
        parser.exit(1,f"Validation failed: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
