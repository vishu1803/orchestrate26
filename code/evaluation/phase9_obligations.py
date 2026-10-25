"""Isolated future-check experiment. No labels, IDs or overrides enter inference."""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evaluation.custom_cases import run_independent_cases
from evaluation.metrics import score_predictions
from ghost_audit.documents import validated_ocr_observations
from ghost_audit.io import DatasetReader, read_contract_csv
from ghost_audit.models import AuditResult, OPERATION_CONTRACT, Phase, Status, Step
from ghost_audit.output import result_row, validate_steps_contract
from ghost_audit.pipeline import AuditPipeline, coverage_diagnostics
from ghost_audit.state_facts import temporal_rejection
from ghost_audit.submission import submission_row, write_submission


def classify_obligation(decisions, outcome, request, index):
    if any(not d.resource.resource_id or not d.resource.system_id for d in decisions):
        return "b_missing_exact_resource"
    if outcome.report is None or not outcome.report.user_id:
        return "c_ambiguous_subject"
    resolution=index.identity_index.resolve_request(request.email,request.audit_at)
    if resolution.user_id!=outcome.report.user_id:
        return "c_ambiguous_subject"
    target=decisions[0].resource.resource_id
    if any(g.resource_id==target and g.code in {"ambiguous_resource_ownership","conflicting_identity_anchor","unresolved_resource_owner"} for g in outcome.blockers):
        return "c_ambiguous_subject"
    observations={(o.source.evidence_id,o.source.locator):o for d in decisions for o in d.resource.observations}
    sources=[s for d in decisions for s in (*d.condition_proofs,*(f.source for f in d.proofs))]
    if any((s.evidence_id,s.locator) not in observations or s!=observations[(s.evidence_id,s.locator)].source
           or temporal_rejection(observations[(s.evidence_id,s.locator)],request.audit_at) for s in sources):
        return "e_temporally_invalid"
    if any(d.compliant is not True or d.blockers or not d.proofs for d in decisions):
        return "d_unsupported_required_treatment"
    return "a_grounded_future_check"


def candidate_row(outcome, request, index):
    if outcome.result is not None:
        return submission_row(outcome),[]
    grouped=defaultdict(list)
    for d in outcome.decisions:
        if d.verification:
            grouped[(d.verification,d.resource.system_id,d.resource.resource_id)].append(d)
    entries=[];selected=[]
    for key,decisions in sorted(grouped.items(),key=lambda x:(list(OPERATION_CONTRACT).index(x[0][0]),x[0][1:])):
        classification=classify_obligation(decisions,outcome,request,index)
        entries.append({"case_id":request.case_id,"operation":key[0],"system_id":key[1],"resource_id":key[2],
                        "classification":classification,"scope_count":len(decisions),
                        "reasons":sorted({d.reason for d in decisions}),
                        "sources":sorted({(f.source.evidence_id,f.source.locator) for d in decisions for f in d.proofs}),
                        "condition_sources":sorted({(s.evidence_id,s.locator) for d in decisions for s in d.condition_proofs})})
        if classification=="a_grounded_future_check":
            selected.append(Step(len(selected)+1,Phase.VERIFICATION,key[1],key[2],key[0],OPERATION_CONTRACT[key[0]][1],""))
    result=AuditResult(outcome.case_id,Status.INCOMPLETE,tuple(selected))
    # Partial serialization measures the proposal; it does NOT make this a valid
    # official incomplete plan. The unchanged strict validator judges it below.
    return result_row(result,allow_partial=True),entries


def run(directory, baseline_documents=False, dataset_dir=None):
    start=time.perf_counter();reader=DatasetReader(dataset_dir)
    # Disable just Experiment A's new document fact for an independent C trial.
    def old_document_facts(documents,index):
        return tuple(o for o in validated_ocr_observations(documents,index)
                     if not(o.data_category=="SUPPORT_MESSAGE" and "order_context" in o.attributes))
    if baseline_documents:
        with patch("ghost_audit.pipeline.validated_ocr_observations",old_document_facts):
            pipeline=AuditPipeline.from_dataset(reader.root)
    else:
        pipeline=AuditPipeline.from_dataset(reader.root)
    samples=reader.requests(sample=True);requests=reader.requests()
    sample_outcomes=pipeline.audit_cases(samples);full=pipeline.audit_cases(requests)
    sample_map={r.case_id:r for r in samples};request_map={r.case_id:r for r in requests}
    sample_rows=[candidate_row(o,sample_map[o.case_id],pipeline.index)[0] for o in sample_outcomes]
    trials=[candidate_row(o,request_map[o.case_id],pipeline.index) for o in full]
    rows=[x[0] for x in trials];obligations=[e for _,items in trials for e in items]
    # All production/proposed arrays are finished before public labels load.
    labels=read_contract_csv(reader.root/"sample_output.csv")
    metrics=score_predictions(sample_rows,labels)
    contract_errors=[]
    for row in rows:
        if row["steps_json"]=="[]":continue # authorized Phase6 empty fallback
        try:validate_steps_contract(row["deletion_status"],json.loads(row["steps_json"]))
        except ValueError as exc:contract_errors.append({"case_id":row["case_id"],"reason":str(exc)})
    directory.mkdir(parents=True,exist_ok=True)
    write_submission(rows,directory/"isolated_output.csv",request_map)
    custom=[x[0] for x in run_independent_cases()]
    report={"baseline_documents":baseline_documents,"metrics":metrics,
            "full_coverage":coverage_diagnostics(full),"obligation_count":len(obligations),
            "classifications":dict(Counter(e["classification"] for e in obligations)),
            "duplicate_count":0,"obligations":obligations,
            "empty_incomplete_cases":sum(r["deletion_status"]=="INCOMPLETE" and r["steps_json"]=="[]" for r in rows),
            "official_plan_contract_errors":contract_errors,"synthetic_cases":custom,
            "elapsed_seconds":time.perf_counter()-start,"application_usage":{"calls":0,"input_tokens":0,"output_tokens":0,"provider_cost_usd":0},
            "promotion":"REJECTED unless strict contract passes AND independently measured sample accuracy improves"}
    (directory/"experiment.json").write_text(json.dumps(report,sort_keys=True,indent=2),encoding="utf-8",newline="\n")
    print(json.dumps({k:report[k] for k in ("obligation_count","classifications","empty_incomplete_cases","elapsed_seconds")}))
    print("Official plan contract failures:",len(contract_errors))
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir",type=Path,required=True)
    parser.add_argument("--baseline-documents",action="store_true")
    parser.add_argument("--dataset-dir")
    args=parser.parse_args();run(args.reports_dir,args.baseline_documents,args.dataset_dir)
