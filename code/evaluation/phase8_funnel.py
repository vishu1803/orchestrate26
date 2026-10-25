"""Read-only first-loss diagnostics. Never imported by production inference."""
import argparse
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.localization import localize, source_texts
from evaluation.main import evaluate_samples
from ghost_audit.evidence import observation_key
from ghost_audit.io import DatasetReader
from ghost_audit.pipeline import AuditPipeline
from ghost_audit.planner import verification_closure
from ghost_audit.state_facts import logical_system, temporal_rejection
from ghost_audit.submission import submission_row

STAGES = ("RAW_SOURCE_ABSENT", "PARSER_MISSED", "STRUCTURED_OBSERVATION_MISSING_FIELD",
          "IDENTITY_LINK_MISSED", "RESOURCE_SCOPE_LINK_MISSED", "TIME_FILTER_REJECTED",
          "POLICY_CONDITION_UNKNOWN_OR_MISAPPLIED", "VERIFICATION_OBLIGATION_NOT_CREATED",
          "COMPILER_OR_SEQUENCE_ERROR", "INSUFFICIENT_GROUNDED_EVIDENCE")


def classify_loss(item):
    """Exactly one earliest demonstrated loss; an unsupported join is not a bug."""
    reason = item["reason"]
    if item.get("rejected_subject_binding"):
        return "TIME_FILTER_REJECTED"
    if reason == "all_state_candidates_inadmissible":
        return "TIME_FILTER_REJECTED"
    if reason in {"unsupported_or_unknown_rule_condition", "treatment_or_preservation_not_proven"}:
        return "POLICY_CONDITION_UNKNOWN_OR_MISAPPLIED"
    if reason == "target_in_raw_source_but_missing_or_wrong_logical_system":
        return "PARSER_MISSED"
    if reason == "same_decision_different_citation":
        return "COMPILER_OR_SEQUENCE_ERROR"
    if reason == "expected_companion_not_compiled":
        return "VERIFICATION_OBLIGATION_NOT_CREATED"
    # Claims-only, identifier-free resources without an ownership edge, absent
    # targets and whole-case withholding are evidence limits, not lost proofs.
    return "INSUFFICIENT_GROUNDED_EVIDENCE"


def scrub(value, names=()):
    """Keep original schema and nulls, but redact direct identifier values."""
    if isinstance(value, Mapping):
        return {k: ("[REDACTED]" if v is not None and any(x in k.lower() for x in
                ("email", "phone", "full_name", "display_name", "requester_name")) else scrub(v, names))
                for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [scrub(v, names) for v in value]
    if isinstance(value, str):
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\b[a-fA-F0-9]{64}\b|\+\d[\d ()-]{7,}\d", "[REDACTED]", value)
        for name in names:
            value = value.replace(name, "[REDACTED]")
        return value
    return value


def raw_corpus(pipeline, reader):
    # Search original text independently of normalized observations. PDF raw
    # extraction and PNG OCR are included with page/region locators. Sample
    # labels, output templates and request lists are not evidence searches.
    rows = []
    for result in pipeline.index.results:
        if result.format in {".json", ".sql", ".log", ".txt"}:
            for n, line in enumerate((reader.root / result.source.file_path).read_text(encoding="utf-8-sig").splitlines(), 1):
                rows.append((result.source.evidence_id, f"raw-line:{n}", result.format, line))
    for d in pipeline.state_engine.documents:
        for n, line in enumerate(d.raw_text.splitlines(), 1):
            rows.append((d.source.evidence_id, f"{d.source.locator}/text-line:{n}", Path(d.source.file_path).suffix, line))
    for name in ("system_activity.csv", "user_audit_log.csv", "user_identities.csv", "deletion_rules.csv", "evidence_files.csv"):
        for n, line in enumerate((reader.root / name).read_text(encoding="utf-8-sig").splitlines(), 1):
            rows.append((name, f"raw-line:{n}", ".csv", line))
    return rows


def token_hits(corpus, tokens):
    tokens = {x.casefold() for x in tokens if x}
    if not tokens:
        return []
    pattern = re.compile(r"(?<![\w])(?:" + "|".join(re.escape(x) for x in sorted(tokens, key=lambda x: (-len(x), x))) + r")(?![\w])", re.I)
    return [(sid, loc, fmt, line) for sid, loc, fmt, line in corpus if pattern.search(line)]


def case_funnel(pipeline, request, outcome, corpus):
    resolution = pipeline.index.identity_index.resolve_request(request.email, request.audit_at)
    tokens = {resolution.user_id, *(a.value for a in resolution.aliases if a.field in {"email", "phone", "email_hash"})}
    raw = token_hits(corpus, tokens)
    # Diagnostic association before time filtering uses the same safe identifiers
    # and exact inverted keys, never expected IDs or future alias inference.
    candidates = {}
    alias_keys = {(a.field, a.normalized_value) for a in resolution.aliases}
    for o in pipeline.index.observations:
        if any(i.normalized_value in {resolution.user_id} or
               (i.field, i.normalized_value) in alias_keys
               for i in o.identifiers):
            candidates[observation_key(o)] = o
    linked = pipeline.index.find_subject_evidence(resolution, request.audit_at, include_untimed=True)
    report = outcome.report
    resources = report.resources if report else ()
    eligible = [r for r in resources if any(o.kind in {"READBACK", "SNAPSHOT"} and not temporal_rejection(o, request.audit_at) for o in r.observations)]
    evaluable = {(d.resource.system_id, d.resource.resource_id, repr(d.resource.scope)) for d in outcome.decisions
                 if d.verification and not d.blockers}
    row = submission_row(outcome)
    return {"case_id": request.case_id, "intent": outcome.authorization, "user_id": resolution.user_id,
            "raw_associated_line_candidates": len(raw), "parsed_alias_candidate_observations": len(candidates),
            "direct_or_trace_linked_observations": len(linked.matches),
            "subject_linked_physical_resources": len(resources), "time_eligible_physical_resources": len(eligible),
            "policy_evaluable_physical_resources": len(evaluable),
            "planned_logical_verifications": len(verification_closure(outcome.decisions)),
            "emitted_steps": len(json.loads(row["steps_json"])), "status": row["deletion_status"],
            "strict_withheld": outcome.result is None, "blockers": sorted({g.code for g in outcome.blockers})}


def build_report(pipeline, reader):
    # Finish all predictions before isolated evaluator loads public labels.
    outcomes, metrics = evaluate_samples(pipeline, reader, submission=True)
    full = pipeline.audit_cases(reader.requests())
    corpus = raw_corpus(pipeline, reader)
    names = tuple(r.name for r in reader.identities())
    localized = localize(metrics, outcomes, reader.requests(sample=True), pipeline, reader.root)
    by_outcome = {o.case_id: o for o in outcomes}
    requests = {r.case_id: r for r in reader.requests(sample=True)}
    missing = []
    for row in localized:
        outcome = by_outcome[row["case_id"]]
        request = requests[row["case_id"]]
        direct = pipeline.index.find_subject_evidence(pipeline.index.identity_index.resolve_request(request.email, request.audit_at), request.audit_at, include_untimed=True)
        for item in row["missing"]:
            target = item["expected_step"]["resource_id"]
            observations = pipeline.index.get_observations(target)
            hits = token_hits(corpus, {target})
            resolution = pipeline.index.identity_index.resolve_request(request.email, request.audit_at)
            aliases = {(a.field, a.normalized_value) for a in resolution.aliases}
            ownership = [o for o in observations if any((i.field == "user_id" and i.normalized_value == resolution.user_id)
                         or (i.field, i.normalized_value) in aliases for i in o.identifiers)]
            item["rejected_subject_binding"] = (item["reason"] == "admissible_candidate_not_linked_to_subject"
                                                 and bool(ownership) and all(temporal_rejection(o, request.audit_at) for o in ownership))
            raw = [{"source": sid, "locator": loc, "format": fmt, "raw_excerpt": scrub(line[max(0,line.find(target)-100):line.find(target)+len(target)+160], names)} for sid,loc,fmt,line in hits]
            detail = [{"observation_id": list(observation_key(o)), "logical_system": logical_system(o),
                       "kind": o.kind, "observed_at": o.observed_at.isoformat() if o.observed_at else None,
                       "available_at": o.source.available_at.isoformat(), "cutoff_decision": temporal_rejection(o, request.audit_at),
                       "original_record_fields": scrub(o.raw_fields, names),
                       "identifier_fields": sorted({i.field for i in o.identifiers}),
                       "link_origins": [{"kind": reason.field, "source": reason.observation_source.evidence_id, "locator": reason.identifier_locator}
                                        for match in direct.matches if observation_key(match.observation)==observation_key(o) for reason in match.reasons]}
                      for o in observations]
            missing.append({"case_id": row["case_id"], "first_loss_stage": classify_loss(item),
                            "supporting_evidence_found": bool(hits), "raw_search_hits": raw,
                            "observations": detail, "audit_at": request.audit_at.isoformat(),
                            "case_blockers": row["case_blockers"], **item})
    full_funnel = [case_funnel(pipeline, r, o, corpus) for r,o in zip(sorted(reader.requests(),key=lambda r:r.case_id),full)]
    sample_funnel = [case_funnel(pipeline, requests[o.case_id], o, corpus) for o in outcomes]
    stages = {s: sum(x["first_loss_stage"]==s for x in missing) for s in STAGES}
    no_steps = [x for x in full_funnel if x["status"]=="INCOMPLETE" and x["emitted_steps"]==0]
    fmt = Counter()
    for x in missing:
        formats = sorted({h["format"] for h in x["raw_search_hits"]})
        fmt["+".join(formats) or "NO_EXTRACTED_TARGET"] += 1
    return {"utc":datetime.now(timezone.utc).isoformat(), "metrics": {k:v for k,v in metrics.items() if k!='mismatches'},
            "first_loss_counts":stages, "missing_count":len(missing),
            "by_operation":dict(Counter(x["expected_step"]["operation"] for x in missing)),
            "by_format_signature":dict(fmt), "by_case":dict(Counter(x["case_id"] for x in missing)),
            "empty_incomplete_summary":{"cases":len(no_steps), "blocker_case_counts":dict(Counter(c for x in no_steps for c in x["blockers"])),
                                        "totals":{k:sum(x[k] for x in no_steps) for k in ("raw_associated_line_candidates","parsed_alias_candidate_observations","subject_linked_physical_resources","time_eligible_physical_resources","policy_evaluable_physical_resources","planned_logical_verifications","emitted_steps")}},
            "source_search":{"manifest_files":len(pipeline.index.results),"raw_lines_searched":len(corpus),
                             "pdf_rendering":"unavailable locally; selectable raw text searched", "png_review":"all11 visually inspected; OCR also searched",
                             "absence_limit":"No RAW_SOURCE_ABSENT conclusion while PDF visual completeness remains unverified; missing exact text is not proof of absent pixels."},
            "missing_steps":missing, "sample_case_funnels":sample_funnel,"production_case_funnels":full_funnel}


def write_report(path, report):
    text = "# Phase 8 first-loss funnel - Stage A, evaluation only\n\nExactly one first-loss class for each missing expected step. Classes mark the earliest demonstrated missing prerequisite, not permission to invent a repair. Raw target searches use original participant evidence text, independent of the normalized index, plus all PDF raw text/PNG OCR and participant identity/history/activity CSVs. Labels and output/request CSVs are excluded from source search. Missing text alone is never RAW_SOURCE_ABSENT.\n\n"
    text += "| First loss | Missing steps |\n| --- | ---: |\n" + "".join(f"| {k} | {v} |\n" for k,v in report["first_loss_counts"].items())
    text += "\nCounters deliberately use different units: raw associated text lines, parsed alias observations (before cutoff), physical resource scopes, logical verification obligations and serialized steps. They are not a monotonically decreasing probability funnel. They are descriptive diagnostics, never inferred outputs. Non-deletion requests have no per-case state investigation. The152 empty rows are individually listed with known obligations and blockers. Withholding an entire case is not equivalent to failing to create a known obligation.\n\n"
    text += "## Ten most actionable evidence investigations\n\n"
    examples = sorted(report["missing_steps"], key=lambda x:(x["first_loss_stage"]!="POLICY_CONDITION_UNKNOWN_OR_MISAPPLIED", not bool(x["raw_search_hits"]), x["case_id"],x["expected_step"]["operation"]))[:10]
    for x in examples:text+=f"- {x['case_id']} {x['expected_step']['operation']} {x['expected_step']['resource_id']}: {x['reason']}; sources {','.join(sorted({h['source'] for h in x['raw_search_hits']})) or 'no exact text target'}.\n"
    text += "\n## Exact first-loss details, format/operation/case counts and every production funnel\n\n```json\n"+json.dumps(report,sort_keys=True,indent=2)+"\n```\n"
    path.write_text(text,encoding="utf-8",newline="\n")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    reader=DatasetReader()
    report=build_report(AuditPipeline.from_dataset(reader.root),reader)
    write_report(args.output,report)
    print(json.dumps({k:report[k] for k in ("missing_count","first_loss_counts","empty_incomplete_summary")}))


if __name__=="__main__":
    main()
