"""Read-only evaluation microscope. Never imported by production inference."""
from collections import Counter, defaultdict
from itertools import zip_longest
import json

from .metrics import ALIGN, FIELDS, SET_FIELDS, _rows


def _counter(steps,fields):
    return Counter(tuple(s[k] for k in fields) for s in steps)


def analyze(predictions,labels,outcomes=(),source_times=None,requests=()):
    actual,gold=_rows(predictions),_rows(labels)
    outcomes={o.case_id:o for o in outcomes}
    cutoffs={r.case_id:r.audit_at for r in requests}
    sources=source_times or {}
    cases=[];causes=defaultdict(lambda:{"missing_steps":0,"cases":set()})
    groups={name:defaultdict(Counter) for name in ("operation","phase")}
    levels=(ALIGN,(*ALIGN,"state"),(*ALIGN,"state","evidence_id"),FIELDS)
    for cid,(status,expected) in sorted(gold.items()):
        predicted_status,steps=actual.get(cid,(None,[]))
        outcome=outcomes.get(cid)
        report=outcome.report if outcome else None
        targets={(r.system_id,r.resource_id) for r in report.resources} if report else set()
        detail=[]
        for fields in levels:
            left,right=_counter(steps,fields),_counter(expected,fields)
            detail.append({"fields":list(fields),"tp":sum((left&right).values()),
                           "missing":[dict(zip(fields,x)) for x in (right-left).elements()],
                           "extra":[dict(zip(fields,x)) for x in (left-right).elements()]})
        left,right=_counter(steps,SET_FIELDS),_counter(expected,SET_FIELDS)
        missing=[dict(zip(SET_FIELDS,s)) for s in (right-left).elements()]
        extra=[dict(zip(SET_FIELDS,s)) for s in (left-right).elements()]
        per_step=[];tags=set();wrong_state=[];wrong_citation=[];misplaced=[];timing=[]
        for s in missing:
            step_tags=[]
            if s["phase"]=="VERIFICATION" and s["system_id"]=="account_service":step_tags.append("missing-account-verification")
            if s["phase"]=="VERIFICATION" and s["operation"]=="VERIFY_RECORD_PRESENT":step_tags.append("missing-retained-record-verification")
            if s["phase"]=="REMEDIATION":step_tags.append("missing-remediation")
            if s["operation"] in {"VERIFY_DATA_FLOW_DISABLED","VERIFY_RESTORE_BLOCKED"}:step_tags.append("missing-flow/restore-verification")
            if (s["system_id"],s["resource_id"]) not in targets:step_tags.append("missing-resource-link")
            elif outcome:
                decisions=[d for d in outcome.decisions if (d.resource.system_id,d.resource.resource_id)==(s["system_id"],s["resource_id"])]
                if decisions and all(d.verification is None for d in decisions):step_tags.append("unproven-policy-condition")
                elif outcome.result is None:step_tags.append("verification-withheld-by-uncertainty")
            if not step_tags:step_tags.append("unresolved-extraction-state-or-scope")
            per_step.append({"step":s,"tags":step_tags})
            for tag in step_tags:causes[tag]["missing_steps"]+=1;causes[tag]["cases"].add(cid)
            tags.update(step_tags)
        by_key=defaultdict(list)
        for s in steps:by_key[tuple(s[k] for k in ALIGN)].append(s)
        for s in expected:
            matches=by_key.get(tuple(s[k] for k in ALIGN),[])
            if matches and not any(x["state"]==s["state"] for x in matches):wrong_state.append({"expected":s,"actual":matches})
            same=[x for x in matches if x["state"]==s["state"]]
            if same and not any(x["evidence_id"]==s["evidence_id"] for x in same):wrong_citation.append({"expected":s,"actual":same})
            exact=[(i+1,x) for i,x in enumerate(steps) if all(x[k]==s[k] for k in SET_FIELDS)]
            if exact and not any(i==s["step_no"] and x["step_no"]==s["step_no"] for i,x in exact):misplaced.append({"expected_step_no":s["step_no"],"actual_positions":[i for i,x in exact],"step":s})
        for side,array in (("actual",steps),("expected",expected)):
            for s in array:
                if s["evidence_id"] and cid in cutoffs:
                    t=sources.get(s["evidence_id"])
                    if t is None or t>cutoffs[cid]:timing.append({"side":side,"step":s,"reason":"unknown_source" if t is None else "source_captured_after_audit"})
        if extra:tags.add("extra-step");causes["extra-step"]["cases"].add(cid)
        for tag,items in (("wrong-state",wrong_state),("wrong-citation",wrong_citation),("wrong-order",misplaced),("wrong-evidence-timing",timing)):
            if items:tags.add(tag);causes[tag]["cases"].add(cid)
        first=next(({"position":i,"actual":a,"expected":b} for i,(a,b) in enumerate(zip_longest(steps,expected),1) if a!=b),None)
        counts={}
        for dimension in groups:
            local=defaultdict(Counter)
            index=SET_FIELDS.index(dimension)
            for key,counter in (("expected",right),("predicted",left),("tp",left&right)):
                for values,n in counter.items():local[values[index]][key]+=n;groups[dimension][values[index]][key]+=n
            counts[dimension]={name:{"tp":x["tp"],"fp":x["predicted"]-x["tp"],"fn":x["expected"]-x["tp"]} for name,x in sorted(local.items())}
        cases.append({"case_id":cid,"actual_status":predicted_status,"gold_status":status,"exact_array":steps==expected,
                      "exact_row":steps==expected and predicted_status==status,"progressive_matching":detail,
                      "missing":per_step,"extra":extra,"missed_resource_ids":sorted({s["resource_id"] for s in missing if (s["system_id"],s["resource_id"]) not in targets}),
                      "wrong_states":wrong_state,"wrong_citations":wrong_citation,"wrong_evidence_timing":timing,
                      "misplaced_steps":misplaced,"first_divergence":first,"tags":sorted(tags),"counts":counts})
    ranked=[{"cause":tag,"missing_steps":data["missing_steps"],"cases_prevented_from_exact":len(data["cases"]),"case_ids":sorted(data["cases"])} for tag,data in causes.items()]
    ranked.sort(key=lambda x:(-x["missing_steps"],-x["cases_prevented_from_exact"],x["cause"]))
    return {"method":"progressive-exact-multiset-v1; positions are shifts, not automatically compiler defects",
            "root_cause_ranking":ranked,"counts":{dimension:{name:{"tp":x["tp"],"fp":x["predicted"]-x["tp"],"fn":x["expected"]-x["tp"]} for name,x in sorted(values.items())} for dimension,values in groups.items()},"cases":cases}


def write_forensics(directory,predictions,labels,outcomes,reader,pipeline=None):
    times={x.file_id:x.captured_at for x in reader.manifest()}
    times.update({x.activity_id:x.event_time for x in reader.activity()})
    times.update({x.audit_id:x.event_time for x in reader.history()})
    report=analyze(predictions,labels,outcomes,times,reader.requests(sample=True))
    localized=directory/"sample_provenance_ledger.md"
    if localized.exists():
        import re
        rows=json.loads(re.search(r"```json\s*(.*?)\s*```",localized.read_text(encoding="utf-8"),re.S)[1])
        gaps=[]
        for row in rows:
            for item in row["missing"]:
                gaps.append({"case_id":row["case_id"],"step":item["expected_step"],
                             "loss_stage":item["causal_stage"],"reason":item["reason"],
                             "raw_exact_target_sources":item["raw_exact_target_sources"],
                             "expected_citation_check":item.get("expected_citation_check"),
                             "state_candidates":item["indexed_candidates"]})
        report["source_sufficiency"]=gaps
        report["source_limit_counts"]={"missing_steps_with_no_target_in_extracted_files":sum(not x["raw_exact_target_sources"] for x in gaps),
                                       "claim_only_no_readback":sum(x["reason"]=="activity_claims_only_no_supplied_state_readback" for x in gaps),
                                       "all_readbacks_temporally_inadmissible":sum(x["reason"]=="all_state_candidates_inadmissible" for x in gaps)}
    if pipeline is not None:
        from ghost_audit.submission import submission_row
        request_map={r.case_id:r for r in reader.requests(sample=True)}
        selected=[]
        for label,predicate in (("complete",lambda o:o.result is not None and o.result.deletion_status=="COMPLETE"),
                                ("incomplete",lambda o:o.result is not None and o.result.deletion_status=="INCOMPLETE"),
                                ("historical_identifier",lambda o:pipeline.index.identity_index.resolve_request(request_map[o.case_id].email,request_map[o.case_id].audit_at).historical_email)):
            chosen=next((o for o in outcomes if predicate(o) and o.case_id not in {x[1].case_id for x in selected}),None)
            if chosen:selected.append((label,chosen))
        traces=[]
        for kind,outcome in selected:
            request=request_map[outcome.case_id]
            identity=pipeline.index.identity_index.resolve_request(request.email,request.audit_at)
            decisions=[]
            for d in outcome.decisions:
                decisions.append({"system_id":d.resource.system_id,"resource_id":d.resource.resource_id,"scope":repr(d.resource.scope),
                                  "category":d.resource.data_category,"state":d.resource.record_existence,
                                  "dimensions":{v.dimension:v.value for v in d.resource.dimensions if v.supporting},
                                  "rule_id":d.rule.rule_id if d.rule else None,"rule_action":d.rule.required_action if d.rule else None,
                                  "compliant":d.compliant,"reason":d.reason,"verification":d.verification,
                                  "evidence":[{"evidence_id":f.source.evidence_id,"locator":f.source.locator,
                                               "observed_at":f.observed_at.isoformat(),"available_at":f.source.available_at.isoformat()} for f in d.proofs]})
            traces.append({"trace_kind":kind,"case_id":outcome.case_id,"request_text":request.request_text,"audit_at":request.audit_at.isoformat(),
                           "authorization":outcome.authorization,"identity":{"user_id":identity.user_id,"historical_email":identity.historical_email,
                           "identity_source_ids":sorted({m.identifier.source_id for m in identity.matches}),"alias_field_counts":dict(Counter(a.field for a in identity.aliases))},
                           "investigation_status":outcome.result.deletion_status if outcome.result else None,"decisions":decisions,
                           "blockers":sorted({g.code for g in outcome.blockers}),"ordered_output":submission_row(outcome)})
        (directory/"phase7_case_traces.md").write_text("# Three actual end-to-end traces - evaluation only\n\nNo expected answer enters these traces. Raw direct identifiers omitted; stable IDs, source locators, clocks, policy and complete ordered output retained.\n\n```json\n"+json.dumps(traces,sort_keys=True,indent=2)+"\n```\n",encoding="utf-8",newline="\n")
    text="# Phase 7 forensic mismatch microscope - evaluator only\n\nAll32cases; no production imports. Positional shifts caused by omitted steps are distinguished from a pure ordering defect. Source-time checks on expected citations are diagnostics, not authority to change inference.\n\n| Cause | Missing step occurrences | Cases prevented from exact |\n| --- | ---: | ---: |\n"
    for row in report["root_cause_ranking"][:10]:text+=f"| {row['cause']} | {row['missing_steps']} | {row['cases_prevented_from_exact']} |\n"
    text+="\n## Five source-level recovery priorities\n\n1. Subject-linked account negatives and explicit resource ownership, rather than numeric guesses.\n2. Security retention deadlines/active holds tied to actual readbacks and audit cutoff.\n3. Anonymous analytics lookup scope and same-source trace ownership without proximity joins.\n4. Shared support/attachment ownership and field-complete treatment proof.\n5. Grounded closure for every known resource; source-clock review before changing citations or sequence.\n\n```json\n"+json.dumps(report,sort_keys=True,indent=2)+"\n```\n"
    (directory/"phase7_mismatch_analyzer.md").write_text(text,encoding="utf-8",newline="\n")
    return report
