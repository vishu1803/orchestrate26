"""Evaluation-only causal tracing; never imported by production inference."""
from collections import Counter
from dataclasses import asdict
import json
import re

from ghost_audit.state_facts import category, logical_system, normalize_facts, temporal_rejection


def source_texts(pipeline, root):
    texts = {}
    for result in pipeline.index.results:
        if result.format in {".json", ".sql", ".log", ".txt"}:
            texts[result.source.evidence_id] = (root / result.source.file_path).read_text(encoding="utf-8-sig")
    for document in pipeline.state_engine.documents:
        texts[document.source.evidence_id] = texts.get(document.source.evidence_id, "") + "\n" + document.raw_text
    return texts


def localize(metrics, outcomes, requests, pipeline, root):
    """Trace missing expected steps through actual indexed and linked observations.

    Labels describe which target to investigate, never which source fact is true.
    The ledger retains missing-source limitations rather than fabricating support.
    """
    by_case = {o.case_id: o for o in outcomes}
    by_request = {r.case_id: r for r in requests}
    texts = source_texts(pipeline, root)
    rows = []
    for mismatch in metrics["mismatches"]:
        outcome = by_case[mismatch["case_id"]]
        request = by_request[outcome.case_id]
        report = outcome.report
        missing = []
        for step in mismatch["missing_steps"]:
            target = step["system_id"], step["resource_id"]
            all_indexed = pipeline.index.get_observations(target[1])
            indexed = tuple(o for o in all_indexed if logical_system(o) == target[0]
                            or (o.kind == "CLAIM" and o.attributes.get("target_system") == target[0]))
            linked = tuple(r for r in report.resources if (r.system_id, r.resource_id) == target) if report else ()
            decisions = tuple(d for d in outcome.decisions if (d.resource.system_id, d.resource.resource_id) == target)
            source_rows = []
            for observation in indexed:
                rejection = temporal_rejection(observation, request.audit_at)
                facts, gaps = normalize_facts(observation) if observation.observed_at else ((), ("missing_clock",))
                source_rows.append({"evidence_id": observation.source.evidence_id, "locator": observation.source.locator,
                                    "kind": observation.kind, "category": category(observation),
                                    "rejection": rejection, "facts": sorted({(f.dimension, f.value) for f in facts}),
                                    "gaps": list(gaps), "identifier_fields": sorted({i.field for i in observation.identifiers}),
                                    "in_report": any(observation in r.observations for r in linked)})
            state_candidates = [r for r in source_rows if r["kind"] in {"READBACK", "SNAPSHOT"}]
            admissible = [r for r in state_candidates if not r["rejection"]]
            equivalent = [s for s in mismatch["predicted_steps"] if all(s[k] == step[k] for k in ("phase", "operation", "system_id", "resource_id", "state"))]
            raw_sources = [sid for sid, text in texts.items() if re.search(r"(?<![A-Za-z0-9_])" + re.escape(target[1]) + r"(?![A-Za-z0-9_])", text)]
            if equivalent:
                stage, reason = "6_citation_or_serialization", "same_decision_different_citation"
            elif not indexed and (all_indexed or raw_sources):
                stage, reason = "2_fact_extraction", "target_in_raw_source_but_missing_or_wrong_logical_system"
            elif not indexed:
                stage, reason = "1_candidate_or_identity", "no_supplied_target_observation"
            elif not state_candidates:
                stage, reason = "3_time_trust_scope", "activity_claims_only_no_supplied_state_readback"
            elif not admissible:
                stage, reason = "3_time_trust_scope", "all_state_candidates_inadmissible"
            elif not linked:
                stage, reason = "1_candidate_or_identity", "admissible_candidate_not_linked_to_subject"
            elif any(d.blockers for d in decisions):
                stage, reason = "4_policy_category_condition", ";".join(sorted({b for d in decisions for b in d.blockers}))
            elif not decisions or not any(r["facts"] and r["in_report"] for r in admissible):
                stage, reason = "2_fact_extraction", "linked_target_has_no_applicable_state_fact"
            elif outcome.result is None:
                stage, reason = "5_planning_or_companion", "case_result_withheld_by_other_unresolved_requirements"
            else:
                stage, reason = "5_planning_or_companion", "expected_companion_not_compiled"
            cited = next((r.source for r in pipeline.index.results if r.source.evidence_id == step["evidence_id"]), None)
            missing.append({"expected_step": step, "causal_stage": stage, "reason": reason,
                            "raw_exact_target_sources": raw_sources, "indexed_candidates": source_rows,
                            "other_logical_systems": sorted({logical_system(o) for o in all_indexed if o not in indexed}),
                            "expected_citation_check": {"available_by_cutoff": cited.available_at <= request.audit_at if cited else None,
                                                        "has_exact_target_in_source": step["evidence_id"] in raw_sources if step["evidence_id"] else None},
                            "linked_scopes": [asdict(r.scope) for r in linked],
                            "policy_decisions": [{"rule_id": d.rule.rule_id if d.rule else None,
                                                  "component": d.component, "compliant": d.compliant,
                                                  "reason": d.reason, "verification": d.verification} for d in decisions]})
        rows.append({"case_id": outcome.case_id, "missing": missing, "extra_steps": mismatch["extra_steps"],
                     "extra_guardrail_stage": "7_unsupported_or_scope_review" if mismatch["extra_steps"] else None,
                     "case_blockers": sorted({g.code for g in outcome.blockers})})
    return rows


def write_ledgers(directory, metrics, outcomes, requests, pipeline, root, full_outcomes=None):
    ledger = localize(metrics, outcomes, requests, pipeline, root)
    counts = Counter(m["causal_stage"] for row in ledger for m in row["missing"])
    header = "# Phase 5 provenance-oriented sample mismatch ledger\n\nEvaluation only; never read by production inference. Stages reflect observed pipeline loss, not hidden causal truth.\n\n"
    header += "| Stage | Missing step occurrences |\n| --- | ---: |\n" + "".join(f"| {k} | {v} |\n" for k,v in sorted(counts.items()))
    (directory / "sample_provenance_ledger.md").write_text(header + "\n```json\n" + json.dumps(ledger,sort_keys=True,indent=2) + "\n```\n",encoding="utf-8",newline="\n")
    if full_outcomes is not None:
        rows = [{"case_id": o.case_id, "status": o.result.deletion_status.value if o.result else None,
                 "blockers": [{"code": g.code, "resource_id": g.resource_id,
                               "sources": [{"evidence_id": s.evidence_id, "locator": s.locator} for s in g.sources]} for g in o.blockers],
                 "policy_unknowns": [{"resource_id": d.resource.resource_id, "system_id": d.resource.system_id,
                                      "category": d.resource.data_category, "scope": asdict(d.resource.scope),
                                      "rule_id": d.rule.rule_id if d.rule else None, "reason": d.reason} for d in o.decisions if d.compliant is None]}
                for o in full_outcomes]
        (directory / "evaluation_blocker_ledger.md").write_text("# Unlabeled 518-request blocker ledger\n\nNo expected outcomes or hidden labels are used.\n\n```json\n"+json.dumps(rows,sort_keys=True,indent=2)+"\n```\n",encoding="utf-8",newline="\n")
    return dict(sorted(counts.items()))
