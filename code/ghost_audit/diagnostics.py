"""Deterministic factual diagnostics; no compliance labels, personal values or predictions."""
from collections import Counter
from dataclasses import asdict
import json

from .documents import document_inventory
from .state_facts import RESOURCE_CLASSES


def source_view(source):
    return {"evidence_id": source.evidence_id, "locator": source.locator,
            "file_path": source.file_path, "source_kind": source.source_kind,
            "available_at": source.available_at.isoformat() if source.available_at else None,
            "sha256": source.content_sha256}


def case_diagnostic(report):
    return {"case_id": report.case_id, "user_id": report.user_id, "audit_at": report.audit_at.isoformat(),
            "alias_facts": len(report.aliases),
            "resources": [{"system_id": r.system_id, "resource_id": r.resource_id,
                           "record_class": r.data_category or "UNKNOWN", "scope": asdict(r.scope),
                           "dimensions": [{"dimension": d.dimension, "value": d.value, "epistemic": d.epistemic,
                                           "selection_reason": "latest_observed_same_physical_scope" if d.supporting else "no_current_supported_fact",
                                           "supporting": [{**source_view(f.source), "observed_at": f.observed_at.isoformat(),
                                                           "field": f.field, "field_locator": f.locator,
                                                           "normalized_state": f.value} for f in d.supporting],
                                           "rejected": [{**source_view(t.source), "reason": t.reason} for t in d.rejected]}
                                          for d in r.dimensions],
                           "match_reasons": [{"field": m.field, "anchor": source_view(m.observation_source),
                                              "identifier_locator": m.identifier_locator,
                                              "identity_sources": sorted({a.source_id for a in m.identity_sources})} for m in r.match_reasons],
                           "gaps": list(r.gaps),
                           "reappearance": [{"kind": t.kind, "before": [source_view(f.source) for f in t.before],
                                             "after": [source_view(f.source) for f in t.after],
                                             "claims": [source_view(o.source) for o in t.claims]} for t in r.recreation]}
                          for r in report.resources],
            "conflicts": [{"code": g.code, "resource_id": g.resource_id,
                           "sources": [source_view(s) for s in g.sources]} for g in report.conflicts],
            "gaps": [{"code": g.code, "resource_id": g.resource_id,
                      "sources": [source_view(s) for s in g.sources]} for g in report.gaps],
            "comparisons": [{"system_id": c.system_id, "resource_id": c.resource_id, "kind": c.kind,
                             "scopes": [asdict(s) for s in c.scopes], "sources": [source_view(s) for s in c.sources]}
                            for c in report.comparisons],
            "activity_claims": [{**source_view(o.source), "event": o.attributes.get("event_type", o.attributes.get("event")),
                                 "observed_at": o.observed_at.isoformat()} for o in report.activity_claims],
            "explanations": [{**source_view(t.source), "reason": t.reason} for t in report.explanations]}


def aggregate_diagnostics(engine, reports, selected_case_ids=()):
    resources = [r for p in reports for r in p.resources]
    linked_locations = {(o.source.evidence_id, o.source.locator) for r in resources for o in r.observations}
    exclusions = Counter(t.reason for p in reports for t in p.explanations if "cutoff" in t.reason)
    states = Counter(r.record_existence for r in resources)
    linked_classes = Counter(r.data_category or "UNKNOWN" for r in resources)
    visual = document_inventory(engine.documents)
    linked_visual = {s.evidence_id for p in reports for g in p.gaps
                     if g.code == "potentially_relevant_visual_semantics_require_review" for s in g.sources}
    source_counts = Counter(o.source.file_path.rsplit(".", 1)[-1] if o.source.source_kind == "FILE" else "activity_claim"
                            for o in engine.index.observations)
    selected = set(selected_case_ids)
    return {"kind": "RESOURCE_FACT_DIAGNOSTICS_ONLY", "ingestion": engine.index.coverage_report(),
            "aggregate": {"cases": len(reports), "resolved_cases": sum(p.user_id is not None for p in reports),
                          "cases_with_resources": sum(bool(p.resources) for p in reports),
                          "case_resource_scopes": len(resources),
                          "unique_logical_resources": len({(r.system_id, r.resource_id) for r in resources}),
                          "unique_physical_resource_scopes": len({(r.system_id, r.resource_id, r.scope) for r in resources}),
                          "linked_observation_locations": len(linked_locations),
                          "observation_sources": dict(sorted(source_counts.items())),
                          "existence_dimensions": dict(sorted(states.items())),
                          "cases_with_conflicts": sum(bool(p.conflicts) for p in reports),
                          "cases_with_unknown_existence": sum(any(r.record_existence == "UNKNOWN" for r in p.resources) for p in reports),
                          "cases_with_gaps": sum(bool(p.gaps) for p in reports),
                          "cases_with_visual_gaps": sum(any(g.code == "potentially_relevant_visual_semantics_require_review" for g in p.gaps) for p in reports),
                          "cases_with_observed_reappearance": sum(any(t.kind == "OBSERVED_REAPPEARANCE" for r in p.resources for t in r.recreation) for p in reports),
                          "cases_with_presence_after_delete_claim": sum(any(t.kind == "PRESENCE_AFTER_DELETE_CLAIM" for r in p.resources for t in r.recreation) for p in reports),
                          "cases_with_scope_divergence": sum(bool(p.comparisons) for p in reports),
                          "comparison_kinds": dict(sorted(Counter(c.kind for p in reports for c in p.comparisons).items())),
                          "linked_cutoff_exclusions": dict(sorted(exclusions.items())),
                          "linked_record_classes": dict(sorted(linked_classes.items())),
                          "classes_without_observed_schema": sorted(set(RESOURCE_CLASSES) - set(engine.class_counts)),
                          "visual_sources_requiring_review": len({d.source.evidence_id for d in engine.documents if d.needs_review}),
                          "visual_sources_without_case_link": sorted({d.source.evidence_id for d in engine.documents} - linked_visual)},
            "visual_inventory": visual,
            "selected_cases": [case_diagnostic(p) for p in reports if p.case_id in selected]}


def serialize_diagnostic(report):
    return json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
