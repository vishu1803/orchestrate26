"""Single production decision pipeline; public labels are never runtime inputs."""
from collections import Counter
from dataclasses import replace
import re

from .documents import (CachedDocumentExtractor, LocalDocumentExtractor, semantic_ledger,
                        validated_document_observations, validated_ocr_observations)
from .evidence import EvidenceIndex, ingest_evidence
from .intent import classify_request_intent
from .io import DatasetReader
from .models import AuditResult, CaseOutcome, CoverageGap, Status
from .output import validate_case
from .planner import compile_plan, execution_order
from .policy import evaluate_report
from .timeline import StateEngine


class AuditPipeline:
    def __init__(self, state_engine, rules):
        self.state_engine = state_engine
        self.index = state_engine.index
        self.rules = tuple(rules)
        self.document_ledger = semantic_ledger(state_engine.documents, self.index)

    @classmethod
    def from_dataset(cls, dataset_dir=None):
        reader = DatasetReader(dataset_dir)
        index = ingest_evidence(reader.root)
        extractor = LocalDocumentExtractor()
        documents = tuple(d for result in index.results if result.format in {".pdf", ".png"}
                          for d in extractor.extract(result, reader.root))
        structured = (*validated_document_observations(documents), *validated_ocr_observations(documents, index))
        if structured:
            reviewed = {o.source.evidence_id for o in structured if o.data_category == "SECURITY_AUDIT_LOG"}
            documents = tuple(replace(d, needs_review=False, coverage="structured_fields_extracted", issues=())
                              if d.source.evidence_id in reviewed else d for d in documents)
            results = tuple(replace(result, observations=(*result.observations,
                                  *(o for o in structured if o.source.evidence_id == result.source.evidence_id))) for result in index.results)
            activity = tuple(o for o in index.observations if o.source.source_kind == "ACTIVITY")
            index = EvidenceIndex(results, activity, index.identity_index)
        return cls(StateEngine(index, reader.root, CachedDocumentExtractor(documents, extractor.measurement)), reader.rules())

    def audit(self, request):
        intent = classify_request_intent(request)
        if intent.authorization == "OTHER_REQUEST":
            # No identity or per-case state investigation for non-deletion.
            result = AuditResult(request.case_id, Status.NOT_APPLICABLE, ())
            outcome = CaseOutcome(request.case_id, intent.authorization, result, None, (), (), ())
            validate_case(outcome, request, self.index)
            return outcome
        if intent.authorization != "AUTHORIZED":
            return CaseOutcome(request.case_id, intent.authorization, None, None, (), (),
                               (CoverageGap("ambiguous_request_intent:" + intent.reason),))
        report = self.state_engine.reconstruct_case(request)
        decisions = evaluate_report(report, self.rules)
        blockers = [CoverageGap(code, tuple(f.source for f in d.proofs), d.resource.resource_id)
                    for d in decisions for code in d.blockers]
        important = {"potentially_relevant_visual_semantics_require_review", "ambiguous_resource_ownership",
                     "conflicting_identity_anchor", "missing_sibling_snapshot_membership_not_absence_proof",
                     "identity_ambiguous_or_unresolved", "conflicting_record_classes"}
        important.add("unresolved_resource_owner")
        important.update({"explicit_reference_without_state_readback", "ambiguous_explicit_resource_reference"})
        blockers.extend(g for g in report.gaps if g.code in important or g.code.startswith("shared_identifier_not_used:"))
        blockers.extend(report.conflicts)
        if report.user_id is None:
            blockers.append(CoverageGap("identity_not_resolved"))
        if not report.resources:
            blockers.append(CoverageGap("no_subject_link_or_unindexed_semantics"))
        if re.search(r"\b(?:account|profile)\b|アカウント|계정|\b(?:cuenta|conta|compte)\b", request.request_text, re.I):
            if not any(r.data_category == "USER_PROFILE" and r.get("record_existence").supporting for r in report.resources):
                blockers.append(CoverageGap("requested_account_scope_not_established"))
        if not decisions:
            blockers.append(CoverageGap("no_grounded_policy_requirements"))
        # Stable deterministic diagnostics. A positive violation can establish
        # INCOMPLETE while other requirements still block final-run readiness.
        unique = {(g.code, g.resource_id, tuple((s.evidence_id, s.locator) for s in g.sources)): g for g in blockers}
        blockers = tuple(unique[k] for k in sorted(unique, key=repr))
        result, bindings = compile_plan(request, decisions, blockers)
        if result is None:
            return CaseOutcome(request.case_id, intent.authorization, None, report, decisions, (),
                               (*blockers, CoverageGap("insufficient_proof_for_responsible_status")))
        outcome = CaseOutcome(request.case_id, intent.authorization, result, report, decisions, bindings, blockers)
        try:
            order = execution_order(result, bindings)
            outcome = replace(outcome, execution_order=order)
            validate_case(outcome, request, self.index)
        except ValueError as exc:
            # Only named invariant failures reach diagnostics; no unvalidated row
            # is returned as a valid result, and no extra external status is made.
            return replace(outcome, result=None, blockers=(*blockers, CoverageGap("plan_validation:" + str(exc))))
        return outcome

    def audit_cases(self, requests):
        return tuple(self.audit(r) for r in sorted(requests, key=lambda r: r.case_id))


def coverage_diagnostics(outcomes):
    reasons = Counter(g.code for o in outcomes for g in o.blockers)
    reports = [o.report for o in outcomes if o.report is not None]
    unknown = [{"case_id": p.case_id, "reasons": sorted({code for r in p.resources if r.record_existence == "UNKNOWN"
               for code in (*r.gaps, *(t.reason for t in r.get("record_existence").rejected))} or {"no_admissible_existence_readback"})}
               for p in reports if any(r.record_existence == "UNKNOWN" for r in p.resources)]
    return {"cases": len(outcomes), "emitted_statuses": dict(sorted(Counter(o.result.deletion_status.value for o in outcomes if o.result).items())),
            "blocked_without_status": sum(o.result is None for o in outcomes),
            "cases_with_blockers": sum(bool(o.blockers) for o in outcomes),
            "cases_without_current_blockers": sum(o.result is not None and not o.blockers for o in outcomes),
            "blocker_counts": dict(sorted(reasons.items())),
            "factual_reports_after_intent_gate": len(reports),
            "cases_with_no_linked_resource": sum(not p.resources for p in reports),
            "cases_with_factual_conflicts": sum(bool(p.conflicts) for p in reports),
            "cases_with_unknown_existence": len(unknown),
            "unknown_existence_case_reasons": unknown,
            "state_report_gap_case_counts": dict(sorted(Counter(code for p in reports for code in {g.code for g in p.gaps}).items())),
            "case_blockers": [{"case_id": o.case_id, "codes": sorted({g.code for g in o.blockers})} for o in outcomes if o.blockers]}
