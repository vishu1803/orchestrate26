"""Scoped factual timelines. No policy, verdicts or action planning."""
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime
from pathlib import Path
import re
from typing import Sequence

from .documents import LocalDocumentExtractor, VisualEvidenceExtractor
from .evidence import EvidenceIndex, observation_key
from .models import (CoverageGap, DimensionState, IdentityResolution, MatchReason, MatchedObservation, Observation, Request, ResourceState,
                     ResourceStateReport, ScopeComparison, SelectionTrace, StateTransition)
from .state_facts import (BASE_DIMENSIONS, category, logical_system, normalize_facts,
                          physical_scope, temporal_rejection, utc)


def _select(dimension, facts, rejected):
    relevant = tuple(f for f in facts if f.dimension == dimension)
    if not relevant:
        return DimensionState(dimension, "UNKNOWN", "UNKNOWN", (), tuple(rejected))
    last = max(f.observed_at for f in relevant)
    latest = tuple(f for f in relevant if f.observed_at == last)
    values = {f.value for f in latest}
    if dimension.startswith(("direct_identifier:", "stable_reference:")):
        values = {(f.value, repr(f.raw_value)) for f in latest}
    conflicts = len(values) > 1
    old = tuple(SelectionTrace(f.source, "superseded_same_dimension_and_physical_scope", dimension)
                for f in relevant if f.observed_at < last)
    return DimensionState(dimension, "UNKNOWN" if conflicts else latest[0].value,
                          "CONFLICT" if conflicts else "OBSERVED", latest, (*rejected, *old))


def _resource(observations, audit_at, reasons=(), fact_cache=None):
    observations = tuple(sorted(observations, key=observation_key))
    anchor = observations[0]
    facts, rejected, gaps = [], [], set()
    for o in observations:
        rejection = temporal_rejection(o, audit_at)
        if rejection:
            rejected.append(SelectionTrace(o.source, rejection))
            gaps.add(rejection)
            continue
        normalized, issues = fact_cache[observation_key(o)] if fact_cache is not None else normalize_facts(o)
        facts.extend(normalized)
        gaps.update(i for i in issues if i != "claim_not_state_proof")
        if o.kind == "CLAIM":
            rejected.append(SelectionTrace(o.source, "claim_not_state_proof"))
        elif not normalized:
            rejected.append(SelectionTrace(o.source, "no_supported_state_fact"))
    dimensions = tuple(_select(d, facts, rejected) for d in sorted(set(BASE_DIMENSIONS) | {f.dimension for f in facts}))
    existence = next(d for d in dimensions if d.dimension == "record_existence")
    last_existence = max((f.observed_at for f in existence.supporting), default=None)
    updated = []
    for d in dimensions:
        if d.dimension.startswith(("direct_identifier:", "stable_reference:")) or d.dimension == "identifiability":
            if d.supporting and (existence.value == "ABSENT" or (last_existence and max(f.observed_at for f in d.supporting) < last_existence)):
                gaps.add("fields_not_observed_at_latest_readback")
                d = DimensionState(d.dimension, "UNKNOWN", "UNKNOWN", (),
                                   (*d.rejected, *(SelectionTrace(f.source, "field_not_current_readback", d.dimension) for f in d.supporting)))
        updated.append(d)
    transitions = []
    history = defaultdict(list)
    for f in facts:
        if f.dimension == "record_existence":
            history[f.observed_at].append(f)
    previous = ()
    for time in sorted(history):
        current = tuple(history[time])
        if {f.value for f in previous} == {"ABSENT"} and {f.value for f in current} == {"PRESENT"}:
            transitions.append(StateTransition("OBSERVED_REAPPEARANCE", previous, current))
        previous = current
    conflicts = any(d.epistemic == "CONFLICT" for d in updated)
    classes = {category(o) for o in observations if category(o) and o.kind in {"READBACK", "SNAPSHOT"}
               and temporal_rejection(o, audit_at) is None}
    record_class = next(iter(classes)) if len(classes) == 1 else ""
    if len(classes) > 1:
        gaps.add("conflicting_record_classes")
    if not logical_system(anchor):
        gaps.add("unspecified_logical_system")
    if not record_class:
        gaps.add("unspecified_record_class")
    return ResourceState(logical_system(anchor), anchor.resource_id, record_class, utc(audit_at),
                         observations, "CONFLICT" if conflicts else "UNKNOWN" if existence.value == "UNKNOWN" else None,
                         physical_scope(anchor), tuple(updated), tuple(reasons), tuple(sorted(gaps)), tuple(transitions))


def reconstruct(observations: Sequence[Observation], audit_at: datetime) -> tuple[ResourceState, ...]:
    """Existing scaffold API: retain scopes and explicitly reject inadmissible facts."""
    utc(audit_at)
    grouped = defaultdict(list)
    for o in observations:
        if o.resource_id:
            grouped[(logical_system(o), o.resource_id, physical_scope(o))].append(o)
    return tuple(_resource(grouped[k], audit_at) for k in sorted(grouped))


class StateEngine:
    """One shared evidence index and document extraction pass per batch.

    Resource expansion requires an eligible identity-grounded anchor in the same
    logical service. Conflicting ownership is rejected. Unspecified physical
    scopes remain separate; a service readback never clears a replica.
    """
    def __init__(self, evidence_index: EvidenceIndex, dataset_root: Path | None = None,
                 document_extractor: VisualEvidenceExtractor | None = None):
        self.index = evidence_index
        self.identity_index = evidence_index.identity_index
        if self.identity_index is None:
            raise ValueError("identity_index_required")
        self.by_resource = defaultdict(list)
        self.fact_cache = {}
        self.class_counts = Counter()
        self.sql_families = defaultdict(lambda: defaultdict(list))
        for o in evidence_index.observations:
            scope = physical_scope(o)
            if scope.table and scope.topology:
                family = re.sub(r"_(?:primary|read_replica|reporting_replica|failover_replica|replica_[a-z_]+)$", "", scope.table)
                self.sql_families[(o.source.evidence_id, family)][scope.table].append(o)
            if o.resource_id:
                self.by_resource[(logical_system(o), o.resource_id)].append(o)
            if o.observed_at is not None:
                try:
                    self.fact_cache[observation_key(o)] = normalize_facts(o)
                except ValueError:
                    self.fact_cache[observation_key(o)] = ((), ("invalid_observation_clock",))
            else:
                self.fact_cache[observation_key(o)] = ((), ("missing_observation_clock",))
            if category(o) and o.kind in {"READBACK", "SNAPSHOT"}:
                self.class_counts[category(o)] += 1
        extractor = document_extractor or LocalDocumentExtractor()
        self.documents = tuple(d for r in evidence_index.results if r.format in {".png", ".pdf"}
                               for d in extractor.extract(r, dataset_root))
        self.extraction_measurement = dict(getattr(extractor, "measurement", {}))
        self.document_index = defaultdict(list)
        for d in self.documents:
            for i in d.candidates:
                self.document_index[(i.field, i.normalized_value)].append(d)

    def _ownership_conflict(self, o, user_id, cutoff):
        for i in o.identifiers:
            if i.field == "user_id" and i.normalized_value != user_id:
                return True
            if i.field in {"email", "phone", "email_hash"}:
                owners = {m.user_id for m in self.identity_index.lookup_identifier(i.field, i.raw_value, cutoff)}
                if owners and owners != {user_id}:
                    return True
            if i.field == "opaque_reference":
                owners = {m.user_id for field in ("email_hash", "phone")
                          for m in self.identity_index.lookup_identifier(field, i.raw_value, cutoff)}
                if owners and owners != {user_id}:
                    return True
        return False

    def reconstruct_case(self, case: Request, identity: IdentityResolution | None = None,
                         activity_index: Sequence[Observation] | None = None) -> ResourceStateReport:
        cutoff = utc(case.audit_at)
        resolution = self.identity_index.resolve_request(case.email, cutoff)
        if identity is not None and (identity.user_id != resolution.user_id or identity.audit_at != cutoff):
            raise ValueError("identity_cutoff_or_subject_mismatch")
        linked = self.index.find_subject_evidence(resolution, cutoff, include_untimed=True)
        if linked.user_id is None:
            return ResourceStateReport(case.case_id, None, cutoff, (), (), (),
                                       (CoverageGap("identity_ambiguous_or_unresolved"),), (), (), ())
        matches = {observation_key(m.observation): m for m in linked.matches}
        anchors = defaultdict(list)
        explanations, gaps = [], [CoverageGap(code) for code in linked.issues]
        # Two bounded hops over explicit per-record source/target references.
        # A reference discovers candidates, never proves existence or absence.
        for hop in range(2):
            discovered = {}
            for match in tuple(matches.values()):
                parent = match.observation
                if temporal_rejection(parent, cutoff) is not None or parent.kind not in {"READBACK", "SNAPSHOT"}:
                    continue
                for payload in (parent.attributes, parent.attributes.get("document", {}), parent.attributes.get("profile", {})):
                    if not hasattr(payload, "get"):
                        continue
                    for field in ("source_resource_id", "target_resource_id"):
                        target = payload.get(field)
                        if not isinstance(target, str) or not target:
                            continue
                        incoming = self.index.get_references(field, target, cutoff)
                        if any(self._ownership_conflict(o, linked.user_id, cutoff)
                               or any(i.field in {"email", "phone", "email_hash"} and not self.identity_index.lookup_identifier(i.field, i.raw_value, cutoff)
                                      for i in o.identifiers) for o in incoming):
                            gaps.append(CoverageGap("ambiguous_explicit_resource_reference", (parent.source,), target))
                            continue
                        candidates = [o for o in self.index.get_observations(target, cutoff)
                                      if o.kind in {"READBACK", "SNAPSHOT"} and not self._ownership_conflict(o, linked.user_id, cutoff)
                                      and not any(i.field in {"email", "phone", "email_hash"}
                                                  and not self.identity_index.lookup_identifier(i.field, i.raw_value, cutoff) for i in o.identifiers)]
                        system_hint = payload.get("source_system" if field == "source_resource_id" else "target_system")
                        if isinstance(system_hint, str) and system_hint:
                            candidates = [o for o in candidates if logical_system(o) == system_hint]
                        elif len({logical_system(o) for o in candidates}) > 1:
                            gaps.append(CoverageGap("ambiguous_explicit_resource_reference", (parent.source,), target))
                            candidates = []
                        if not candidates:
                            gaps.append(CoverageGap("explicit_reference_without_state_readback", (parent.source,), target))
                        for o in candidates:
                            key = observation_key(o)
                            if key not in matches:
                                discovered[key] = MatchedObservation(o, (MatchReason(field, parent.source, parent.source.locator + "/" + field),))
            if not discovered:
                break
            matches.update(discovered)
        for m in matches.values():
            if self._ownership_conflict(m.observation, linked.user_id, cutoff):
                explanations.append(SelectionTrace(m.observation.source, "conflicting_identity_anchor_rejected"))
                gaps.append(CoverageGap("conflicting_identity_anchor", (m.observation.source,)))
                continue
            if m.observation.resource_id:
                anchors[(logical_system(m.observation), m.observation.resource_id)].append(m)
        grouped, reasons, activity = defaultdict(list), defaultdict(list), {}
        for key, linked_anchors in sorted(anchors.items()):
            competing = tuple(o for o in self.by_resource[key] if temporal_rejection(o, cutoff) is None
                              and self._ownership_conflict(o, linked.user_id, cutoff))
            if competing:
                gaps.append(CoverageGap("ambiguous_resource_ownership", tuple(o.source for o in competing), key[1]))
            for o in self.by_resource[key]:
                rejection = temporal_rejection(o, cutoff)
                if rejection in {"captured_after_cutoff", "embedded_clock_after_cutoff", "observed_after_cutoff"}:
                    explanations.append(SelectionTrace(o.source, rejection))
                    continue
                if self._ownership_conflict(o, linked.user_id, cutoff):
                    explanations.append(SelectionTrace(o.source, "resource_ownership_conflict"))
                    continue
                if competing and observation_key(o) not in matches:
                    explanations.append(SelectionTrace(o.source, "resource_only_link_ambiguous"))
                    continue
                if observation_key(o) not in matches and any(i.field in {"email", "phone", "email_hash"}
                         and not self.identity_index.lookup_identifier(i.field, i.raw_value, cutoff) for i in o.identifiers):
                    # A colliding resource ID cannot turn a different, unlinked
                    # visible owner into an undocumented historical alias.
                    explanations.append(SelectionTrace(o.source, "resource_only_owner_not_established"))
                    gaps.append(CoverageGap("unresolved_resource_owner", (o.source,), key[1]))
                    continue
                scope_key = key + (physical_scope(o),)
                grouped[scope_key].append(o)
                reasons[scope_key].extend(matches[observation_key(o)].reasons if observation_key(o) in matches else
                                          (MatchReason("resource_id", linked_anchors[0].observation.source,
                                                       linked_anchors[0].observation.source.locator),))
                if o.kind == "CLAIM" and temporal_rejection(o, cutoff) is None:
                    activity[observation_key(o)] = o
            for o in self.index.get_activity(key[1], cutoff):
                if logical_system(o) == key[0] or o.attributes.get("target_system") == key[0]:
                    activity[observation_key(o)] = o
        if activity_index is not None:
            # Optional callers may supply only already-indexed activity claims.
            allowed = {observation_key(o) for o in self.index.observations if o.kind == "CLAIM"}
            for o in activity_index:
                if observation_key(o) not in allowed or o.kind != "CLAIM":
                    raise ValueError("activity_must_be_indexed_claim")
        resources = tuple(_resource(grouped[k], cutoff, reasons[k], self.fact_cache) for k in sorted(grouped))
        enriched = []
        for r in resources:
            present = r.get("record_existence").supporting if r.record_existence == "PRESENT" else ()
            prior_claims = tuple(o for o in activity.values()
                                 if o.attributes.get("event_type") == "DELETE_RECORD"
                                 and o.resource_id == r.resource_id
                                 and (o.system_id == r.system_id or o.attributes.get("target_system") == r.system_id)
                                 and present and o.observed_at < min(f.observed_at for f in present))
            if prior_claims:
                # Presence is proved; prior successful absence and sync causation
                # are not. Claims stay explicitly separate from observed facts.
                transition = StateTransition("PRESENCE_AFTER_DELETE_CLAIM", (), present, prior_claims)
                r = replace(r, recreation=(*r.recreation, transition))
            enriched.append(r)
        resources = tuple(enriched)
        for r in resources:
            gaps.extend(CoverageGap(code, tuple(o.source for o in r.observations), r.resource_id) for code in r.gaps)
            explanations.extend(t for d in r.dimensions for t in d.rejected if not t.dimension)
        # Exact tokens only. Unassigned documents stay visible globally, without
        # assigning every screenshot to every unrelated subject.
        docs = {}
        alias_keys = {("user_id", linked.user_id)}
        for a in resolution.aliases:
            if a.field == "email" and a.normalized_value and {m.user_id for m in self.identity_index.lookup_identifier(a.field, a.value, cutoff)} == {linked.user_id}:
                alias_keys.add((a.field, a.normalized_value))
        alias_keys.update(("resource_id", key[1]) for key in anchors)
        for m in linked.matches:
            link = m.observation.attributes.get("identity_link")
            if link and isinstance(link.get("business_reference"), str):
                alias_keys.add(("business_reference", link["business_reference"]))
        for key in sorted(alias_keys):
            for d in self.document_index.get(key, ()):
                if d.source.available_at <= cutoff and d.needs_review:
                    docs[observation_key(d)] = d
        for d in docs.values():
            gaps.append(CoverageGap("potentially_relevant_visual_semantics_require_review", (d.source,)))
        conflicts = tuple(CoverageGap("same_time_conflicting_" + d.dimension, tuple(f.source for f in d.supporting), r.resource_id)
                          for r in resources for d in r.dimensions if d.epistemic == "CONFLICT")
        comparisons = []
        logical = defaultdict(list)
        for r in resources:
            logical[(r.system_id, r.resource_id)].append(r)
        for key, scoped in sorted(logical.items()):
            if {r.record_existence for r in scoped} >= {"PRESENT", "ABSENT"}:
                comparisons.append(ScopeComparison(*key, "SCOPED_STATE_DIVERGENCE", tuple(r.scope for r in scoped),
                                                   tuple(f.source for r in scoped for f in r.get("record_existence").supporting)))
            for (source_id, family), tables in sorted(self.sql_families.items()):
                relevant = [o for r in scoped for o in r.observations if o.source.evidence_id == source_id and o.context.get("table") in tables]
                if not relevant:
                    continue
                for table, rows in sorted(tables.items()):
                    eligible_rows = [o for o in rows if temporal_rejection(o, cutoff) is None]
                    if eligible_rows and not any(o.resource_id == key[1] for o in eligible_rows):
                        # This is a difference in observed table membership only.
                        # It NEVER creates an ABSENT resource or complete-scope claim.
                        sources = (relevant[0].source, eligible_rows[0].source)
                        comparisons.append(ScopeComparison(*key, "SNAPSHOT_MEMBERSHIP_DIVERGENCE_NOT_GLOBAL_ABSENCE",
                                                           (physical_scope(relevant[0]), physical_scope(eligible_rows[0])), sources))
                        gaps.append(CoverageGap("missing_sibling_snapshot_membership_not_absence_proof", sources, key[1]))
        if not resources:
            gaps.append(CoverageGap("no_linked_state_observations"))
        return ResourceStateReport(case.case_id, linked.user_id, cutoff, resolution.aliases, resources,
                                   conflicts, tuple(sorted(gaps, key=lambda g: (g.code, g.resource_id or "", tuple((s.evidence_id, s.locator) for s in g.sources)))),
                                   tuple(comparisons), tuple(activity[k] for k in sorted(activity)),
                                   tuple(sorted(set(explanations), key=lambda t: (t.source.evidence_id, t.source.locator, t.reason))))

    def reconstruct_cases(self, cases: Sequence[Request]) -> tuple[ResourceStateReport, ...]:
        return tuple(self.reconstruct_case(c) for c in sorted(cases, key=lambda c: c.case_id))


def reconstruct_case(case: Request, identity: IdentityResolution, evidence_index: EvidenceIndex,
                     activity_index: Sequence[Observation] | None = None) -> ResourceStateReport:
    """One-shot compatibility API; batches should reuse StateEngine."""
    return StateEngine(evidence_index).reconstruct_case(case, identity, activity_index)


def reconstruct_cases(cases: Sequence[Request], evidence_index: EvidenceIndex, **kwargs) -> tuple[ResourceStateReport, ...]:
    return StateEngine(evidence_index, **kwargs).reconstruct_cases(cases)
