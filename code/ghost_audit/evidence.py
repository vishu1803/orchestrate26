"""Deterministic provenance index and cutoff-aware candidate queries, never verdicts."""
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import re
from pathlib import Path
from typing import Sequence

from .identity import IdentityIndex
from .identity import normalize_identifier
from .io import DatasetReader, InputError, read_contract_csv, validate_manifest_path
from .models import (EvidenceFile, ExtractionResult, ExtractionStatus, IdentityResolution,
                     MatchedObservation, MatchReason, Observation, ResolutionStatus,
                     SourceRef, Subject, SubjectEvidence, SystemActivity)
from .normalization import freeze, make_observation
from .parsers import parse_evidence


def _utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Point-in-time query requires an aware cutoff")
    return value.astimezone(timezone.utc)


def observation_key(observation):
    return observation.source.evidence_id, observation.source.locator


def eligible(observation, as_of):
    if as_of is None:
        return True
    cutoff = _utc(as_of)
    if observation.source.available_at > cutoff:
        return False
    if any(t.value is None or t.value > cutoff for t in observation.timestamps):
        return False
    if observation.observed_at is None:
        # Available documents/metadata remain candidates, not timed state proof.
        return observation.kind in {"RAW", "METADATA"}
    return observation.observed_at <= cutoff


class EvidenceSourceError(ValueError):
    """A failed source query is not an empty resource readback."""

    def __init__(self, result):
        self.result = result
        super().__init__(f"{result.source.evidence_id}: {result.status.value}")


class EvidenceIndex:
    """Immutable observation tuples with resource/source/identifier/trace/time indexes."""

    def __init__(self, results: Sequence[ExtractionResult], activity: Sequence[Observation] = (),
                 identity_index: IdentityIndex | None = None):
        self.results = tuple(sorted(results, key=lambda r: r.source.evidence_id))
        if len({r.source.evidence_id for r in self.results}) != len(self.results):
            raise ValueError("duplicate_source_ids")
        self.identity_index = identity_index
        self.observations = tuple(sorted((o for r in results for o in r.observations), key=observation_key)) + tuple(sorted(activity, key=observation_key))
        if len({observation_key(o) for o in self.observations}) != len(self.observations):
            raise ValueError("duplicate_observation_locations")
        self._inverted = defaultdict(list)
        for number, observation in enumerate(self.observations):
            keys = [("source", observation.source.evidence_id)]
            if observation.resource_id:
                keys.append(("resource", observation.resource_id))
            if observation.system_id:
                keys.append(("system", observation.system_id))
            target = observation.attributes.get("target_system")
            if isinstance(target, str) and target:
                keys.append(("system", target))
            if observation.trace_id:
                keys.extend([("trace", observation.trace_id),
                             ("scoped_trace", (observation.source.evidence_id, observation.system_id, observation.trace_id))])
            for identifier in observation.identifiers:
                keys.extend([("identifier", (identifier.field, identifier.normalized_value)),
                             ("exact_identifier", (identifier.field, identifier.raw_value))])
            for payload in (observation.attributes, observation.attributes.get("document", {}), observation.attributes.get("profile", {})):
                if hasattr(payload, "get"):
                    for field in ("source_resource_id", "target_resource_id", "lookup_key", "subject_key", "customer_reference", "subject_reference"):
                        value = payload.get(field)
                        if isinstance(value, str) and value:
                            keys.append(("typed_reference", (field, value)))
            for key in set(keys):
                self._inverted[key].append(number)
        timed = sorted((max([o.source.available_at] + [t.value for t in o.timestamps if t.value] + ([o.observed_at] if o.observed_at else [])), n)
                       for n, o in enumerate(self.observations))
        self._times = tuple(t for t, _ in timed)
        self._time_numbers = tuple(n for _, n in timed)

    def _query(self, key, as_of=None):
        return tuple(sorted((self.observations[n] for n in self._inverted.get(key, ()) if eligible(self.observations[n], as_of)), key=observation_key))

    def get_observations(self, resource_id, as_of=None):
        return self._query(("resource", resource_id), as_of)

    def get_by_source(self, source_id, as_of=None):
        result = next((r for r in self.results if r.source.evidence_id == source_id), None)
        if result and result.status in {ExtractionStatus.FAILED, ExtractionStatus.UNSUPPORTED}:
            raise EvidenceSourceError(result)
        return self._query(("source", source_id), as_of)

    def get_by_system(self, system_id, as_of=None):
        return self._query(("system", system_id), as_of)

    def get_by_trace(self, trace_id, as_of=None):
        return self._query(("trace", trace_id), as_of)

    def get_references(self, kind: str, value: str, as_of=None) -> tuple[Observation, ...]:
        """Typed exact inverted references; original values/provenance stay intact."""
        if kind in {"email", "phone", "email_hash"}:
            return self._query(("identifier", (kind, normalize_identifier(kind, value))), as_of)
        if kind == "user_id":
            return self._query(("identifier", (kind, value)), as_of)
        if kind in {"resource_id", "system_id", "trace_id"}:
            return self._query(({"resource_id":"resource", "system_id":"system", "trace_id":"trace"}[kind], value), as_of)
        if kind not in {"source_resource_id", "target_resource_id", "lookup_key", "subject_key", "customer_reference", "subject_reference"}:
            raise ValueError("unsupported_typed_reference")
        return self._query(("typed_reference", (kind, value)), as_of)

    def get_activity(self, resource_id, as_of=None):
        return tuple(o for o in self.get_observations(resource_id, as_of) if o.source.source_kind == "ACTIVITY")

    def observations_as_of(self, as_of):
        prefix = bisect_right(self._times, _utc(as_of))
        return tuple(sorted((self.observations[n] for n in self._time_numbers[:prefix] if eligible(self.observations[n], as_of)), key=observation_key))

    def source_result(self, source_id):
        return next(result for result in self.results if result.source.evidence_id == source_id)

    def find_subject_evidence(self, resolution: IdentityResolution, as_of, *, include_untimed=False) -> SubjectEvidence:
        if self.identity_index is None:
            return SubjectEvidence(None, (), ("identity_index_required_for_collision_checks",))
        cutoff = _utc(as_of)
        def candidate(observation):
            if eligible(observation, cutoff):
                return True
            # Phase 3 can display known-available malformed/untimed candidates as
            # UNKNOWN. Never permit a known future clock or future capture here.
            return (include_untimed and observation.source.available_at <= cutoff
                    and not any(t.value and t.value > cutoff for t in observation.timestamps)
                    and (observation.observed_at is None or observation.observed_at <= cutoff))
        current = self.identity_index.resolve_request(resolution.normalized_email, cutoff)
        if current.status != ResolutionStatus.RESOLVED or current.user_id != resolution.user_id:
            return SubjectEvidence(None, (), ("identity_not_unique_at_query_cutoff",))
        user_id = current.user_id
        # Call actual Phase 1 APIs: don't use aliases captured at a later cutoff.
        identity_at = self.identity_index.identity_at(user_id, cutoff)
        aliases = self.identity_index.aliases_for(user_id, cutoff)
        candidate_numbers = set(self._inverted.get(("identifier", ("user_id", user_id)), ()))
        safe_aliases, issues = {}, set()
        for alias in aliases:
            if alias.field not in {"email", "phone", "email_hash"} or not alias.normalized_value:
                continue
            owners = {m.user_id for m in self.identity_index.lookup_identifier(alias.field, alias.value, cutoff)}
            if owners == {user_id}:
                key = alias.field, alias.normalized_value
                safe_aliases.setdefault(key, []).append(alias)
                candidate_numbers.update(self._inverted.get(("identifier", key), ()))
                if alias.field in {"email_hash", "phone"}:
                    candidate_numbers.update(self._inverted.get(("identifier", ("opaque_reference", alias.normalized_value)), ()))
            else:
                issues.add("shared_identifier_not_used:" + alias.field)
        matched = {}
        def alias_sources(identifier):
            if identifier.field == "opaque_reference":
                return tuple(a for (field, value), sources in safe_aliases.items()
                             if field in {"email_hash", "phone"} and value == identifier.normalized_value for a in sources)
            return tuple(safe_aliases.get((identifier.field, identifier.normalized_value), ()))
        for number in sorted(candidate_numbers):
            observation = self.observations[number]
            if not candidate(observation):
                continue
            explicit_users = {i.normalized_value for i in observation.identifiers if i.field == "user_id"}
            if explicit_users and explicit_users != {user_id}:
                issues.add("conflicting_explicit_subject_reference")
                continue
            reasons = []
            for identifier in observation.identifiers:
                key = identifier.field, identifier.normalized_value
                supporting_aliases = alias_sources(identifier)
                if key == ("user_id", user_id) or supporting_aliases:
                    reasons.append(MatchReason(identifier.field, observation.source, identifier.locator,
                                               supporting_aliases))
            if reasons:
                matched[number] = reasons
        # Correlate only same-source/same-service trace observations, keeping both
        # original lines, clocks and grounding pointer; never copy a later identity
        # into an earlier standalone observation.
        for number, reasons in tuple(matched.items()):
            anchor = self.observations[number]
            if anchor.trace_id:
                scope = anchor.source.evidence_id, anchor.system_id, anchor.trace_id
                trace_numbers = tuple(n for n in self._inverted.get(("scoped_trace", scope), ()) if candidate(self.observations[n])
                                      and all(not anchor.attributes.get(k) or not self.observations[n].attributes.get(k)
                                              or anchor.attributes[k] == self.observations[n].attributes[k]
                                              for k in ("region", "shard")))
                # A reused trace with competing subject anchors cannot attribute
                # an identifier-free completion to either person. Directly linked
                # observations remain available; only the ambiguous join fails.
                conflicting = False
                for n in trace_numbers:
                    trace_observation = self.observations[n]
                    trace_users = {i.normalized_value for i in trace_observation.identifiers if i.field == "user_id"}
                    if any(i.field == "user_id" and i.normalized_value != user_id for i in trace_observation.identifiers):
                        conflicting = True
                    if trace_users != {user_id} and any(i.field != "user_id" and not alias_sources(i) for i in trace_observation.identifiers):
                        conflicting = True
                if conflicting:
                    issues.add("trace_identifier_conflict")
                    continue
                for other in trace_numbers:
                    observation = self.observations[other]
                    users = {i.normalized_value for i in observation.identifiers if i.field == "user_id"}
                    contradictory = any((i.field == "user_id" and i.normalized_value != user_id)
                                        or (i.field != "user_id" and not alias_sources(i))
                                        for i in observation.identifiers)
                    if contradictory and users != {user_id}:
                        issues.add("trace_identifier_conflict")
                        continue
                    if (candidate(observation) and (not users or users == {user_id}) and anchor.observed_at is not None
                            and observation.observed_at is not None and observation.observed_at >= anchor.observed_at):
                        matched.setdefault(other, []).append(MatchReason("trace_id", anchor.source, anchor.source.locator))
        if any(f.uncertainties for f in identity_at.fields):
            issues.add("identity_has_temporal_uncertainty")
        return SubjectEvidence(user_id, tuple(MatchedObservation(self.observations[n], tuple(reasons))
                                             for n, reasons in sorted(matched.items(), key=lambda item: observation_key(self.observations[item[0]]))), tuple(sorted(issues)))

    def coverage_report(self):
        by_format = {}
        for result in self.results:
            item = by_format.setdefault(result.format, {"files": 0, "observations": 0, "statuses": {}, "issues": 0, "deferred_visual_files": 0})
            item["files"] += 1; item["observations"] += len(result.observations)
            item["statuses"][result.status.value] = item["statuses"].get(result.status.value, 0) + 1
            item["issues"] += len(result.issues)
            item["deferred_visual_files"] += any(i.severity == "DEFERRED" for i in result.issues)
        return {"manifest_files": len(self.results), "formats": dict(sorted(by_format.items())),
                "activity_observations": sum(o.source.source_kind == "ACTIVITY" for o in self.observations),
                "total_observations": len(self.observations),
                "issue_codes": dict(sorted(Counter(i.code for r in self.results for i in r.issues).items())),
                "files": [{"file_id": r.source.evidence_id, "format": r.format, "status": r.status.value,
                           "observations": len(r.observations), "issues": [i.code for i in r.issues]} for r in self.results]}


def ingest_evidence(dataset_root, manifest: Sequence[EvidenceFile] | None = None,
                    identity_index: IdentityIndex | None = None) -> EvidenceIndex:
    reader = DatasetReader(dataset_root)
    entries = tuple(manifest) if manifest is not None else reader.manifest()
    if len({entry.file_id for entry in entries}) != len(entries):
        raise ValueError("duplicate_manifest_file_ids")
    listed = {validate_manifest_path(reader.root, e.file_path) for e in entries}
    actual = {p.resolve() for p in (reader.root / "evidence").rglob("*") if p.is_file()}
    if listed != actual or len(listed) != len(entries):
        raise ValueError("manifest_asset_inventory_mismatch")
    results = []
    raw_manifest = {row["file_id"]: row for row in read_contract_csv(reader.root / "evidence_files.csv")}
    for entry in sorted(entries, key=lambda e: e.file_id):
        path = validate_manifest_path(reader.root, entry.file_path)
        source = SourceRef(entry.file_id, entry.captured_at, "", entry.file_path, entry.origin,
                           captured_at_raw=raw_manifest.get(entry.file_id, {}).get("captured_at"),
                           manifest_locator=f"evidence_files.csv:row:{entry.lineage.row_number}")
        results.append(parse_evidence(path, source))
    activity_path = reader.root / "system_activity.csv"
    digest = hashlib.sha256(activity_path.read_bytes()).hexdigest()
    activities = []
    raw_activity = {row["activity_id"]: row for row in read_contract_csv(activity_path)}
    for row in reader.activity():
        raw = raw_activity[row.activity_id]
        source = SourceRef(row.activity_id, row.event_time, f"row:{row.lineage.row_number}", "system_activity.csv", row.source_system, digest, "ACTIVITY",
                           raw["event_time"], f"system_activity.csv:row:{row.lineage.row_number}")
        derived = {}
        if row.event_type == "LINK_RESOURCE_IDENTITY":
            link = re.fullmatch(r"Data catalog linked (\S+) \(([^()]*)\) to (\S+) and (user_[A-Za-z0-9_-]+)\.", row.details)
            attachment = re.fullmatch(r"Attachment catalog confirmed (\S+) \(([^()]*)\) belongs only to (\S+) and (user_[A-Za-z0-9_-]+); no other subject is linked\.", row.details)
            match = link or attachment
            if match and match[1] == row.resource_id:
                derived["identity_link"] = {"resource_id": match[1], "business_reference": match[2],
                                             "email": match[3], "user_id": match[4]}
        observation, errors = make_observation({**raw, "system_id": row.source_system, **derived}, source, kind="CLAIM")
        observation = replace(observation, raw_fields=freeze(raw))
        activities.append(observation)
    if identity_index is None:
        identity_index = IdentityIndex(reader.identities(), reader.history())
    return EvidenceIndex(results, activities, identity_index)


def link_observations(subject: Subject, observations: Sequence[Observation]) -> tuple[Observation, ...]:
    """Scaffold wrapper: stable-reference-only; alias matching needs collision-aware index API."""
    return tuple(sorted((o for o in observations if any(i.field == "user_id" and i.normalized_value == subject.user_id for i in o.identifiers)), key=observation_key))
