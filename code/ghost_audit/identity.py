"""Exact, provenance-preserving identity history; never decides deletion status."""
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from typing import Sequence

from .io import IDENTITY_FIELDS, InputError
from .models import (Identifier, IdentityAt, IdentityChange, IdentityField, IdentityMatch,
                     IdentityResolution, IdentitySnapshot, Request, ResolutionStatus, Subject)

NORMALIZATION = {"email": "trim+unicode_casefold", "phone": "trim_only",
                 "email_hash": "exact_nonblank", "name": "trim_only"}


def normalize_identifier(field: str, raw: str) -> str | None:
    """No plus/dot rewrites, phone country guesses, fuzzy names or hash derivation."""
    if field not in IDENTITY_FIELDS:
        raise ValueError("Unsupported identity field")
    if not raw.strip():
        return None
    if field == "email":
        return raw.strip().casefold()
    return raw if field == "email_hash" else raw.strip()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Identity APIs require timezone-aware cutoffs/timestamps")
    return value.astimezone(timezone.utc)


def _sort_fact(fact: Identifier):
    return fact.field, fact.available_at, fact.source_id, fact.role, fact.value


class IdentityIndex:
    """Build field timelines and exact/normalized ownership indexes once per input.

    Event time is the audit row's availability time (no separate capture is supplied).
    Future rows cannot establish earlier values, including their old_value. Historical
    ownership stays a search association after an alias expires; reused aliases are
    therefore ambiguous. Current field state and historical aliases are separate APIs.
    """

    def __init__(self, identities: Sequence[IdentitySnapshot], history: Sequence[IdentityChange]):
        self._users = {}
        grouped = defaultdict(list)
        exact, normalized = defaultdict(list), defaultdict(list)

        def add(user_id, field, value, time, lineage, role):
            time = _utc(time)
            fact = Identifier(field, value, time if role != "OLD" else None,
                              time if role == "OLD" else None, lineage.source_id,
                              normalize_identifier(field, value), NORMALIZATION[field], time,
                              lineage.source_file, lineage.row_number, role)
            grouped[(user_id, field)].append(fact)
            if fact.normalized_value is not None:
                match = IdentityMatch(user_id, fact)
                exact[(field, value)].append(match)
                normalized[(field, fact.normalized_value)].append(match)

        for row in identities:
            if row.user_id in self._users:
                raise InputError(row.lineage.source_file, row.lineage.row_number, "user_id", "duplicate_required_id")
            self._users[row.user_id] = row
            for field in IDENTITY_FIELDS:
                add(row.user_id, field, getattr(row, field), row.updated_at, row.lineage, "SNAPSHOT")
        seen = set()
        for row in history:
            if row.audit_id in seen:
                raise InputError(row.lineage.source_file, row.lineage.row_number, "audit_id", "duplicate_required_id")
            seen.add(row.audit_id)
            if row.user_id not in self._users:
                raise InputError(row.lineage.source_file, row.lineage.row_number, "user_id", "unknown_user_reference")
            if row.field_name not in IDENTITY_FIELDS:
                raise InputError(row.lineage.source_file, row.lineage.row_number, "field_name", "unsupported_identity_field")
            add(row.user_id, row.field_name, row.old_value, row.event_time, row.lineage, "OLD")
            add(row.user_id, row.field_name, row.new_value, row.event_time, row.lineage, "NEW")

        self._groups, self._times = {}, {}
        for key, facts in grouped.items():
            by_time = defaultdict(list)
            for fact in facts:
                by_time[fact.available_at].append(fact)
            self._times[key] = tuple(sorted(by_time))
            self._groups[key] = tuple(tuple(sorted(by_time[t], key=_sort_fact)) for t in self._times[key])
        self._exact = self._freeze_reverse(exact)
        self._normalized = self._freeze_reverse(normalized)
        self._aliases_cache, self._identity_cache = {}, {}

    @staticmethod
    def _freeze_reverse(index):
        result = {}
        for key, matches in index.items():
            ordered = tuple(sorted(matches, key=lambda m: (m.identifier.available_at, m.user_id, _sort_fact(m.identifier))))
            result[key] = (tuple(m.identifier.available_at for m in ordered), ordered)
        return result

    def _eligible_groups(self, user_id: str, field: str, cutoff: datetime):
        if user_id not in self._users:
            raise KeyError("Unknown stable user ID")
        key = (user_id, field)
        return self._groups[key][:bisect_right(self._times[key], cutoff)]

    def aliases_for(self, user_id: str, audit_at: datetime) -> tuple[Identifier, ...]:
        """All eligible raw alias observations; intervals close only with eligible evidence.

        Interval starts/ends are supported change boundaries, not a claim of evidence
        availability before available_at. Unknown boundaries remain None.
        """
        cutoff = _utc(audit_at)
        cache_key = user_id, cutoff
        if cache_key not in self._aliases_cache:
            result = []
            for field in IDENTITY_FIELDS:
                groups = self._eligible_groups(user_id, field, cutoff)
                previous = ()
                for number, group in enumerate(groups):
                    following = groups[number + 1] if number + 1 < len(groups) else ()
                    for fact in group:
                        start, end = fact.valid_from, fact.valid_until
                        if fact.role == "OLD":
                            prior_values = {f.normalized_value for f in previous if f.role != "OLD"}
                            if prior_values == {fact.normalized_value}:
                                start = previous[0].available_at
                        else:
                            old_values = {f.normalized_value for f in following if f.role == "OLD"}
                            if old_values == {fact.normalized_value}:
                                end = following[0].available_at
                        result.append(replace(fact, valid_from=start, valid_until=end))
                    previous = group
            self._aliases_cache[cache_key] = tuple(sorted(result, key=_sort_fact))
        return self._aliases_cache[cache_key]

    def identity_at(self, user_id: str, audit_at: datetime) -> IdentityAt:
        """Current per-field state from eligible observations, with explicit gaps/conflicts."""
        cutoff = _utc(audit_at)
        cache_key = user_id, cutoff
        if cache_key not in self._identity_cache:
            fields = []
            aliases = self.aliases_for(user_id, cutoff)
            for field in IDENTITY_FIELDS:
                groups = self._eligible_groups(user_id, field, cutoff)
                reasons, previous_pairs = set(), set()
                current_values, provenance = None, ()
                for group in groups:
                    old_values = {f.normalized_value for f in group if f.role == "OLD"}
                    new_values = {f.normalized_value for f in group if f.role == "NEW"}
                    pairs = {(a, b) for a in old_values for b in new_values}
                    repeated = bool(pairs) and pairs <= previous_pairs and new_values == current_values
                    if current_values is not None and old_values and old_values != current_values and not repeated:
                        reasons.add("DISCONTINUOUS_HISTORY")
                    if len(old_values) > 1 or len(new_values) > 1:
                        reasons.add("CONFLICTING_CHANGES")
                    readbacks = tuple(f for f in group if f.role != "OLD")
                    observed_values = {f.normalized_value for f in readbacks}
                    if any(f.role == "SNAPSHOT" for f in readbacks) and current_values is not None and not old_values and observed_values != current_values:
                        reasons.add("SNAPSHOT_HISTORY_DISAGREEMENT")
                    current_values = observed_values
                    if len(observed_values) != 1:
                        reasons.add("CONFLICTING_OBSERVATIONS")
                    provenance = readbacks
                    previous_pairs.update(pairs)
                if not groups:
                    reasons.add("NO_ELIGIBLE_FIELD_OBSERVATION")
                value = provenance[0].value if current_values is not None and len(current_values) == 1 else None
                # Use interval-enriched copies, retaining every agreeing/conflicting source.
                current_sources = {(f.source_id, f.role, f.available_at) for f in provenance}
                enriched = tuple(f for f in aliases if f.field == field and (f.source_id, f.role, f.available_at) in current_sources)
                fields.append(IdentityField(field, value,
                                            normalize_identifier(field, value) if value is not None else None,
                                            enriched, tuple(sorted(reasons))))
            self._identity_cache[cache_key] = IdentityAt(user_id, cutoff, tuple(fields))
        return self._identity_cache[cache_key]

    def lookup_identifier(self, field: str, value: str, audit_at: datetime, *, exact: bool = False) -> tuple[IdentityMatch, ...]:
        """Return eligible ownership claims only; shared phone/name/hash never merges users."""
        cutoff = _utc(audit_at)
        key_value = value if exact else normalize_identifier(field, value)
        if field not in IDENTITY_FIELDS:
            raise ValueError("Unsupported identity field")
        times, matches = (self._exact if exact else self._normalized).get((field, key_value), ((), ()))
        eligible = matches[:bisect_right(times, cutoff)]
        owners = sorted({m.user_id for m in eligible})
        result = []
        for owner in owners:
            for fact in self.aliases_for(owner, cutoff):
                candidate = fact.value if exact else fact.normalized_value
                if fact.field == field and candidate == key_value:
                    result.append(IdentityMatch(owner, fact))
        return tuple(result)

    def resolve_request(self, email: str, audit_at: datetime) -> IdentityResolution:
        """Resolve an email association; never inspect request text or reported status."""
        cutoff = _utc(audit_at)
        normalized = normalize_identifier("email", email) or ""
        matches = self.lookup_identifier("email", email, cutoff) if normalized else ()
        owners = tuple(sorted({m.user_id for m in matches}))
        aliases, uncertainties, historical = (), (), False
        user_id = None
        if len(owners) == 1:
            status, user_id = ResolutionStatus.RESOLVED, owners[0]
            aliases = self.aliases_for(user_id, cutoff)
            current = self.identity_at(user_id, cutoff)
            uncertainties = tuple(f"{f.field}:{reason}" for f in current.fields for reason in f.uncertainties)
            historical = (current.get("email").value is not None
                          and current.get("email").normalized_value != normalized
                          and any(m.identifier.role == "OLD" for m in matches))
        elif owners:
            status = ResolutionStatus.AMBIGUOUS
            uncertainties = ("MULTIPLE_ELIGIBLE_OWNERS",)
        else:
            status = ResolutionStatus.UNRESOLVED
            uncertainties = ("NO_ELIGIBLE_EMAIL_OBSERVATION",)
        return IdentityResolution(status, user_id, normalized, cutoff, owners,
                                  aliases, matches, uncertainties, historical)


class IdentityResolutionError(ValueError):
    """Compatibility wrapper cannot return a Subject for a nonunique resolution."""

    def __init__(self, result: IdentityResolution):
        self.result = result
        super().__init__(result.status.value)


def resolve_subject(email: str, audit_at: datetime,
                    identities: Sequence[IdentitySnapshot], history: Sequence[IdentityChange]) -> Subject:
    """One-shot scaffold API; batches should reuse IdentityIndex instead."""
    result = IdentityIndex(identities, history).resolve_request(email, audit_at)
    if result.status != ResolutionStatus.RESOLVED:
        raise IdentityResolutionError(result)
    return Subject(result.user_id, result.aliases)


def coverage_summary(index: IdentityIndex, requests: Sequence[Request]) -> dict[str, object]:
    """Aggregate identity coverage, not audit accuracy; never emit raw case/PII rows."""
    counts = Counter({status.value: 0 for status in ResolutionStatus})
    reasons = Counter()
    historical = uncertain = partial = 0
    for request in requests:
        result = index.resolve_request(request.email, request.audit_at)
        counts[result.status.value] += 1
        historical += result.historical_email
        uncertain += bool(result.uncertainties)
        reasons.update(result.uncertainties)
        if result.user_id is not None:
            partial += any(f.value is None for f in index.identity_at(result.user_id, request.audit_at).fields)
    return {"requests": len(requests), **counts, "historical_email_resolutions": historical,
            "requests_with_uncertainty": uncertain, "resolved_with_unknown_current_fields": partial,
            "uncertainty_reasons": dict(sorted(reasons.items())), "bad_rows": 0}
