"""Lossless immutable raw trees plus separate, conservative observation normalization."""
from dataclasses import replace
from types import MappingProxyType
from collections.abc import Mapping
import re

from .identity import normalize_identifier
from .io import InputError, utc_timestamp
from .models import EvidenceIdentifier, EvidenceTime, ExtractionIssue, Observation

TIME_KEYS = ("observed_at", "recorded_at", "event_time", "timestamp", "updated_at", "indexed_at", "captured_at", "exported_at", "prefix_timestamp", "created_at")
IDENTIFIER_KEYS = {
    "user_id": "user_id", "customer_reference": "user_id", "subject_reference": "reference",
    "subject_ref": "reference", "email": "email", "customer_email": "email",
    "requester_email": "email", "owner_email": "email", "email_hash": "email_hash",
    "phone": "phone", "customer_phone": "phone", "requester_phone": "phone", "owner_phone": "phone",
    "lookup_key": "reference", "subject_key": "reference", "correlation_key": "reference",
    "match_key": "reference", "matched_value": "reference", "query": "reference",
    "lookup_value": "reference", "subject_selector": "reference", "scan_key": "reference",
    "owner_key": "reference",
}


def freeze(value):
    """Freeze mappings/arrays recursively; values/null/false/empty/missing stay distinct."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def pointer_child(pointer, key):
    return pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")


def identifiers(raw, pointer):
    result = []

    def walk(value, location):
        if isinstance(value, Mapping):
            for key, item in value.items():
                child = pointer_child(location, key)
                category = IDENTIFIER_KEYS.get(key)
                if isinstance(item, str) and category:
                    if category == "reference":
                        category = ("email" if re.fullmatch(r"[^@\s]+@[^@\s]+", item.strip())
                                    else "user_id" if re.fullmatch(r"user_[A-Za-z0-9_-]+", item)
                                    else "opaque_reference" if item.strip() and item.casefold() not in {"no direct identifier", "none", "redacted", "anonymized"} else None)
                    if category:
                        normalized = item if category in {"user_id", "opaque_reference"} else normalize_identifier(category, item)
                        if normalized:
                            result.append(EvidenceIdentifier(category, item, normalized, child))
                # Never turn a body-text substring or a different record list into ownership.
                if key not in {"records", "resources", "snapshots", "service_exports"}:
                    walk(item, child)
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, pointer_child(location, index))
    walk(raw, pointer)
    return tuple(result)


def make_observation(raw, source, *, context=None, kind="SNAPSHOT", collection=None, topology=None):
    context = dict(context or {})
    issues, times = [], []
    for label, value in context.get("ancestor_timestamps", ()):
        parsed = None
        try:
            parsed = utc_timestamp(value, source.file_path, 0, label)
        except (InputError, ValueError, TypeError):
            issues.append(ExtractionIssue(source.evidence_id, source.locator, "invalid_ancestor_timestamp", "ERROR"))
        times.append(EvidenceTime(label, freeze(value), parsed))
    for label, container in (("context", context), ("record", raw)):
        for key in TIME_KEYS:
            if key in container:
                value = container[key]
                parsed = None
                try:
                    if not isinstance(value, str):
                        raise ValueError
                    parsed = utc_timestamp(value, source.file_path, 0, key)
                except (InputError, ValueError):
                    issues.append(ExtractionIssue(source.evidence_id, source.locator, "invalid_timestamp:" + label + "." + key, "ERROR"))
                times.append(EvidenceTime(label + "." + key, freeze(value), parsed))
    def nested_times(value, location):
        if isinstance(value, Mapping):
            for key, child in value.items():
                label = pointer_child(location, key)
                if key in TIME_KEYS:
                    parsed = None
                    try:
                        parsed = utc_timestamp(child, source.file_path, 0, key)
                    except (InputError, TypeError, ValueError):
                        issues.append(ExtractionIssue(source.evidence_id, source.locator, "invalid_nested_timestamp", "ERROR"))
                    times.append(EvidenceTime(label, freeze(child), parsed))
                nested_times(child, label)
        elif isinstance(value, (tuple, list)):
            for number, child in enumerate(value):
                nested_times(child, pointer_child(location, number))
    for key, value in raw.items():
        if isinstance(value, (Mapping, list, tuple)):
            nested_times(value, "record/" + key)
    # Keep all contextual clocks; do not silently replace inner with manifest time.
    observed = next((t.value for key in TIME_KEYS for t in times if t.field == "record." + key and t.value), None)
    if observed is None:
        nested = {t.value for t in times if t.field.startswith("record/") and t.value}
        if len(nested) == 1:
            observed = next(iter(nested))
    if observed is None:
        observed = next((t.value for t in reversed(times) if t.field == "context.captured_at" and t.value), None)
    attrs = dict(raw)
    for key in ("enabled", "restore_allowed"):
        value = raw.get(key)
        if value in ("true", "false", "1", "0", 1, 0):
            attrs[key] = value in ("true", "1", 1)
    for key in ("rows", "http_status", "status_code", "direct_identifiers"):
        value = raw.get(key)
        if isinstance(value, str) and re.fullmatch(r"\d+", value):
            attrs[key] = int(value)
    system = next((raw[k] for k in ("system_id", "system", "origin_system", "service") if isinstance(raw.get(k), str)), context.get("system_id"))
    resource = raw.get("resource_id")
    if resource is None:
        nested_resources = {child["resource_id"] for key in ("profile", "document")
                            if isinstance((child := raw.get(key)), Mapping) and isinstance(child.get("resource_id"), str)}
        if len(nested_resources) == 1:
            resource = next(iter(nested_resources))
        elif len(nested_resources) > 1:
            issues.append(ExtractionIssue(source.evidence_id, source.locator, "ambiguous_nested_resource_ids", "WARNING"))
    if resource is not None and not isinstance(resource, str):
        issues.append(ExtractionIssue(source.evidence_id, source.locator, "invalid_resource_id_type", "ERROR"))
        resource = None
    category = raw.get("data_category", raw.get("record_type"))
    trace = raw.get("trace_id")
    if not isinstance(trace, str):
        trace = None
    attrs.update(system_id=system, resource_id=resource)
    result = Observation(system, resource, category, observed, source, kind, freeze(attrs),
                         freeze(raw), freeze(context), tuple(times), identifiers(raw, source.locator),
                         collection or raw.get("collection") or context.get("collection"), topology or context.get("topology"), trace)
    return result, issues
