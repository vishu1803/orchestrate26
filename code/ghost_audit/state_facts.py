"""Documented schema-to-fact rules, independent of deletion policy and workflow claims."""
from collections.abc import Mapping
from datetime import datetime, timezone

from .models import NormalizedFact, PhysicalScope
from .normalization import freeze

# Observed participant collection schemas, not case families or expected outcomes.
COLLECTIONS = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "profile_lookups": ("account_service", "USER_PROFILE"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "index_queries": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "exports": ("export_service", "USER_EXPORT"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "connectors": ("integration_service", "DATA_FLOW"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "retained_order_records": ("finance_service", "LEGAL_HOLD_RECORD"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
}
RESOURCE_CLASSES = ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SECONDARY_IDENTIFIER",
                    "MARKETING_PROFILE", "USER_EXPORT", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT",
                    "EMAIL_DELIVERY_LOG", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
                    "SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "ACCOUNT_TOMBSTONE",
                    "DATA_FLOW", "BACKUP_ARCHIVE")
DIRECT_FIELDS = {"name", "full_name", "display_name", "requester_name", "email", "phone",
                 "email_hash", "customer_email", "customer_phone", "requester_email",
                 "requester_phone", "owner_email", "owner_phone"}
STABLE_FIELDS = {"user_id", "customer_reference", "subject_reference"}
BASE_DIMENSIONS = ("record_existence", "identifiability", "data_flow", "restore_access")
ANALYTICS_FIELDS = DIRECT_FIELDS | STABLE_FIELDS | {
    "resource_id", "system_id", "system", "origin_system", "record_type", "data_category", "result",
    "audience_cohort", "reporting_window", "metrics", "recent_activity", "query", "document", "profile", "record_json", "collection_name",
    "observed_at", "recorded_at", "event_time", "timestamp", "updated_at", "captured_at", "exported_at", "indexed_at", "created_at", "prefix_timestamp",
    "irreversibly_unlinked", "anonymization_verified", "direct_identifiers", "event", "raw_line", "level", "service", "instance", "pod", "region", "shard",
    "trace_id", "requestId", "function", "message", "message_fields", "lookup_key", "subject_key", "correlation_key", "match_key", "detector", "matched_value", "scan_key", "duration_ms", "took_ms", "logger", "severity", "seq"}


def utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware_timestamp_required")
    return value.astimezone(timezone.utc)


def temporal_rejection(observation, cutoff):
    """No fallback from a missing event clock to manifest availability."""
    cutoff = utc(cutoff)
    try:
        available = utc(observation.source.available_at)
    except ValueError:
        return "missing_or_invalid_availability"
    if available > cutoff:
        return "captured_after_cutoff"
    # The empty string is the valid RFC 6901 pointer for a root JSON record.
    if not observation.source.evidence_id or observation.source.locator is None:
        return "missing_source_provenance"
    for clock in observation.timestamps:
        try:
            time = utc(clock.value)
        except ValueError:
            return "invalid_embedded_clock"
        if time > cutoff:
            return "embedded_clock_after_cutoff"
    try:
        observed = utc(observation.observed_at)
    except ValueError:
        return "missing_or_invalid_observation_time"
    return "observed_after_cutoff" if observed > cutoff else None


def logical_system(observation):
    if observation.kind == "CLAIM" and observation.attributes.get("identity_link"):
        return observation.attributes.get("target_system") or observation.system_id or ""
    if observation.system_id == "support_replica" and observation.source.origin == "support_platform":
        # The manifest names the logical platform; the component service is an
        # actual replica name retained in raw fields and physical_scope.
        return observation.source.origin
    if observation.system_id:
        return observation.system_id
    store = observation.context.get("data_store")
    if isinstance(store, str) and store in {system for system, _ in COLLECTIONS.values()}:
        return store
    schema = COLLECTIONS.get(observation.collection)
    if schema:
        return schema[0]
    return ""


def category(observation):
    explicit = observation.data_category or COLLECTIONS.get(observation.collection, ("", ""))[1]
    if explicit:
        return explicit
    event = observation.attributes.get("event") if isinstance(observation.attributes.get("event"), str) else ""
    if (event == "contact_query_completed" and observation.system_id == "support_replica"
            and observation.source.origin == "support_platform") or (event == "contact_lookup_completed" and observation.system_id == "analytics_platform"):
        # These are contact/secondary-identifier stores, not analytics aggregates
        # or shared support messages; resource-ID prefixes do not select policy.
        return "SECONDARY_IDENTIFIER"
    return {
        "cache_lookup": "CACHE_ENTRY", "index_query_completed": "SEARCH_INDEX_ENTRY",
        "profile_lookup_completed": "USER_PROFILE", "message_pii_scan": "SUPPORT_MESSAGE",
        "message_read": "SUPPORT_MESSAGE", "support_ticket_read_completed": "SUPPORT_MESSAGE",
        "attachment_pii_scan": "SUPPORT_ATTACHMENT", "analytics_identity_scan": "ANALYTICS_PROFILE",
        "analytics_profile_read": "ANALYTICS_PROFILE", "analytics_profile_read_completed": "ANALYTICS_PROFILE",
        "connector_config_loaded": "DATA_FLOW", "connector_config_read_completed": "DATA_FLOW",
        "connector_heartbeat": "DATA_FLOW",
        "restore_authorization_completed": "BACKUP_ARCHIVE", "restore_candidate_evaluated": "BACKUP_ARCHIVE",
        "restore_policy_read_completed": "BACKUP_ARCHIVE", "retained_order_loaded": "LEGAL_HOLD_RECORD",
        "audit_record_read_completed": "SECURITY_AUDIT_LOG", "export_metadata_read_completed": "USER_EXPORT",
        "export_download_check_completed": "USER_EXPORT",
    }.get(event, "")


def physical_scope(observation):
    attrs, ctx = observation.attributes, observation.context
    def value(key):
        nested = attrs.get("document")
        item = attrs.get(key, ctx.get(key, nested.get(key, "") if isinstance(nested, Mapping) else ""))
        return str(item) if isinstance(item, (str, int)) else ""
    table = value("table") or (observation.collection or "" if observation.source.file_path.endswith(".sql") else "")
    component = "service:" + observation.system_id if observation.system_id and observation.system_id != logical_system(observation) else ""
    return PhysicalScope(table, observation.topology or component, value("region"), value("shard"),
                         value("data_store") or value("index") or value("index_name") or value("cache"),
                         observation.collection or "",
                         observation.source.origin if not logical_system(observation) else "",
                         value("object_key") or value("archive_key") or value("archive_path"))


def observation_time(observation):
    # A row updated_at is a write clock, not when the snapshot was read.
    clocks = [utc(observation.observed_at)]
    # An export of historical readbacks does not re-observe every historical
    # result at export time. Explicit event/observation clocks retain their time.
    explicit_event = any(t.field in {"record.observed_at", "record.recorded_at", "record.event_time", "record.timestamp"}
                         for t in observation.timestamps)
    if observation.kind == "SNAPSHOT" and not explicit_event:
        clocks.extend(utc(t.value) for t in observation.timestamps
                      if t.value and (t.field.endswith("captured_at") or t.field.endswith("exported_at")))
    return max(clocks)


def boolean(value):
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return value == 1
    if type(value) is str and value in {"true", "false", "0", "1"}:
        return value in {"true", "1"}
    return None


def normalize_facts(observation):
    """Return exact source facts and gaps, never interpret operation success as state.

    Markers accepted: FOUND/NOT_FOUND, IDENTIFIABLE/ANONYMIZED/REDACTED,
    ACTIVE/DISABLED/BLOCKED and cache hit/miss. Flags accept only bool, 0/1,
    true/false strings. A redaction marker alone proves no cleared field.
    """
    if observation.kind not in {"READBACK", "SNAPSHOT"}:
        return (), ("claim_not_state_proof" if observation.kind == "CLAIM" else "semantic_extraction_required",)
    facts, gaps = [], []
    when = observation_time(observation)
    attrs = observation.attributes

    def add(dimension, value, field, raw, locator=None):
        location = locator or observation.source.locator + "/" + field
        if "record_json" in attrs:
            location = location.replace("/document/", "/record_json#/")
        facts.append(NormalizedFact(dimension, value, observation.source, when, field,
                                    freeze(raw), location))

    for field in ("state", "status"):
        if field in attrs:
            gaps.append("uninterpreted_state_field:" + field)

    result = attrs.get("result")
    markers = {"FOUND": "PRESENT", "NOT_FOUND": "ABSENT", "hit": "PRESENT", "miss": "ABSENT",
               "IDENTIFIABLE": "PRESENT", "ANONYMIZED": "PRESENT", "REDACTED": "PRESENT"}
    if isinstance(result, str) and result in markers and observation.resource_id:
        add("record_existence", markers[result], "result", result)
    elif result is not None and (not isinstance(result, str) or result not in {"ACTIVE", "DISABLED", "BLOCKED"}):
        gaps.append("unsupported_result_marker")
    if isinstance(result, str) and result in {"IDENTIFIABLE", "ANONYMIZED"}:
        add("identifiability", result, "result", result)
    if result == "REDACTED":
        gaps.append("redaction_marker_without_field_proof")
    for key in ("rows", "total_hits", "http_status", "status_code"):
        if key in attrs:
            raw = attrs[key]
            # Numeric strings are normalized by the Phase 2 adapter, raw stays intact.
            value = int(raw) if isinstance(raw, str) and raw.isascii() and raw.isdigit() else raw
            if type(value) is not int:
                gaps.append("unsupported_" + key)
            elif observation.kind == "READBACK" and observation.resource_id:
                state = ("ABSENT" if value == 404 else "PRESENT" if value == 200 else None) if key in {"http_status", "status_code"} else ("ABSENT" if value == 0 else "PRESENT" if value > 0 else None)
                if state:
                    add("record_existence", state, key, raw)
                else:
                    gaps.append("nondefinitive_" + key)
    if "hits" in attrs:
        hits = attrs["hits"]
        if observation.kind == "READBACK" and isinstance(hits, (tuple, list)) and observation.resource_id:
            add("record_existence", "PRESENT" if hits else "ABSENT", "hits", hits)
        elif observation.kind == "READBACK" and isinstance(hits, Mapping) and observation.resource_id:
            total, documents = hits.get("total"), hits.get("documents")
            if type(total) is int and isinstance(documents, (tuple, list)):
                if total == 0 and not documents:
                    add("record_existence", "ABSENT", "hits", hits)
                elif total > 0 and any(isinstance(d, Mapping) and d.get("resource_id") == observation.resource_id for d in documents):
                    add("record_existence", "PRESENT", "hits", hits)
                else:
                    gaps.append("query_hits_do_not_establish_target")
            else:
                gaps.append("unsupported_hits")
        else:
            gaps.append("unsupported_hits")
    if observation.kind == "SNAPSHOT" and observation.resource_id and result is None and not attrs.get("empty_collection") and not attrs.get("empty_table"):
        add("record_existence", "PRESENT", "snapshot_row", observation.resource_id, observation.source.locator)
    if attrs.get("empty_collection") or attrs.get("empty_table"):
        gaps.append("partial_empty_scope_not_absence")
    for prefix, payload in (("", attrs), ("document/", attrs.get("document")), ("profile/", attrs.get("profile"))):
        if not isinstance(payload, Mapping):
            continue
        for key, dimension, yes, no in (("enabled", "data_flow", "ACTIVE", "DISABLED"),
                                       ("restore_allowed", "restore_access", "ACTIVE", "BLOCKED"),
                                       ("archive_present", "record_existence", "PRESENT", "ABSENT")):
            if key in payload:
                value = boolean(payload[key])
                if value is None:
                    gaps.append("unsupported_" + prefix + key)
                else:
                    add(dimension, yes if value else no, prefix + key, payload[key])
    cat = category(observation)
    event = attrs.get("event") if isinstance(attrs.get("event"), str) else ""
    if event in {"support_ticket_read_completed", "analytics_profile_read_completed", "analytics_profile_read",
                 "connector_config_read_completed", "connector_config_loaded", "retained_order_loaded",
                 "message_read"} and observation.resource_id:
        add("record_existence", "PRESENT", "event", event)
    direct_match = (attrs.get("detector") == "direct_identifier" or
                    any(i.field in {"email", "phone", "email_hash"} and i.locator.endswith("/matched_value") for i in observation.identifiers))
    if event in {"attachment_pii_scan", "message_pii_scan", "analytics_identity_scan"} and direct_match and attrs.get("direct_identifiers") != 0 and isinstance(attrs.get("matched_value"), str) and attrs["matched_value"].strip():
        add("record_existence", "PRESENT", "matched_value", attrs["matched_value"])
        add("identifiability", "IDENTIFIABLE", "matched_value", attrs["matched_value"])
        add("pii_scan", "PRESENT", "matched_value", attrs["matched_value"])
    if event == "restore_authorization_completed":
        decision = attrs.get("decision")
        if isinstance(decision, str) and decision in {"allow", "deny"}:
            add("restore_access", "ACTIVE" if decision == "allow" else "BLOCKED", "decision", decision)
        else:
            gaps.append("unsupported_restore_authorization_decision")
    if event == "restore_candidate_evaluated":
        allowed, blocked = boolean(attrs.get("eligible")), boolean(attrs.get("deletion_block"))
        if allowed is True and blocked is False:
            add("restore_access", "ACTIVE", "eligible_and_deletion_block", (attrs["eligible"], attrs["deletion_block"]))
        elif blocked is True:
            add("restore_access", "BLOCKED", "deletion_block", attrs["deletion_block"])
        else:
            gaps.append("restore_candidate_permission_unknown")
    if cat == "DATA_FLOW" and isinstance(result, str) and result in {"ACTIVE", "DISABLED"}:
        add("data_flow", result, "result", result)
    if cat == "BACKUP_ARCHIVE" and isinstance(result, str) and result in {"ACTIVE", "BLOCKED"}:
        add("restore_access", result, "result", result)

    def fields(payload, prefix):
        if not isinstance(payload, Mapping):
            return
        for key, raw in payload.items():
            if key in DIRECT_FIELDS:
                if raw is None or (isinstance(raw, str) and not raw.strip()):
                    add("direct_identifier:" + key, "CLEARED", prefix + key, raw)
                elif isinstance(raw, str):
                    add("direct_identifier:" + key, "PRESENT", prefix + key, raw)
                    add("identifiability", "IDENTIFIABLE", prefix + key, raw)
                else:
                    gaps.append("unsupported_direct_identifier:" + key)
            elif key in STABLE_FIELDS:
                if key == "subject_reference" and raw == "no direct identifier":
                    gaps.append("non_identifier_reference_placeholder")
                    continue
                if raw is None or raw == "":
                    add("stable_reference:" + key, "CLEARED", prefix + key, raw)
                elif isinstance(raw, str):
                    add("stable_reference:" + key, "PRESENT", prefix + key, raw)
    # Query/search/lookup identifiers locate a record but are not stored PII proof.
    fields(attrs, "")
    for key in ("document", "profile"):
        fields(attrs.get(key), key + "/")
    hits = attrs.get("hits")
    if isinstance(hits, Mapping) and isinstance(hits.get("documents"), (list, tuple)):
        for n, document in enumerate(hits["documents"]):
            if isinstance(document, Mapping) and document.get("resource_id") == observation.resource_id:
                fields(document, "hits/documents/" + str(n) + "/")
    if "direct_identifiers" in attrs:
        count = attrs["direct_identifiers"]
        if type(count) is int and count >= 0:
            add("pii_scan", "CLEAR" if count == 0 else "PRESENT", "direct_identifiers", count)
            if count:
                add("identifiability", "IDENTIFIABLE", "direct_identifiers", count)
        else:
            gaps.append("unsupported_direct_identifiers")
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        # Known profile exports explicitly serialize every attribution slot.
        # This establishes unlinking from the stored row; a missing field, null
        # email alone or an unexamined device/identity key does not.
        for prefix, payload in (("", attrs), ("document/", attrs.get("document")), ("profile/", attrs.get("profile"))):
            if not isinstance(payload, Mapping):
                continue
            unknown = {k for k,v in payload.items() if k not in ANALYTICS_FIELDS and v not in (None, "")}
            for container in (payload.get("metrics"), payload.get("recent_activity")):
                def suspicious(value):
                    if isinstance(value, Mapping):
                        return any((k in DIRECT_FIELDS | STABLE_FIELDS or k.endswith(("_id", "_reference", "_key")) or k in {"ip_address", "uid", "identity", "device"})
                                   and v not in (None, "") or suspicious(v) for k,v in value.items())
                    return isinstance(value, (tuple,list)) and any(suspicious(v) for v in value)
                if suspicious(container):
                    unknown.add("nested_attribution")
            gaps.extend("unreviewed_analytics_field:" + key for key in sorted(unknown))
            required = {"email", "phone", "email_hash"}
            stable = set(payload) & STABLE_FIELDS
            clear = lambda value: value is None or (isinstance(value, str) and not value.strip())
            metadata = {"resource_id", "system_id"}
            if observation.kind == "READBACK":
                metadata |= {"trace_id", "lookup_key", "subject_key", "correlation_key", "match_key"}
            extra_links = {k for k,v in payload.items() if k not in metadata and
                           (k.endswith(("_id", "_reference", "_key")) or k in {"uid", "identity", "device"}) and not clear(v)}
            if required <= set(payload) and stable and all(clear(payload[k]) for k in required | stable) and not extra_links and not unknown:
                direct = {k:v for k,v in payload.items() if k in DIRECT_FIELDS}
                if all(clear(v) for v in direct.values()):
                    add("identifiability", "ANONYMIZED", prefix + "attribution_fields",
                        {k:payload[k] for k in sorted(required | stable)})
    return tuple(facts), tuple(sorted(set(gaps)))
