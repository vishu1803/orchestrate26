"""Three-valued supplied-policy interpretation, never a default-delete fallback."""
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone, time
from pathlib import Path
import re
from typing import Sequence
from .io import load_rules
from .models import PolicyAction, PolicyDecision, PolicyRule, ResourceState
from .state_facts import boolean, observation_time, temporal_rejection


def read_policy_rules(path: Path) -> tuple[PolicyRule, ...]:
    """Validate actual supplied actions and keep conditions verbatim."""
    return load_rules(path)


def _payloads(resource):
    for observation in resource.observations:
        if observation.kind not in {"READBACK", "SNAPSHOT"} or temporal_rejection(observation, resource.as_of):
            continue
        yield observation, observation.attributes
        for key in ("document", "profile"):
            payload = observation.attributes.get(key)
            if isinstance(payload, Mapping):
                yield observation, payload


def _field(resource, *names):
    candidates = [(observation_time(o), p[k], o.source) for o, p in _payloads(resource) for k in names if k in p]
    if not candidates:
        return None, ()
    latest = max(t for t, _, _ in candidates)
    rows = [(v, s) for t, v, s in candidates if t == latest]
    if len({repr(v) for v, _ in rows}) != 1:
        return None, tuple(s for _, s in rows)
    return rows[0][0], tuple(s for _, s in rows)


def _date(raw):
    if not isinstance(raw, str):
        return None
    try:
        if re.fullmatch(r"\d{4}-\d\d-\d\d", raw):
            # Supplied date-only retention deadlines include that UTC calendar day.
            return datetime.combine(datetime.fromisoformat(raw).date(), time.max, timezone.utc)
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return value.astimezone(timezone.utc) if value.tzinfo else None
    except ValueError:
        return None


def _condition(resource, rule):
    """Interpret only documented condition grammars; unsupported text stays unknown."""
    condition = " ".join(rule.condition.casefold().split())
    if condition == "always":
        return True, ()
    if condition == "conversation contains shared customer, agent, or order context that must be retained":
        flag, sources = _field(resource, "shared_context", "requires_context_retention")
        if boolean(flag) is not None:
            return boolean(flag), sources
        text, sources = _field(resource, "message_text", "message_excerpt")
        if isinstance(text, str) and re.search(r"\bORD-[A-Za-z0-9-]+\b|\b(?:agent response|shared conversation|another customer|order (?:update|details|delivery)|affected order includes|customer (?:asked support|followed up about an order))\b", text, re.I):
            return True, sources
        # A service-export ticket synopsis plus its declared customer/requester
        # columns establishes a customer delivery thread. Ownership may use the
        # stable reference or an email already linked by the identity resolver. A
        # user's free-text mention of delivery is not equivalent to that schema.
        if isinstance(text, str) and re.fullmatch(r"Customer supplied contact details for (?:a |an )?(?:delivery|shipment|order) (?:query|update|status check)\.?", text.strip(), re.I):
            schema_sources = tuple(o.source for o,p in _payloads(resource)
                                   if o.source in sources and o.collection == "tickets"
                                   and {"customer_reference","requester_name","requester_email","requester_phone","message_excerpt"} <= set(p)
                                   and any(isinstance(p.get(k),str) and p[k] for k in ("customer_reference","requester_email"))
                                   and p["message_excerpt"] == text)
            if schema_sources:
                return True, schema_sources
        return None, sources
    if condition == "attachment belongs only to the deletion subject":
        flag, sources = _field(resource, "belongs_only_to_subject", "exclusive_subject")
        return boolean(flag), sources
    if condition == "record is still attributable to a user":
        if resource.identifiability == "IDENTIFIABLE" or any(d.dimension.startswith("stable_reference:") and d.value == "PRESENT" for d in resource.dimensions):
            return True, tuple(f.source for d in resource.dimensions if d.value in {"IDENTIFIABLE", "PRESENT"} for f in d.supporting)
        if resource.identifiability == "ANONYMIZED":
            return False, tuple(f.source for f in resource.get("identifiability").supporting)
        return None, ()
    if condition == "log contains a user email address":
        fields = [d for d in resource.dimensions if d.dimension.startswith("direct_identifier:") and "email" in d.dimension]
        if any(d.value == "PRESENT" for d in fields):
            return True, tuple(f.source for d in fields for f in d.supporting)
        return None, ()
    if condition == "record is within the supplied retention period":
        raw, sources = _field(resource, "retention_until", "retained_until")
        deadline = _date(raw)
        return (deadline >= resource.as_of if deadline else None), sources
    if condition == "a supplied legal hold is active":
        flag, sources = _field(resource, "hold_active", "legal_hold_active")
        if boolean(flag) is not None:
            return boolean(flag), sources
        status, sources = _field(resource, "hold_status")
        if isinstance(status, str) and status in {"ACTIVE", "RELEASED"}:
            return status == "ACTIVE", sources
        return None, sources
    if condition == "restore access can be blocked":
        flag, sources = _field(resource, "can_block_restore", "restore_blockable")
        if boolean(flag) is not None:
            return boolean(flag), sources
        # An observed explicit restore ACL, including false, establishes this
        # supplied schema's block-control capability; an archive name does not.
        acl, sources = _field(resource, "restore_allowed")
        if boolean(acl) is not None or resource.restore_access == "BLOCKED":
            return True, sources or tuple(f.source for f in resource.get("restore_access").supporting)
        return None, ()
    if condition == "account is deleted and only a stable internal user_id is needed to preserve references to retained records":
        status, status_sources = _field(resource, "account_status")
        needed, sources = _field(resource, "references_required", "stable_reference_required")
        stable = [d for d in resource.dimensions if d.dimension.startswith("stable_reference:") and d.value == "PRESENT"]
        declared_reference = tuple(o.source for o,p in _payloads(resource)
                                   if o.collection == "deleted_customer_references" and p.get("account_status") == "DELETED"
                                   and isinstance(p.get("subject_reference"), str) and p["subject_reference"])
        # This explicitly declared reference-registry schema establishes the
        # operational reference purpose; arbitrary tombstone labels still need
        # supplied reference requirements. An explicit false flag is not ignored.
        purpose = boolean(needed) is True or (needed is None and bool(declared_reference))
        return (True if status == "DELETED" and purpose and stable else None), (*status_sources, *sources, *declared_reference)
    return None, ()


def _pii(resource):
    return tuple(d for d in resource.dimensions if d.dimension.startswith("direct_identifier:") and d.value == "PRESENT")


def _cleared(resource):
    # Require explicit coverage of all prohibited direct field groups. A marker,
    # missing key or blank displayed email alone cannot prove field redaction.
    groups = (("name", "full_name", "display_name", "requester_name"),
              ("email", "customer_email", "requester_email", "owner_email"),
              ("phone", "customer_phone", "requester_phone", "owner_phone"), ("email_hash",))
    if any(g.startswith("unsupported_direct_identifier:") for g in resource.gaps):
        return False
    if resource.data_category == "SUPPORT_MESSAGE" and not any(d.dimension == "direct_identifier:email_hash" for d in resource.dimensions):
        schemas = [set(o.context.get("columns", ())) for o,p in _payloads(resource)]
        if any({"requester_name", "requester_email", "requester_phone"} <= cols and "email_hash" not in cols for cols in schemas):
            groups = groups[:-1]  # Declared SQL schema excludes this field.
    return all(any(resource.get("direct_identifier:" + name).value == "CLEARED" for name in group) for group in groups)


def apply_policy(resource: ResourceState, rules: Sequence[PolicyRule]) -> PolicyDecision:
    """Evaluate conditions, retention, tombstones and recreation/restore risks."""
    matching = [rule for rule in rules if rule.data_category == resource.data_category]
    if len(matching) != 1:
        return PolicyDecision(resource, None, None, "missing_or_ambiguous_policy_rule", blockers=("missing_or_ambiguous_policy_rule",))
    rule = matching[0]
    condition, condition_sources = _condition(resource, rule)
    verification = {PolicyAction.DELETE: "VERIFY_RECORD_ABSENT", PolicyAction.REDACT: "VERIFY_RECORD_REDACTED",
                    PolicyAction.ANONYMIZE: "VERIFY_RECORD_ANONYMIZED", PolicyAction.RETAIN: "VERIFY_RECORD_PRESENT"}[rule.required_action]
    preserve = rule.required_action != PolicyAction.DELETE
    base = PolicyDecision(resource, rule, None, "", verification=verification,
                          condition_proofs=tuple(condition_sources), preserve_record=preserve)
    if condition is not True:
        # Already-treated anonymized/cleared records still require a proof check;
        # other out-of-condition rows have no invented opposite action.
        treated = (rule.required_action == PolicyAction.ANONYMIZE and condition is False)
        treated |= rule.required_action == PolicyAction.REDACT and resource.data_category == "EMAIL_DELIVERY_LOG" and _cleared(resource)
        if not treated:
            reason = "unsupported_or_unknown_rule_condition" if condition is None else "rule_condition_not_met_no_alternative"
            return replace(base, reason=reason, verification=None, blockers=(reason,))
    existence = resource.get("record_existence")
    if rule.required_action == PolicyAction.DELETE:
        if existence.value == "PRESENT":
            return replace(base, compliant=False, reason="delete_required_record_observed_present", finding="REPORT_REMAINING_RECORD",
                           remediation="DELETE_RECORD", proofs=existence.supporting)
        if existence.value == "ABSENT":
            return replace(base, compliant=True, reason="scoped_absence_observed", proofs=existence.supporting)
    elif rule.required_action == PolicyAction.RETAIN:
        if existence.value == "PRESENT":
            return replace(base, compliant=True, reason="required_retained_record_observed", proofs=existence.supporting)
        return replace(base, reason="required_retained_record_not_proven_present", blockers=("required_retained_record_not_proven_present",))
    elif rule.required_action in {PolicyAction.REDACT, PolicyAction.ANONYMIZE}:
        exposed = _pii(resource)
        linked = tuple(d for d in resource.dimensions if d.dimension.startswith("stable_reference:") and d.value == "PRESENT")
        identifiable = resource.get("identifiability")
        violation = bool(exposed) or identifiable.value == "IDENTIFIABLE"
        if rule.required_action == PolicyAction.ANONYMIZE:
            violation |= bool(linked)
        if violation:
            relevant = (*exposed, *(linked if rule.required_action == PolicyAction.ANONYMIZE else ()))
            proofs = tuple(f for d in relevant for f in d.supporting)
            proofs = proofs or identifiable.supporting
            return replace(base, compliant=False, reason="prohibited_identifiers_or_attribution_observed", finding="REPORT_EXPOSED_PII",
                           remediation="REDACT_RECORD" if rule.required_action == PolicyAction.REDACT else "ANONYMIZE_RECORD", proofs=proofs)
        if existence.value == "PRESENT":
            if rule.required_action == PolicyAction.REDACT and _cleared(resource):
                stable_ok = resource.data_category != "ACCOUNT_TOMBSTONE" or bool(linked)
                if stable_ok:
                    return replace(base, compliant=True, reason="direct_fields_explicitly_cleared_reference_preserved",
                                   proofs=tuple(f for d in resource.dimensions if d.dimension.startswith(("direct_identifier:", "stable_reference:")) for f in d.supporting))
            if rule.required_action == PolicyAction.ANONYMIZE:
                verified, sources = _field(resource, "irreversibly_unlinked", "anonymization_verified")
                explicit_fields = any(f.field.endswith("attribution_fields") for f in identifiable.supporting)
                reviewed = not any(g.startswith("unreviewed_analytics_field:") for g in resource.gaps)
                if (boolean(verified) is True or explicit_fields) and identifiable.value == "ANONYMIZED" and not linked and reviewed:
                    return replace(base, compliant=True, reason="irreversible_unlinking_observed", proofs=identifiable.supporting,
                                   condition_proofs=(*base.condition_proofs, *sources))
        return replace(base, reason="treatment_or_preservation_not_proven", blockers=("treatment_or_preservation_not_proven",))
    return replace(base, reason="resource_existence_unknown_or_conflicting", blockers=("resource_existence_unknown_or_conflicting",))


def process_decisions(resource):
    decisions = []
    for dimension, active, inactive, finding, remediation, verification in (
        ("data_flow", "ACTIVE", "DISABLED", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
        ("restore_access", "ACTIVE", "BLOCKED", "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")):
        state = resource.get(dimension)
        required = (dimension == "data_flow" and resource.data_category == "DATA_FLOW") or (dimension == "restore_access" and resource.data_category == "BACKUP_ARCHIVE")
        if state.value == "UNKNOWN" and not required:
            continue
        known = state.value in {active, inactive}
        decisions.append(PolicyDecision(resource, None, state.value == inactive if known else None,
                                        "observed_process_state" if known else "process_state_unknown", component=dimension,
                                        finding=finding if state.value == active else None,
                                        remediation=remediation if state.value == active else None, verification=verification,
                                        proofs=state.supporting, blockers=() if known else ("process_state_unknown",)))
    return tuple(decisions)


def evaluate_report(report, rules):
    decisions = []
    grounded_keys = {(r.system_id, r.resource_id) for r in report.resources if any(d.supporting for d in r.dimensions)}
    for resource in report.resources:
        # An unscoped event claim is a target hint, not an additional physical copy.
        # A named replica/region remains independently unresolved.
        scope = resource.scope
        claim_only = all(o.kind == "CLAIM" for o in resource.observations)
        unscoped = scope is None or not any((scope.table, scope.topology, scope.region, scope.shard, scope.data_store, scope.storage_key))
        if claim_only and unscoped and (resource.system_id, resource.resource_id) in grounded_keys:
            continue
        if resource.data_category != "DATA_FLOW":
            decisions.append(apply_policy(resource, rules))
        decisions.extend(process_decisions(resource))
    return tuple(decisions)
