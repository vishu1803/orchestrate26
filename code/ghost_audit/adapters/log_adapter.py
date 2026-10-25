"""ISO, bracket, pipe, syslog, JSON and escaped cloud-message events; no silent lines."""
from dataclasses import replace
import re
import shlex
from .json_adapter import strict_json
from ..models import ExtractionIssue
from ..normalization import IDENTIFIER_KEYS, freeze, make_observation

PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+)\s+(.*)$")


def key_values(text):
    return {key: value for token in shlex.split(text, posix=True) if "=" in token
            for key, value in [token.split("=", 1)]}


def parse_line(line):
    match = PREFIX.match(line)
    if not match:
        raise ValueError("missing_iso_prefix")
    timestamp, body = match.groups()
    if body.startswith("{"):
        fields = strict_json(body)
        if not isinstance(fields, dict):
            raise ValueError("nonobject_log_json")
    else:
        fields = key_values(body)
        bracket = re.match(r"\[(\w+)\]\s*\[([^]]+)\]\s*\[([^]]+)\]\s*([^: ]+):", body)
        pipe = line.split(" | ", 5)
        syslog = re.match(r"<\d+>1\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+", body)
        if bracket:
            fields.update(level=bracket[1], service=bracket[2], trace_id=bracket[3], event=bracket[4])
        elif len(pipe) == 6:
            fields.update(level=pipe[1], service=pipe[2], trace_id=pipe[3], event=pipe[4])
        elif syslog:
            fields.setdefault("service", syslog[1]); fields.setdefault("trace_id", syslog[2])
        if isinstance(fields.get("message"), str) and "=" in fields["message"]:
            nested = key_values(fields["message"])
            fields["message_fields"] = nested
            # Explicit outer fields win; neither version is removed from the raw line.
            fields = {**nested, **fields}
        if "function" in fields:
            fields.setdefault("service", fields["function"])
        if "requestId" in fields:
            fields.setdefault("trace_id", fields["requestId"])
    fields.setdefault("timestamp", timestamp)
    fields["prefix_timestamp"] = timestamp
    if not fields.get("event"):
        raise ValueError("missing_event_name")
    return fields


def readback_event(event):
    return (event in {"record_lookup", "record_readback", "profile_readback", "index_readback",
                       "connector_readback", "restore_readback", "message_pii_scan", "analytics_profile_scan",
                       "cache_lookup", "analytics_profile_read", "analytics_identity_scan", "attachment_pii_scan",
                       "message_read", "connector_config_loaded", "retained_order_loaded",
                       "restore_authorization_completed", "restore_candidate_evaluated",
                       "export_download_check_completed", "connector_heartbeat"}
            or event.endswith(("_lookup_completed", "_query_completed", "_read_completed", "_scan_completed", "_readback")))


def parse(data, source):
    lines = data.decode("utf-8-sig").splitlines()
    observations, issues = [], []
    for number, line in enumerate(lines, 1):
        location = f"line:{number}"
        try:
            fields = parse_line(line)
            kind = "READBACK" if readback_event(fields["event"]) else "CLAIM"
        except (ValueError, TypeError):
            fields, kind = {}, "RAW"
            if line.strip():
                issues.append(ExtractionIssue(source.evidence_id, location, "unparsed_log_line", "WARNING"))
        fields["raw_line"] = line
        # These services encode nullable payload fields as the exact KV literal
        # null. It is not the stable user ID "null" or a stored email address.
        # Keep original tokens/raw line separately from typed interpretation.
        nullable = set(IDENTIFIER_KEYS) | {"name", "full_name", "display_name", "requester_name"}
        def typed_values(value):
            if isinstance(value, dict):
                return {k: None if k in nullable and v == "null" else typed_values(v) for k,v in value.items()}
            if isinstance(value, (list, tuple)):
                return [typed_values(v) for v in value]
            return value
        prefix = PREFIX.match(line)
        typed = typed_values(fields) if prefix and not prefix[2].startswith("{") else fields
        observation, errors = make_observation(typed, replace(source, locator=location), kind=kind)
        observation = replace(observation, raw_fields=freeze(fields))
        observations.append(observation); issues.extend(errors)
    return observations, issues, {"lines": len(lines)}
