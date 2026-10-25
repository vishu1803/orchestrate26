"""Typed participant CSV ingestion, actionable errors and confined manifest paths."""
import csv
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
import re

from .models import (OUTPUT_COLUMNS, EvidenceFile, IdentityChange, IdentitySnapshot,
                     PolicyAction, PolicyRule, Request, RowOrigin, SystemActivity)

REQUEST_COLUMNS = ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text")
CSV_COLUMNS = {
    "deletion_requests.csv": REQUEST_COLUMNS,
    "sample_deletion_requests.csv": REQUEST_COLUMNS,
    "sample_output.csv": OUTPUT_COLUMNS,
    "output.csv": OUTPUT_COLUMNS,
    "user_identities.csv": ("user_id", "name", "email", "phone", "email_hash", "updated_at"),
    "user_audit_log.csv": ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"),
    "system_activity.csv": ("activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"),
    "deletion_rules.csv": ("rule_id", "data_category", "condition", "required_action"),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
}


IDENTITY_FIELDS = ("name", "email", "phone", "email_hash")


class InputError(ValueError):
    """Location-rich validation failure; never echoes raw personal values."""

    def __init__(self, source: str | Path, row: int, field: str, code: str):
        self.source, self.row, self.field, self.code = str(source), row, field, code
        super().__init__(f"{source}: row {row}, field {field}: {code}")


def utc_timestamp(value: str, source: str | Path, row: int, field: str) -> datetime:
    """Require ISO date+time+offset, then convert to aware UTC (inclusive cutoff)."""
    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
    try:
        if not re.fullmatch(pattern, value):
            raise ValueError
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise InputError(source, row, field, "invalid_aware_iso_timestamp") from exc


def _records(path: Path, expected: tuple[str, ...] | None = None):
    """Yield physical line, raw row and stable ID; strict CSV, no null coercion."""
    path = Path(path)
    if path.name not in CSV_COLUMNS:
        raise InputError(path, 1, "header", "unknown_contract_file")
    if expected is not None and CSV_COLUMNS[path.name] != expected:
        raise InputError(path, 1, "header", "wrong_input_contract_for_reader")
    reader = None
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            if tuple(reader.fieldnames or ()) != CSV_COLUMNS[path.name]:
                raise InputError(path, 1, "header", "expected_columns=" + ",".join(CSV_COLUMNS[path.name]))
            seen = set()
            primary_key = CSV_COLUMNS[path.name][0]
            for record in reader:
                line = reader.line_num
                if None in record or any(v is None or "\0" in v for v in record.values()):
                    raise InputError(path, line, "record", "malformed_csv_row")
                identifier = record[primary_key]
                if not identifier.strip() or identifier != identifier.strip():
                    raise InputError(path, line, primary_key, "invalid_required_id")
                if identifier in seen:
                    raise InputError(path, line, primary_key, "duplicate_required_id")
                seen.add(identifier)
                yield line, record, identifier
    except InputError:
        raise
    except csv.Error as exc:
        raise InputError(path, max(1, reader.line_num if reader else 1), "record", "malformed_csv_quoting") from exc
    except (OSError, UnicodeError) as exc:
        raise InputError(path, max(1, reader.line_num if reader else 1), "record", type(exc).__name__) from exc


def read_contract_csv(path: Path) -> list[dict[str, str]]:
    """Retain Phase 0 raw-reader API; now also rejects duplicate primary IDs."""
    return [record for _, record, _ in _records(path)]


def _required(row: dict[str, str], fields: tuple[str, ...], path: Path, line: int) -> None:
    for field in fields:
        if not row[field].strip():
            raise InputError(path, line, field, "empty_required_field")


def load_requests(path: Path) -> tuple[Request, ...]:
    """Load either request set without interpreting request text or workflow claims."""
    result = []
    for line, row, identifier in _records(path, REQUEST_COLUMNS):
        _required(row, ("email", "request_text"), path, line)
        if row["reported_status"] not in {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}:
            raise InputError(path, line, "reported_status", "invalid_workflow_claim_enum")
        times = {key: utc_timestamp(row[key], path, line, key) for key in ("requested_at", "reported_at", "audit_at")}
        result.append(Request(row["case_id"], row["email"], times["requested_at"],
                              row["reported_status"], times["reported_at"], times["audit_at"],
                              row["request_text"], RowOrigin(str(path), line, identifier)))
    return tuple(result)


def load_identities(path: Path) -> tuple[IdentitySnapshot, ...]:
    """Direct identifiers may be empty; raw strings, including whitespace, survive."""
    return tuple(IdentitySnapshot(row["user_id"], row["name"], row["email"], row["phone"],
                                  row["email_hash"], utc_timestamp(row["updated_at"], path, line, "updated_at"),
                                  RowOrigin(str(path), line, identifier))
                 for line, row, identifier in _records(path, CSV_COLUMNS["user_identities.csv"]))


def load_history(path: Path) -> tuple[IdentityChange, ...]:
    """Empty old/new values mean observed empty, not a missing CSV cell."""
    result = []
    for line, row, identifier in _records(path, CSV_COLUMNS["user_audit_log.csv"]):
        _required(row, ("user_id",), path, line)
        if row["field_name"] not in IDENTITY_FIELDS:
            raise InputError(path, line, "field_name", "unsupported_identity_field")
        result.append(IdentityChange(identifier, row["user_id"],
                                     utc_timestamp(row["event_time"], path, line, "event_time"),
                                     row["field_name"], row["old_value"], row["new_value"],
                                     RowOrigin(str(path), line, identifier)))
    return tuple(result)


def load_activity(path: Path) -> tuple[SystemActivity, ...]:
    """Typed claims only; blank optional operational details/targets are retained."""
    result = []
    for line, row, identifier in _records(path, CSV_COLUMNS["system_activity.csv"]):
        _required(row, ("event_type", "source_system"), path, line)
        result.append(SystemActivity(identifier, utc_timestamp(row["event_time"], path, line, "event_time"),
                                      row["event_type"], row["source_system"], row["target_system"],
                                      row["resource_id"], row["reported_result"], row["details"],
                                      RowOrigin(str(path), line, identifier)))
    return tuple(result)


def load_rules(path: Path) -> tuple[PolicyRule, ...]:
    """Validate policy table only; leave free-text conditional interpretation deferred."""
    result = []
    for line, row, identifier in _records(path, CSV_COLUMNS["deletion_rules.csv"]):
        _required(row, ("data_category", "condition", "required_action"), path, line)
        try:
            action = PolicyAction(row["required_action"])
        except ValueError as exc:
            raise InputError(path, line, "required_action", "invalid_policy_action") from exc
        result.append(PolicyRule(identifier, row["data_category"], row["condition"], action))
    return tuple(result)


def validate_manifest_path(dataset_dir: Path, file_path: str) -> Path:
    """Resolve dataset-relative evidence paths; reject escape, drives and symlinks out."""
    relative = PurePosixPath(file_path)
    if (not file_path or "\\" in file_path or relative.is_absolute()
            or PureWindowsPath(file_path).drive or ".." in relative.parts):
        raise ValueError("Manifest path must be relative and confined")
    evidence_root = (dataset_dir / "evidence").resolve()
    path = (dataset_dir / relative).resolve()
    if (not evidence_root.is_relative_to(dataset_dir.resolve())
            or not path.is_relative_to(evidence_root) or not path.is_file()):
        raise ValueError("Manifest path is outside evidence or does not exist")
    return path


def load_manifest(path: Path) -> tuple[EvidenceFile, ...]:
    """Read metadata/stat paths only. Never open or interpret an evidence asset."""
    result = []
    for line, row, identifier in _records(path, CSV_COLUMNS["evidence_files.csv"]):
        _required(row, ("file_path", "origin"), path, line)
        try:
            resolved = validate_manifest_path(path.parent, row["file_path"])
        except ValueError as exc:
            raise InputError(path, line, "file_path", "unsafe_or_missing_evidence_path") from exc
        result.append(EvidenceFile(identifier, row["file_path"], row["origin"],
                                   utc_timestamp(row["captured_at"], path, line, "captured_at"),
                                   resolved, RowOrigin(str(path), line, identifier)))
    return tuple(result)


class DatasetReader:
    """Configurable dataset root; relative configurations resolve from repo, not cwd."""

    def __init__(self, dataset_dir: str | Path | None = None):
        repo = Path(__file__).resolve().parents[2]
        text = str(dataset_dir) if dataset_dir is not None else "dataset"
        path = Path(text)
        if "\\" in text and not path.is_absolute():
            windows = PureWindowsPath(text)
            if windows.drive:
                raise InputError(text, 0, "dataset_dir", "foreign_absolute_path_on_this_platform")
            path = Path(*windows.parts)
        self.root = (path if path.is_absolute() else repo / path).resolve()
        if not self.root.is_dir():
            raise InputError(self.root, 0, "dataset_dir", "directory_not_found")

    def requests(self, *, sample: bool = False) -> tuple[Request, ...]:
        return load_requests(self.root / ("sample_deletion_requests.csv" if sample else "deletion_requests.csv"))

    def identities(self) -> tuple[IdentitySnapshot, ...]:
        return load_identities(self.root / "user_identities.csv")

    def history(self) -> tuple[IdentityChange, ...]:
        return load_history(self.root / "user_audit_log.csv")

    def activity(self) -> tuple[SystemActivity, ...]:
        return load_activity(self.root / "system_activity.csv")

    def rules(self) -> tuple[PolicyRule, ...]:
        return load_rules(self.root / "deletion_rules.csv")

    def manifest(self) -> tuple[EvidenceFile, ...]:
        return load_manifest(self.root / "evidence_files.csv")
