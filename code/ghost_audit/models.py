"""Typed contracts. Internal unknowns must never be serialized as final verdicts."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal, Mapping


class Status(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class State(str, Enum):
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class PolicyAction(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


# Insertion order is the canonical within-phase operation order, not inference.
OPERATION_CONTRACT = {
    "REPORT_REMAINING_RECORD": (Phase.FINDING, State.PRESENT),
    "REPORT_EXPOSED_PII": (Phase.FINDING, State.PRESENT),
    "REPORT_ACTIVE_DATA_FLOW": (Phase.FINDING, State.ACTIVE),
    "REPORT_RESTORE_RISK": (Phase.FINDING, State.ACTIVE),
    "DISABLE_DATA_FLOW": (Phase.REMEDIATION, State.DISABLED),
    "BLOCK_RESTORE": (Phase.REMEDIATION, State.BLOCKED),
    "DELETE_RECORD": (Phase.REMEDIATION, State.ABSENT),
    "REDACT_RECORD": (Phase.REMEDIATION, State.REDACTED),
    "ANONYMIZE_RECORD": (Phase.REMEDIATION, State.ANONYMIZED),
    "VERIFY_RECORD_ABSENT": (Phase.VERIFICATION, State.ABSENT),
    "VERIFY_RECORD_PRESENT": (Phase.VERIFICATION, State.PRESENT),
    "VERIFY_RECORD_REDACTED": (Phase.VERIFICATION, State.REDACTED),
    "VERIFY_RECORD_ANONYMIZED": (Phase.VERIFICATION, State.ANONYMIZED),
    "VERIFY_DATA_FLOW_DISABLED": (Phase.VERIFICATION, State.DISABLED),
    "VERIFY_RESTORE_BLOCKED": (Phase.VERIFICATION, State.BLOCKED),
}
OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")


@dataclass(frozen=True)
class RowOrigin:
    source_file: str
    row_number: int  # physical ending line of the CSV record (header is line 1)
    source_id: str


@dataclass(frozen=True)
class Request:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str
    lineage: RowOrigin | None = None


@dataclass(frozen=True)
class SourceRef:
    evidence_id: str  # participant file_id/activity_id/audit_id, never invented
    available_at: datetime  # manifest capture or event availability timestamp
    locator: str  # page/bbox, JSON pointer, SQL table/key, CSV row or log lines
    file_path: str = ""
    origin: str = ""
    content_sha256: str = ""
    source_kind: Literal["FILE", "ACTIVITY"] = "FILE"
    captured_at_raw: str | None = None
    manifest_locator: str | None = None


@dataclass(frozen=True)
class Identifier:
    field: str
    value: str
    valid_from: datetime | None
    valid_until: datetime | None
    source_id: str
    normalized_value: str | None = None
    normalization: str = ""
    available_at: datetime | None = None
    source_file: str = ""
    row_number: int = 0
    role: Literal["SNAPSHOT", "OLD", "NEW"] = "SNAPSHOT"


@dataclass(frozen=True)
class Subject:
    user_id: str
    identifiers: tuple[Identifier, ...]


@dataclass(frozen=True)
class IdentitySnapshot:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime
    lineage: RowOrigin


@dataclass(frozen=True)
class IdentityChange:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str
    lineage: RowOrigin


@dataclass(frozen=True)
class SystemActivity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    lineage: RowOrigin


@dataclass(frozen=True)
class EvidenceFile:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime
    resolved_path: Path
    lineage: RowOrigin


class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class IdentityField:
    field: str
    value: str | None  # None = unknown/conflicting; empty string = observed empty
    normalized_value: str | None
    provenance: tuple[Identifier, ...]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True)
class IdentityAt:
    user_id: str
    audit_at: datetime
    fields: tuple[IdentityField, ...]

    def get(self, field: str) -> IdentityField:
        return next(item for item in self.fields if item.field == field)


@dataclass(frozen=True)
class IdentityMatch:
    user_id: str
    identifier: Identifier


@dataclass(frozen=True)
class IdentityResolution:
    status: ResolutionStatus
    user_id: str | None
    normalized_email: str
    audit_at: datetime
    candidate_ids: tuple[str, ...]
    aliases: tuple[Identifier, ...]
    matches: tuple[IdentityMatch, ...]
    uncertainties: tuple[str, ...]
    historical_email: bool


@dataclass(frozen=True)
class Observation:
    system_id: str | None
    resource_id: str | None
    data_category: str | None
    observed_at: datetime | None
    source: SourceRef
    kind: Literal["READBACK", "SNAPSHOT", "CLAIM", "RAW", "METADATA"]
    attributes: Mapping[str, object]
    raw_fields: object = field(default_factory=dict)
    context: Mapping[str, object] = field(default_factory=dict)
    timestamps: tuple["EvidenceTime", ...] = ()
    identifiers: tuple["EvidenceIdentifier", ...] = ()
    collection: str | None = None
    topology: str | None = None
    trace_id: str | None = None


@dataclass(frozen=True)
class EvidenceTime:
    field: str
    raw_value: object
    value: datetime | None


@dataclass(frozen=True)
class EvidenceIdentifier:
    field: str
    raw_value: str
    normalized_value: str
    locator: str


class ExtractionStatus(str, Enum):
    PARSED = "parsed"
    PARTIAL = "partially_parsed"
    METADATA_ONLY = "metadata_only"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass(frozen=True)
class ExtractionIssue:
    source_id: str
    locator: str
    code: str
    severity: Literal["ERROR", "WARNING", "DEFERRED"]


@dataclass(frozen=True)
class ExtractionResult:
    source: SourceRef
    format: str
    status: ExtractionStatus
    observations: tuple[Observation, ...]
    issues: tuple[ExtractionIssue, ...]
    metadata: Mapping[str, object]


@dataclass(frozen=True)
class MatchReason:
    field: str
    observation_source: SourceRef
    identifier_locator: str
    identity_sources: tuple[Identifier, ...] = ()


@dataclass(frozen=True)
class MatchedObservation:
    observation: Observation
    reasons: tuple[MatchReason, ...]


@dataclass(frozen=True)
class SubjectEvidence:
    user_id: str | None
    matches: tuple[MatchedObservation, ...]
    issues: tuple[str, ...]


@dataclass(frozen=True)
class ResourceState:
    system_id: str
    resource_id: str
    data_category: str
    as_of: datetime
    observations: tuple[Observation, ...]
    unresolved_reason: str | None  # None only after reconstruction resolves state
    scope: "PhysicalScope | None" = None
    dimensions: tuple["DimensionState", ...] = ()
    match_reasons: tuple[MatchReason, ...] = ()
    gaps: tuple[str, ...] = ()
    recreation: tuple["StateTransition", ...] = ()

    def get(self, dimension: str) -> "DimensionState":
        return next((d for d in self.dimensions if d.dimension == dimension),
                    DimensionState(dimension, "UNKNOWN", "UNKNOWN", (), ()))

    @property
    def record_existence(self) -> str:
        return self.get("record_existence").value

    @property
    def identifiability(self) -> str:
        return self.get("identifiability").value

    @property
    def data_flow(self) -> str:
        return self.get("data_flow").value

    @property
    def restore_access(self) -> str:
        return self.get("restore_access").value


@dataclass(frozen=True, order=True)
class PhysicalScope:
    # Empty strings mean unspecified, never an assertion of a global scope.
    table: str = ""
    topology: str = ""
    region: str = ""
    shard: str = ""
    data_store: str = ""
    collection: str = ""
    source_origin: str = ""
    storage_key: str = ""


@dataclass(frozen=True)
class NormalizedFact:
    dimension: str
    value: str
    source: SourceRef
    observed_at: datetime
    field: str
    raw_value: object
    locator: str


@dataclass(frozen=True)
class SelectionTrace:
    source: SourceRef
    reason: str
    dimension: str = ""


@dataclass(frozen=True)
class DimensionState:
    dimension: str
    value: str
    epistemic: Literal["OBSERVED", "UNKNOWN", "CONFLICT"]
    supporting: tuple[NormalizedFact, ...]
    rejected: tuple[SelectionTrace, ...]


@dataclass(frozen=True)
class StateTransition:
    kind: str
    before: tuple[NormalizedFact, ...]
    after: tuple[NormalizedFact, ...]
    claims: tuple[Observation, ...] = ()


@dataclass(frozen=True)
class ScopeComparison:
    system_id: str
    resource_id: str
    kind: str
    scopes: tuple[PhysicalScope, ...]
    sources: tuple[SourceRef, ...]


@dataclass(frozen=True)
class CoverageGap:
    code: str
    sources: tuple[SourceRef, ...] = ()
    resource_id: str | None = None


@dataclass(frozen=True)
class VisualDocument:
    source: SourceRef
    coverage: Literal["metadata_only", "text_extracted", "structured_fields_extracted", "review_required"]
    raw_text: str
    regions: tuple[Mapping[str, object], ...]
    candidates: tuple[EvidenceIdentifier, ...]
    time_candidates: tuple[str, ...]
    confidence: float | None
    needs_review: bool
    backend: str
    issues: tuple[str, ...]


@dataclass(frozen=True)
class ResourceStateReport:
    case_id: str
    user_id: str | None
    audit_at: datetime
    aliases: tuple[Identifier, ...]
    resources: tuple[ResourceState, ...]
    conflicts: tuple[CoverageGap, ...]
    gaps: tuple[CoverageGap, ...]
    comparisons: tuple[ScopeComparison, ...]
    activity_claims: tuple[Observation, ...]
    explanations: tuple[SelectionTrace, ...]


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: PolicyAction


@dataclass(frozen=True)
class PolicyDecision:
    resource: ResourceState
    rule: PolicyRule | None
    compliant: bool | None
    reason: str
    component: str = "record"
    finding: str | None = None
    remediation: str | None = None
    verification: str | None = None
    proofs: tuple[NormalizedFact, ...] = ()
    condition_proofs: tuple[SourceRef, ...] = ()
    blockers: tuple[str, ...] = ()
    preserve_record: bool = False


@dataclass(frozen=True)
class Step:
    step_no: int
    phase: Phase
    system_id: str
    resource_id: str
    operation: str
    state: State
    evidence_id: str


@dataclass(frozen=True)
class AuditResult:
    case_id: str
    deletion_status: Status
    steps: tuple[Step, ...]


@dataclass(frozen=True)
class StepBinding:
    step_no: int
    decisions: tuple[PolicyDecision, ...]


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    authorization: str
    result: AuditResult | None  # No fabricated external status for insufficient proof.
    report: ResourceStateReport | None
    decisions: tuple[PolicyDecision, ...]
    bindings: tuple[StepBinding, ...]
    blockers: tuple[CoverageGap, ...]
    execution_order: tuple[int, ...] = ()
