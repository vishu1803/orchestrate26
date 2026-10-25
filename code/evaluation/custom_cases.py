"""Participant-created scenarios, isolated from inference and public labels."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CustomCase:
    name: str
    request_text: str
    setup: str
    expected_status: str
    expected_checks: tuple[str, ...]
    mutation: str


CUSTOM_CASES = (
    CustomCase("access_without_deletion", "Please export a copy of my account data.",
               "No deletion authorization. Any workflow status is irrelevant.",
               "NOT_APPLICABLE", ("steps_json=[]", "No remediation authorized"),
               "Change request to explicitly authorize deletion; intent must change."),
    CustomCase("tombstone_exposes_email", "Delete my personal information.",
               "Before cutoff: tombstone readback has stable user reference and a direct email; REDACT rule applies.",
               "INCOMPLETE", ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED",
                              "Preserve stable internal user reference"),
               "Remove all prohibited direct identifiers; retained reference alone is compliant."),
    CustomCase("sync_reintroduces_record", "Delete my account and personal information.",
               "Delete reports success; later pre-cutoff readback observes a recreated profile and enabled connector.",
               "INCOMPLETE", ("REPORT_REMAINING_RECORD", "REPORT_ACTIVE_DATA_FLOW",
                              "DISABLE_DATA_FLOW before DELETE_RECORD", "Verify flow disabled and record absent"),
               "Move recreation evidence after cutoff; it must not affect the earlier audit."),
)


def run_independent_cases():
    """New executable Phase 4 fixtures, isolated from public labels and inference."""
    from datetime import datetime, timezone
    from ghost_audit.models import (ExtractionResult, ExtractionStatus, IdentitySnapshot,
                                    Request, RowOrigin, SourceRef)
    from ghost_audit.normalization import freeze, make_observation
    from ghost_audit.identity import IdentityIndex
    from ghost_audit.evidence import EvidenceIndex
    from ghost_audit.io import DatasetReader
    from ghost_audit.timeline import StateEngine
    from ghost_audit.pipeline import AuditPipeline
    from ghost_audit.output import validate_case
    time = datetime(2025, 1, 2, tzinfo=timezone.utc)
    cutoff = datetime(2025, 1, 3, tzinfo=timezone.utc)
    identity = IdentitySnapshot("fixture-subject", "Fictional Person", "fixture@example.invalid", "fixture-phone", "fixture-hash", time,
                                RowOrigin("participant-fixture", 2, "fixture-subject"))
    rules = DatasetReader().rules()
    def run(name, text, records, expected_status, expected_operations):
        observations = []
        for n, raw in enumerate(records):
            source = SourceRef(f"fixture_{name}", time, f"/records/{n}", "participant-fixture", "participant", "fixture-content")
            obs, errors = make_observation({"observed_at": time.isoformat(), **raw}, source)
            assert not errors
            observations.append(obs)
        result = ExtractionResult(SourceRef(f"fixture_{name}", time, "", content_sha256="fixture-content"), ".json", ExtractionStatus.PARSED,
                                  tuple(observations), (), freeze({}))
        index = EvidenceIndex([result], identity_index=IdentityIndex([identity], []))
        pipeline = AuditPipeline(StateEngine(index), rules)
        request = Request(name, identity.email, time, "COMPLETE", time, cutoff, text)
        outcome = pipeline.audit(request)
        actual = outcome.result.deletion_status.value if outcome.result else None
        operations = {s.operation for s in outcome.result.steps} if outcome.result else set()
        passed = actual == expected_status and operations == set(expected_operations) and not outcome.blockers
        if outcome.result:
            validate_case(outcome, request, index, require_complete_coverage=True)
        return {"name": name, "expected_status": expected_status, "actual_status": actual,
                "expected_operations": list(expected_operations), "actual_operations": sorted(operations),
                "passed": passed, "blockers": [g.code for g in outcome.blockers]}, outcome, pipeline, request
    tombstone = {"system_id": "identity_service", "resource_id": "fixture-tombstone", "record_type": "ACCOUNT_TOMBSTONE",
                 "user_id": identity.user_id, "account_status": "DELETED", "references_required": True,
                 "name": None, "email": None, "phone": None, "email_hash": identity.email_hash}
    legal = {"system_id": "legal_service", "resource_id": "fixture-legal", "record_type": "LEGAL_HOLD_RECORD",
             "user_id": identity.user_id, "hold_active": True}
    rows = [run("phase4_access_scope", "Please export my account data; do not delete anything.",
                [{"system_id": "account_service", "resource_id": "fixture-profile", "record_type": "USER_PROFILE", "user_id": identity.user_id}],
                "NOT_APPLICABLE", ()),
            run("phase4_tombstone_legal_preservation", "Please remove my personal information; keep required legal records.", [tombstone, legal],
                "INCOMPLETE", ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_PRESENT")),
            run("phase4_flow_restore_exposure", "Please delete my account and personal data.",
                [{"system_id": "account_service", "resource_id": "fixture-profile", "record_type": "USER_PROFILE", "user_id": identity.user_id},
                 {"system_id": "integration_service", "resource_id": "fixture-flow", "record_type": "DATA_FLOW", "user_id": identity.user_id, "enabled": True},
                 {"system_id": "backup_service", "resource_id": "fixture-backup", "record_type": "BACKUP_ARCHIVE", "user_id": identity.user_id, "restore_allowed": True}],
                "INCOMPLETE", ("REPORT_REMAINING_RECORD", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK", "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
                               "DELETE_RECORD", "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"))]
    return tuple(rows)
