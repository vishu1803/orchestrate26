"""Deterministic wire compilation and strict source-bound case validation."""
from dataclasses import asdict, fields
import csv
import json
from pathlib import Path
from typing import Mapping, Sequence
from .models import AuditResult, OPERATION_CONTRACT, OUTPUT_COLUMNS, Phase, Status, Step
from .state_facts import normalize_facts, temporal_rejection

STEP_FIELDS = tuple(field.name for field in fields(Step))


def validate_step_shape(step: Mapping[str, object]) -> None:
    """Check exact fields, primitive types and allowed operation/phase/state triple."""
    if set(step) != set(STEP_FIELDS):
        raise ValueError("A step must have exactly the seven specified fields")
    if type(step["step_no"]) is not int or step["step_no"] < 1:
        raise ValueError("step_no must be a positive integer")
    if any(not isinstance(step[k], str) for k in STEP_FIELDS if k != "step_no"):
        raise ValueError("All other step fields must be strings")
    if not step["system_id"] or not step["resource_id"]:
        raise ValueError("System and resource IDs are required")
    if OPERATION_CONTRACT.get(step["operation"]) != (step["phase"], step["state"]):
        raise ValueError("Invalid operation/phase/state triple")


def validate_steps_contract(status: str, steps: list[dict[str, object]], *, allow_partial=False) -> None:
    """Check wire semantics only, without claiming evidence truth/completeness."""
    Status(status)
    if not isinstance(steps, list):
        raise ValueError("steps_json must decode to an array")
    if status == Status.NOT_APPLICABLE:
        if steps:
            raise ValueError("NOT_APPLICABLE requires []")
        return
    if not steps and not (allow_partial and status == Status.INCOMPLETE):
        raise ValueError("Deletion cases require evidence/plan steps")
    keys = []
    for number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ValueError("Each step must be an object")
        validate_step_shape(step)
        if step["step_no"] != number:
            raise ValueError("Step numbers must be consecutive")
        phase = step["phase"]
        if status == Status.COMPLETE and phase != Phase.VERIFICATION:
            raise ValueError("COMPLETE has verification only")
        must_cite = phase == Phase.FINDING or status == Status.COMPLETE
        if bool(step["evidence_id"]) != must_cite:
            raise ValueError("Invalid evidence citation placement")
        keys.append((list(Phase).index(Phase(phase)), list(OPERATION_CONTRACT).index(step["operation"]),
                     step["system_id"], step["resource_id"]))
    if keys != sorted(keys):
        raise ValueError("Steps are not canonically ordered")
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate logical target/operation")
    actions = {}
    for step in steps:
        if step["phase"] == Phase.REMEDIATION and step["operation"] in {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}:
            target = step["system_id"], step["resource_id"]
            if target in actions and actions[target] != step["operation"]:
                raise ValueError("Conflicting record treatments")
            actions[target] = step["operation"]
    if status == Status.INCOMPLETE and not allow_partial and {s["phase"] for s in steps} != {p.value for p in Phase}:
        raise ValueError("INCOMPLETE requires all three phases")


def result_row(result: AuditResult, *, allow_partial=False) -> dict[str, str]:
    steps = [asdict(s) for s in result.steps]
    validate_steps_contract(result.deletion_status, steps, allow_partial=allow_partial)
    return {"case_id": result.case_id, "deletion_status": result.deletion_status.value,
            "steps_json": json.dumps(steps, ensure_ascii=False, sort_keys=True, separators=(",", ":"))}


def write_output(results: Sequence[AuditResult], path: Path, expected_case_ids=None) -> None:
    """Enforce requested coverage and serialize validated results deterministically.

    Callers must use validate_case with strict coverage before any real export.
    Phase 4 exercises this serializer with synthetic temporary files only.
    """
    rows = [result_row(r) for r in sorted(results, key=lambda r: r.case_id)]
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_output_case_id")
    if expected_case_ids is not None and set(ids) != set(expected_case_ids):
        raise ValueError("output_case_coverage_mismatch")
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


def validate_case(outcome, request, evidence_index, *, require_complete_coverage=False):
    """Validate real source supports, target binding, clocks, steps and coverage.

    A partial INCOMPLETE diagnostic may have blockers, but it is not final-run
    ready. The strict coverage flag rejects it for a production export.
    """
    result = outcome.result
    if result is None:
        raise ValueError("case_blocked_no_external_status")
    if outcome.case_id != request.case_id or result.case_id != request.case_id:
        raise ValueError("case_id_mismatch")
    result_row(result)
    if require_complete_coverage and outcome.blockers:
        raise ValueError("unresolved_case_coverage")
    if result.deletion_status == Status.NOT_APPLICABLE:
        if outcome.authorization != "OTHER_REQUEST" or outcome.report is not None:
            raise ValueError("non_deletion_gate_bypassed")
        return
    if outcome.authorization != "AUTHORIZED" or outcome.report is None:
        raise ValueError("deletion_not_authorized_or_unlinked")
    if result.deletion_status == Status.COMPLETE and (outcome.blockers or any(d.compliant is not True for d in outcome.decisions)):
        raise ValueError("complete_without_all_required_proof")
    originals = {(o.source.evidence_id, o.source.locator): o for o in evidence_index.observations}
    bindings = {b.step_no: b for b in outcome.bindings}
    for step in result.steps:
        binding = bindings.get(step.step_no)
        if not binding or not binding.decisions:
            raise ValueError("missing_step_provenance_binding")
        witnesses = []
        for d in binding.decisions:
            if (d.resource.system_id, d.resource.resource_id) != (step.system_id, step.resource_id):
                raise ValueError("step_target_not_bound")
            if d.resource not in outcome.report.resources:
                raise ValueError("resource_not_in_linked_report")
            expected = d.finding if step.phase == Phase.FINDING else d.remediation if step.phase == Phase.REMEDIATION else d.verification
            if expected != step.operation:
                raise ValueError("operation_not_supported_by_policy_decision")
            if step.phase == Phase.FINDING and d.compliant is not False:
                raise ValueError("finding_without_proven_violation")
            if step.operation == "DELETE_RECORD" and d.preserve_record:
                raise ValueError("retained_record_would_be_deleted")
            for condition_source in d.condition_proofs:
                observed = originals.get((condition_source.evidence_id, condition_source.locator))
                if observed is None or condition_source != observed.source or observed not in d.resource.observations or temporal_rejection(observed, request.audit_at):
                    raise ValueError("invalid_policy_condition_source")
            for proof in d.proofs:
                key = proof.source.evidence_id, proof.source.locator
                observation = originals.get(key)
                if observation is None or observation not in d.resource.observations:
                    raise ValueError("evidence_not_in_bound_source")
                if proof.source != observation.source or temporal_rejection(observation, request.audit_at):
                    raise ValueError("inadmissible_or_modified_source")
                actual, _ = normalize_facts(observation)
                if proof not in actual or proof.observed_at > request.audit_at:
                    raise ValueError("unsupported_normalized_fact")
                if not any(proof in dimension.supporting for dimension in d.resource.dimensions):
                    raise ValueError("stale_or_unselected_evidence")
                if step.evidence_id == proof.source.evidence_id:
                    witnesses.append(proof)
        if step.evidence_id and not witnesses:
            raise ValueError("citation_does_not_prove_step")
    # Every proven violation needs its finding/action/check; already compliant
    # obligations still need a final verification in an incomplete case.
    for d in outcome.decisions:
        required = [d.verification] if d.verification else []
        if d.compliant is False:
            required += [d.finding, d.remediation]
        for operation in required:
            if operation and not any(s.operation == operation and (s.system_id, s.resource_id) == (d.resource.system_id, d.resource.resource_id) for s in result.steps):
                raise ValueError("missing_required_plan_step")


def validate_rows(rows, expected_case_ids):
    ids = []
    for row in rows:
        if tuple(row) != OUTPUT_COLUMNS or any(not isinstance(v, str) for v in row.values()):
            raise ValueError("invalid_output_columns_or_types")
        ids.append(row["case_id"])
        def unique(pairs):
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ValueError("duplicate_json_key")
                result[k] = v
            return result
        steps = json.loads(row["steps_json"], object_pairs_hook=unique)
        validate_steps_contract(row["deletion_status"], steps)
    if ids != sorted(ids) or len(set(ids)) != len(ids) or set(ids) != set(expected_case_ids):
        raise ValueError("output_sort_uniqueness_or_coverage")
