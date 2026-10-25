"""Deterministic step planner interface; no model-produced compliance verdicts."""
from collections import defaultdict
from typing import Sequence
from .models import AuditResult, OPERATION_CONTRACT, Phase, PolicyDecision, Request, Status, Step, StepBinding


class InsufficientEvidence(ValueError):
    """Internal blocker, never a fourth serialized deletion status."""


def verification_closure(decisions):
    """All applicable known-resource checks, including compliant scopes.

    Unknown conditions remain explicit decisions without an invented check. A
    logical check retains every supporting physical-scope decision in its binding.
    This inventory exists even if uncertainty prevents a responsible verdict.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        if decision.verification:
            key = decision.verification, decision.resource.system_id, decision.resource.resource_id
            grouped[key].append(decision)
    return {key: tuple(grouped[key]) for key in sorted(grouped, key=lambda k:(list(OPERATION_CONTRACT).index(k[0]), k[1], k[2]))}


def closure_inventory(outcome):
    """Grounded per-scope inventory; uncertainty is not a missing-resource guess."""
    emitted = {(s.operation,s.system_id,s.resource_id) for s in outcome.result.steps} if outcome.result else set()
    return [{"system_id": d.resource.system_id, "resource_id": d.resource.resource_id,
             "category": d.resource.data_category, "scope": repr(d.resource.scope),
             "component": d.component, "rule_id": d.rule.rule_id if d.rule else None,
             "compliant": d.compliant, "condition_or_state_reason": d.reason,
             "verification": d.verification,
             "emitted": bool(d.verification and (d.verification,d.resource.system_id,d.resource.resource_id) in emitted),
             "source_ids": sorted({f.source.evidence_id for f in d.proofs}),
             "state": d.resource.record_existence,
             "blocked": list(d.blockers)} for d in outcome.decisions]


def compile_plan(request: Request, decisions: Sequence[PolicyDecision], blockers=()):
    violations = [d for d in decisions if d.compliant is False and d.finding and d.remediation and d.proofs]
    if violations:
        status = Status.INCOMPLETE
    elif decisions and all(d.compliant is True for d in decisions) and not blockers:
        status = Status.COMPLETE
    else:
        return None, ()
    grouped = defaultdict(list)
    for d in decisions:
        if status == Status.INCOMPLETE and d in violations:
            grouped[(d.finding, d.resource.system_id, d.resource.resource_id)].append(d)
            grouped[(d.remediation, d.resource.system_id, d.resource.resource_id)].append(d)
    grouped.update(verification_closure(decisions))
    steps, bindings = [], []
    # Official serialized order is independent of an execution dependency graph.
    # All known scopes remain in each binding even when the wire target is logical.
    for number, key in enumerate(sorted(grouped, key=lambda k: (list(Phase).index(OPERATION_CONTRACT[k[0]][0]),
                                                               list(OPERATION_CONTRACT).index(k[0]), k[1], k[2])), 1):
        operation, system, resource = key
        phase, state = OPERATION_CONTRACT[operation]
        must_cite = phase == Phase.FINDING or status == Status.COMPLETE
        proof = [f for d in grouped[key] for f in d.proofs]
        if must_cite and not proof:
            raise InsufficientEvidence("step_has_no_admissible_proof")
        # Choose a deterministic witness only among agreeing, previously selected
        # factual supports. This never chooses truth between contradictory facts.
        witness = max(proof, key=lambda f: (f.observed_at, f.source.available_at, f.source.evidence_id, f.source.locator)) if proof else None
        steps.append(Step(number, phase, system, resource, operation, state, witness.source.evidence_id if must_cite else ""))
        bindings.append(StepBinding(number, tuple(grouped[key])))
    return AuditResult(request.case_id, status, tuple(steps)), tuple(bindings)


def plan_steps(request: Request, decisions: Sequence[PolicyDecision]) -> AuditResult:
    """Compile findings, dependency-safe remediation and final-state checks."""
    result, _ = compile_plan(request, decisions, tuple(code for d in decisions for code in d.blockers))
    if result is None:
        raise InsufficientEvidence("case_has_no_responsible_external_status")
    return result


def execution_order(result, bindings):
    """Return remediation step numbers in dependency order, without executing work.

    Official wire order remains operation/system/resource. A source_resource_id
    edge orders downstream cleanup before its uniquely identified source cleanup.
    Disable/block steps precede all record changes. Cycles are explicit blockers.
    """
    steps = {s.step_no: s for s in result.steps if s.phase == Phase.REMEDIATION}
    edges = {n: set() for n in steps}
    controls = {n for n, s in steps.items() if s.operation in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}}
    for n, step in steps.items():
        if n not in controls:
            edges[n].update(controls)
    by_resource = defaultdict(list)
    for n, step in steps.items():
        by_resource[step.resource_id].append(n)
    for binding in bindings:
        downstream = binding.step_no
        if downstream not in steps or downstream in controls:
            continue
        for decision in binding.decisions:
            for observation in decision.resource.observations:
                for payload in (observation.attributes, observation.attributes.get("document", {})):
                    source = payload.get("source_resource_id") if hasattr(payload, "get") else None
                    matches = by_resource.get(source, ())
                    if len(matches) == 1 and matches[0] != downstream:
                        edges[matches[0]].add(downstream)
    ordered = []
    while len(ordered) < len(steps):
        ready = sorted(n for n in steps if n not in ordered and edges[n] <= set(ordered))
        if not ready:
            raise InsufficientEvidence("remediation_dependency_cycle")
        ordered.append(ready[0])
    return tuple(ordered)
