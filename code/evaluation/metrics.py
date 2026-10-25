"""Independent scoring interface; definitions are in evaluation_report.md."""
from collections import Counter, defaultdict
from itertools import zip_longest
import json
from typing import Mapping, Sequence

FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
ALIGN = ("phase", "system_id", "resource_id", "operation")
SET_FIELDS = tuple(f for f in FIELDS if f != "step_no")


def _rows(rows):
    result = {}
    for row in rows:
        case_id = row["case_id"]
        if case_id in result:
            raise ValueError("duplicate_case_id_in_evaluation")
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError("invalid_evaluation_status")
        steps = row.get("steps", row.get("steps_json"))
        if isinstance(steps, str):
            steps = json.loads(steps)
        if not isinstance(steps, (tuple, list)):
            raise ValueError("invalid_evaluation_step_array")
        for step in steps:
            if set(step) != set(FIELDS) or type(step["step_no"]) is not int or any(not isinstance(step[k], str) for k in SET_FIELDS):
                raise ValueError("invalid_evaluation_step_fields")
        result[case_id] = (row["deletion_status"], list(steps))
    return result


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _aligned(left, right):
    groups = [defaultdict(list), defaultdict(list)]
    for side, steps in zip(groups, (left, right)):
        for step in steps:
            side[tuple(step[k] for k in ALIGN)].append(step)
    for key in sorted(set(groups[0]) | set(groups[1])):
        yield from zip_longest(groups[0][key], groups[1][key])


def score_predictions(predictions: Sequence[Mapping[str, object]],
                      labels: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Measure status, step multiset, aligned fields and exact sequence."""
    predicted, expected = _rows(predictions), _rows(labels)
    if set(predicted) - set(expected):
        raise ValueError("unexpected_prediction_cases")
    true_positive = predicted_count = expected_count = 0
    status_correct = sequence_correct = row_correct = aligned_count = indexed_count = indexed_correct = 0
    field_correct = Counter({f: 0 for f in FIELDS})
    group_counts = {field: defaultdict(Counter) for field in ("phase", "operation", "system_id")}
    mismatches = []
    for case_id in sorted(expected):
        gold_status, gold = expected[case_id]
        status, steps = predicted.get(case_id, (None, []))
        status_correct += status == gold_status
        sequence_match = case_id in predicted and steps == gold
        sequence_correct += sequence_match
        row_correct += sequence_match and status == gold_status
        left = Counter(tuple(s[k] for k in SET_FIELDS) for s in steps)
        right = Counter(tuple(s[k] for k in SET_FIELDS) for s in gold)
        true_positive += sum((left & right).values())
        for field, groups in group_counts.items():
            index = SET_FIELDS.index(field)
            for name, tuples in (("expected", right), ("predicted", left), ("true_positive", left & right)):
                for values, count in tuples.items():
                    groups[values[index]][name] += count
        predicted_count += len(steps); expected_count += len(gold)
        for a, b in zip_longest(steps, gold):
            indexed_count += 1
            indexed_correct += a is not None and b is not None and a == b
        for a, b in _aligned(steps, gold):
            aligned_count += 1
            for field in FIELDS:
                field_correct[field] += a is not None and b is not None and a[field] == b[field]
        if status != gold_status or not sequence_match:
            mismatches.append({"case_id": case_id, "predicted_status": status, "expected_status": gold_status,
                               "missing_steps": [dict(zip(SET_FIELDS, s)) for s in (right - left).elements()],
                               "extra_steps": [dict(zip(SET_FIELDS, s)) for s in (left - right).elements()],
                               "predicted_steps": steps, "expected_steps": gold})
    precision, recall = _ratio(true_positive, predicted_count), _ratio(true_positive, expected_count)
    f1 = None if precision is None or recall is None else (2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return {"algorithm": "multiset-v1; field-align-key-occurrence-v1; index-v1", "cases": len(expected),
            "emitted_cases": len(predicted), "missing_cases": sorted(set(expected) - set(predicted)),
            "status": {"correct": status_correct, "total": len(expected), "accuracy": _ratio(status_correct, len(expected))},
            "sequence": {"correct": sequence_correct, "total": len(expected), "accuracy": _ratio(sequence_correct, len(expected))},
            "exact_row": {"correct": row_correct, "total": len(expected), "accuracy": _ratio(row_correct, len(expected))},
            "steps": {"true_positive": true_positive, "predicted": predicted_count, "expected": expected_count,
                      "false_positive": predicted_count - true_positive, "false_negative": expected_count - true_positive,
                      "precision": precision, "recall": recall, "f1": f1},
            "order_aware_steps": {"correct": indexed_correct, "total": indexed_count, "accuracy": _ratio(indexed_correct, indexed_count)},
            "fields": {f: {"correct": field_correct[f], "total": aligned_count, "accuracy": _ratio(field_correct[f], aligned_count)} for f in FIELDS},
            "field_overall": {"correct": sum(field_correct.values()), "total": aligned_count * len(FIELDS), "accuracy": _ratio(sum(field_correct.values()), aligned_count * len(FIELDS))},
            "label_status_counts": dict(sorted(Counter(s for s, _ in expected.values()).items())),
            "grouped_steps": {field: {name: {"true_positive": counts["true_positive"], "expected": counts["expected"],
                                            "predicted": counts["predicted"], "recall": _ratio(counts["true_positive"], counts["expected"])}
                                      for name,counts in sorted(groups.items())} for field,groups in group_counts.items()},
            "mismatches": mismatches}


def categorize_mismatches(metrics, outcomes):
    """Deterministic symptoms and named blockers, not inferred hidden root truth."""
    counts = Counter({k: 0 for k in ("wrong_intent", "missing_resource", "decoy_false_link", "wrong_historical_alias", "wrong_physical_scope",
                                   "wrong_audit_cutoff", "wrongly_claimed_COMPLETE", "policy_mapping", "missing_or_wrong_citation",
                                   "missing_or_extra_verification", "sort_sequence_mismatch", "document_semantic_gap", "insufficient_evidence")})
    by_id = {o.case_id: o for o in outcomes}
    for mismatch in metrics["mismatches"]:
        tags = set()
        outcome = by_id[mismatch["case_id"]]
        missing, extra = mismatch["missing_steps"], mismatch["extra_steps"]
        predicted = mismatch["predicted_steps"]
        gold = mismatch["expected_steps"]
        p_targets = {(s["system_id"], s["resource_id"]) for s in predicted}
        if any((s["system_id"], s["resource_id"]) not in p_targets for s in missing):
            tags.add("missing_resource")
        if any(s["phase"] == "VERIFICATION" for s in (*missing, *extra)):
            tags.add("missing_or_extra_verification")
        if any(all(a[k] == b[k] for k in SET_FIELDS if k != "evidence_id") and a["evidence_id"] != b["evidence_id"] for a in missing for b in extra):
            tags.add("missing_or_wrong_citation")
        if any((a["system_id"], a["resource_id"], a["phase"]) == (b["system_id"], b["resource_id"], b["phase"]) and a["operation"] != b["operation"] for a in missing for b in extra):
            tags.add("policy_mapping")
        if not missing and not extra and predicted != gold:
            tags.add("sort_sequence_mismatch")
        if mismatch["predicted_status"] == "COMPLETE" and mismatch["expected_status"] != "COMPLETE":
            tags.add("wrongly_claimed_COMPLETE")
        if outcome.authorization != "AUTHORIZED" and mismatch["expected_status"] != "NOT_APPLICABLE":
            tags.add("wrong_intent")
        if outcome.result is None or outcome.blockers:
            tags.add("insufficient_evidence")
        if any(g.code == "unsupported_or_unknown_rule_condition" for g in outcome.blockers):
            tags.add("unresolved_rule_condition")
        if any(g.code == "requested_account_scope_not_established" for g in outcome.blockers):
            tags.add("unresolved_account_scope")
        if any("visual" in g.code or "document" in g.code for g in outcome.blockers):
            tags.add("document_semantic_gap")
        # Decoy/alias/cutoff/physical-scope mistakes require independent attribution;
        # absent that evidence they remain zero, not guessed from an omitted step.
        mismatch["categories"] = sorted(tags)
        counts.update(tags)
    return dict(sorted(counts.items()))
