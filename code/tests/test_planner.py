"""Wire-schema and mutation checks, not a working remediation planner."""
from copy import deepcopy
import unittest
from _support import ROOT
from ghost_audit.output import STEP_FIELDS, validate_step_shape, validate_steps_contract


def verification():
    return {"step_no": 1, "phase": "VERIFICATION", "system_id": "synthetic_system",
            "resource_id": "synthetic_resource", "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT", "evidence_id": "synthetic_source"}


class WireContractTests(unittest.TestCase):
    def test_exact_step_fields(self):
        self.assertEqual(STEP_FIELDS, ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"))
        validate_step_shape(verification())

    def test_shape_rejects_invalid_mutations(self):
        for key, value in (("extra", "x"), ("step_no", True), ("step_no", 0), ("state", "PRESENT"), ("operation", "INVENTED"), ("resource_id", "")):
            step = verification(); step[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_step_shape(step)
        step = verification(); del step["evidence_id"]
        with self.assertRaises(ValueError):
            validate_step_shape(step)

    def test_not_applicable_requires_empty_array(self):
        validate_steps_contract("NOT_APPLICABLE", [])
        with self.assertRaises(ValueError):
            validate_steps_contract("NOT_APPLICABLE", [verification()])

    def test_complete_verification_requires_citation(self):
        validate_steps_contract("COMPLETE", [verification()])
        step = verification(); step["evidence_id"] = ""
        with self.assertRaises(ValueError):
            validate_steps_contract("COMPLETE", [step])
        step.update(phase="FINDING", operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id="synthetic_source")
        with self.assertRaises(ValueError):
            validate_steps_contract("COMPLETE", [step])

    def test_consecutive_numbers_and_canonical_order(self):
        a = verification(); b = deepcopy(a); b.update(step_no=2, resource_id="aaa")
        with self.assertRaises(ValueError):
            validate_steps_contract("COMPLETE", [a, b])
        b.update(step_no=3, resource_id="zzz")
        with self.assertRaises(ValueError):
            validate_steps_contract("COMPLETE", [a, b])

    def test_dependency_safe_remediation(self):
        from evaluation.custom_cases import run_independent_cases
        _, outcome, _, _ = run_independent_cases()[2]
        operations = [s.operation for s in outcome.result.steps if s.phase == "REMEDIATION"]
        self.assertEqual(operations, ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"])
        self.assertEqual(list(outcome.execution_order), [s.step_no for s in outcome.result.steps if s.phase == "REMEDIATION"])
