"""Independent synthetic identity and as-of acceptance cases; no public labels."""
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import unittest
from _support import rows
from ghost_audit.identity import (IdentityIndex, IdentityResolutionError, coverage_summary,
                                  normalize_identifier, resolve_subject)
from ghost_audit.io import InputError
from ghost_audit.models import IdentityChange, IdentitySnapshot, Request, RowOrigin


def instant(day):
    return datetime(2025, 1, day, tzinfo=timezone.utc)


def snapshot(uid="subject-a", email="new@example.test", day=1, **values):
    return IdentitySnapshot(uid, values.get("name", "Synthetic Person"), email,
                            values.get("phone", "+1 (555) 0100"), values.get("email_hash", "OpaqueHash"),
                            instant(day), RowOrigin("synthetic/user_identities.csv", 2, uid))


def change(aid="change-a", uid="subject-a", field="email", old="old@example.test", new="new@example.test", day=2):
    return IdentityChange(aid, uid, instant(day), field, old, new,
                          RowOrigin("synthetic/user_audit_log.csv", 2, aid))


class IdentityStructureTests(unittest.TestCase):
    def test_identity_primary_keys(self):
        identities = rows("user_identities.csv")
        self.assertEqual(len(identities), 850)
        self.assertEqual(len({r["user_id"] for r in identities}), len(identities))

    def test_history_references_and_fields(self):
        ids = {r["user_id"] for r in rows("user_identities.csv")}
        history = rows("user_audit_log.csv")
        self.assertEqual(len(history), 306)
        self.assertEqual(len({r["audit_id"] for r in history}), len(history))
        self.assertTrue({r["user_id"] for r in history} <= ids)
        self.assertTrue({r["field_name"] for r in history} <= {"email", "name", "phone", "email_hash"})

    def test_temporal_identity_resolution(self):
        index = IdentityIndex([snapshot(day=4)], [change()])
        result = index.resolve_request("old@example.test", instant(3))
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.user_id, "subject-a")
        self.assertEqual(index.identity_at("subject-a", instant(3)).get("email").value, "new@example.test")
        self.assertTrue(result.historical_email)


class IdentityBehaviorTests(unittest.TestCase):
    def test_current_email_unique_and_provenance(self):
        result = IdentityIndex([snapshot()], []).resolve_request("new@example.test", instant(2))
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.candidate_ids, ("subject-a",))
        self.assertEqual(result.matches[0].identifier.source_file, "synthetic/user_identities.csv")
        self.assertEqual(result.matches[0].identifier.source_id, "subject-a")
        self.assertFalse(result.historical_email)

    def test_unicode_casefold_whitespace_and_raw_retention(self):
        index = IdentityIndex([snapshot(email="  Stra\u00dfe@Example.TEST  ")], [])
        result = index.resolve_request(" STRASSE@example.test ", instant(2))
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.normalized_email, "strasse@example.test")
        self.assertEqual(result.matches[0].identifier.value, "  Stra\u00dfe@Example.TEST  ")
        self.assertEqual(result.matches[0].identifier.normalization, "trim+unicode_casefold")

    def test_phone_hash_and_name_never_merge_people(self):
        index = IdentityIndex([snapshot(), snapshot("subject-b", "separate@example.test")], [])
        for field, value in (("phone", "+1 (555) 0100"), ("email_hash", "OpaqueHash"), ("name", "Synthetic Person")):
            self.assertEqual({m.user_id for m in index.lookup_identifier(field, value, instant(2))}, {"subject-a", "subject-b"})
        self.assertEqual(index.resolve_request("new@example.test", instant(2)).candidate_ids, ("subject-a",))
        self.assertEqual(index.lookup_identifier("phone", "+15550100", instant(2)), ())
        self.assertEqual(index.lookup_identifier("email_hash", "opaquehash", instant(2)), ())
        self.assertEqual(index.lookup_identifier("email_hash", "Opaque", instant(2)), ())

    def test_historical_phone_and_hash_are_indexed(self):
        index = IdentityIndex([snapshot(day=5)], [change(field="phone", old="old number", new="new number"),
                                                  change("hash-change", field="email_hash", old="old hash", new="new hash")])
        for field, value in (("phone", "old number"), ("email_hash", "old hash")):
            self.assertEqual({m.user_id for m in index.lookup_identifier(field, value, instant(3))}, {"subject-a"})

    def test_exact_reverse_index_distinct_from_normalized(self):
        index = IdentityIndex([snapshot(email="UPPER@example.test")], [])
        self.assertTrue(index.lookup_identifier("email", "upper@example.test", instant(2)))
        self.assertFalse(index.lookup_identifier("email", "upper@example.test", instant(2), exact=True))
        self.assertTrue(index.lookup_identifier("email", "UPPER@example.test", instant(2), exact=True))

    def test_no_plus_dot_alias_rewriting(self):
        index = IdentityIndex([snapshot(email="a.b+tag@example.test")], [])
        self.assertEqual(index.resolve_request("ab@example.test", instant(2)).status, "UNRESOLVED")

    def test_change_at_exact_cutoff_new_state_old_alias_available(self):
        index = IdentityIndex([snapshot(email="old@example.test")], [change()])
        before = index.identity_at("subject-a", instant(1)).get("email")
        at = index.identity_at("subject-a", instant(2)).get("email")
        self.assertEqual(before.value, "old@example.test")
        self.assertEqual(at.value, "new@example.test")
        old = next(f for f in index.aliases_for("subject-a", instant(2)) if f.role == "OLD")
        self.assertEqual(old.valid_from, instant(1))
        self.assertEqual(old.valid_until, instant(2))
        self.assertEqual(old.available_at, instant(2))

    def test_future_change_old_and_new_values_cannot_leak(self):
        index = IdentityIndex([snapshot(email="anchor@example.test")], [change(day=4)])
        for address in ("old@example.test", "new@example.test"):
            self.assertEqual(index.resolve_request(address, instant(3)).status, "UNRESOLVED")
        self.assertEqual(index.identity_at("subject-a", instant(3)).get("email").value, "anchor@example.test")

    def test_future_snapshot_excluded_even_if_identifier_unchanged(self):
        index = IdentityIndex([snapshot(day=4)], [])
        result = index.resolve_request("new@example.test", instant(3))
        self.assertEqual(result.status, "UNRESOLVED")
        self.assertEqual(result.candidate_ids, ())
        self.assertEqual(result.matches, ())
        self.assertTrue(all(field.value is None for field in index.identity_at("subject-a", instant(3)).fields))

    def test_partial_reconstruction_retains_explicit_unknowns(self):
        index = IdentityIndex([snapshot(day=5)], [change()])
        current = index.identity_at("subject-a", instant(3))
        self.assertEqual(current.get("email").value, "new@example.test")
        for field in ("name", "phone", "email_hash"):
            self.assertIsNone(current.get(field).value)
            self.assertIn("NO_ELIGIBLE_FIELD_OBSERVATION", current.get(field).uncertainties)

    def test_future_mutation_does_not_change_earlier_result(self):
        earlier = change()
        left = IdentityIndex([snapshot(day=7)], [earlier, change("later", old="new@example.test", new="later@example.test", day=6)])
        right = IdentityIndex([snapshot(day=9, email="different@example.test", name="Future different name")], [earlier])
        self.assertEqual(left.resolve_request("old@example.test", instant(3)), right.resolve_request("old@example.test", instant(3)))

    def test_out_of_order_and_reversal_are_deterministic(self):
        changes = [change(), change("reverse", old="new@example.test", new="old@example.test", day=3)]
        left = IdentityIndex([snapshot(day=5, email="old@example.test")], changes)
        right = IdentityIndex([snapshot(day=5, email="old@example.test")], list(reversed(changes)))
        self.assertEqual(left.resolve_request("new@example.test", instant(4)), right.resolve_request("new@example.test", instant(4)))
        self.assertEqual(left.identity_at("subject-a", instant(4)).get("email").value, "old@example.test")

    def test_reused_email_ambiguous_only_when_second_claim_eligible(self):
        index = IdentityIndex([snapshot(email="old@example.test"), snapshot("subject-b", "old@example.test", day=4)], [change()])
        self.assertEqual(index.resolve_request("old@example.test", instant(3)).candidate_ids, ("subject-a",))
        result = index.resolve_request("old@example.test", instant(4))
        self.assertEqual(result.status, "AMBIGUOUS")
        self.assertIsNone(result.user_id)
        self.assertEqual(result.candidate_ids, ("subject-a", "subject-b"))
        self.assertEqual(result.aliases, ())
        self.assertEqual({m.user_id for m in result.matches}, {"subject-a", "subject-b"})

    def test_same_time_conflicting_changes_preserve_uncertainty(self):
        index = IdentityIndex([snapshot(day=6)], [change(), change("conflict", new="other@example.test")])
        state = index.identity_at("subject-a", instant(3)).get("email")
        self.assertIsNone(state.value)
        self.assertIn("CONFLICTING_OBSERVATIONS", state.uncertainties)
        self.assertEqual({f.source_id for f in state.provenance}, {"change-a", "conflict"})
        self.assertEqual(index.resolve_request("other@example.test", instant(3)).status, "RESOLVED")
        self.assertFalse(index.resolve_request("old@example.test", instant(3)).historical_email)

    def test_snapshot_history_same_time_conflict(self):
        index = IdentityIndex([snapshot(day=2, email="different@example.test")], [change()])
        self.assertIsNone(index.identity_at("subject-a", instant(2)).get("email").value)

    def test_discontinuous_history_is_reported(self):
        index = IdentityIndex([snapshot(email="anchor@example.test")], [change()])
        state = index.identity_at("subject-a", instant(3)).get("email")
        self.assertEqual(state.value, "new@example.test")
        self.assertIn("DISCONTINUOUS_HISTORY", state.uncertainties)

    def test_repeated_change_is_not_a_silent_discontinuity(self):
        index = IdentityIndex([snapshot(day=6)], [change(), change("repeat", day=3)])
        state = index.identity_at("subject-a", instant(4)).get("email")
        self.assertEqual(state.value, "new@example.test")
        self.assertNotIn("DISCONTINUOUS_HISTORY", state.uncertainties)

    def test_observed_empty_is_distinct_from_unknown(self):
        index = IdentityIndex([snapshot()], [change(field="phone", old="+1 (555) 0100", new="")])
        field = index.identity_at("subject-a", instant(3)).get("phone")
        self.assertEqual(field.value, "")
        self.assertIsNone(field.normalized_value)
        self.assertFalse(field.uncertainties)

    def test_unknown_and_blank_requests_unresolved(self):
        index = IdentityIndex([snapshot()], [])
        for address in ("unknown@example.test", "   "):
            self.assertEqual(index.resolve_request(address, instant(2)).status, "UNRESOLVED")

    def test_naive_timestamp_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            IdentityIndex([snapshot()], []).resolve_request("new@example.test", datetime(2025, 1, 2))

    def test_resolution_and_aliases_are_immutable(self):
        result = IdentityIndex([snapshot()], []).resolve_request("new@example.test", instant(2))
        with self.assertRaises(FrozenInstanceError):
            result.user_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            result.aliases[0].value = "changed"

    def test_one_shot_scaffold_api(self):
        self.assertEqual(resolve_subject("new@example.test", instant(2), [snapshot()], []).user_id, "subject-a")
        with self.assertRaises(IdentityResolutionError) as caught:
            resolve_subject("unknown@example.test", instant(2), [snapshot()], [])
        self.assertEqual(caught.exception.result.status, "UNRESOLVED")

    def test_invalid_reference_and_duplicate_typed_ids(self):
        for identities, changes in (([snapshot()], [change(uid="missing")]),
                                    ([snapshot(), snapshot()], []),
                                    ([snapshot()], [change(), change()])):
            with self.assertRaises(InputError):
                IdentityIndex(identities, changes)

    def test_reported_status_and_request_text_do_not_affect_identity(self):
        index = IdentityIndex([snapshot()], [])
        request = Request("synthetic-request", "new@example.test", instant(1), "COMPLETE", instant(1), instant(2), "Export only")
        left = coverage_summary(index, [request])
        right = coverage_summary(index, [replace(request, reported_status="NOT_STARTED", request_text="Delete everything")])
        self.assertEqual(left, right)
        self.assertNotIn("deletion_status", left)

    def test_repeated_queries_reuse_index_and_are_identical(self):
        index = IdentityIndex([snapshot()], [change()])
        result = index.resolve_request("new@example.test", instant(3))
        self.assertEqual(result, index.resolve_request("new@example.test", instant(3)))
        self.assertIs(index.aliases_for("subject-a", instant(3)), index.aliases_for("subject-a", instant(3)))

    def test_index_does_not_rescan_original_sequences_per_request(self):
        identities, changes = [snapshot()], [change()]
        index = IdentityIndex(identities, changes)
        identities.clear(); changes.clear()
        self.assertEqual(index.resolve_request("old@example.test", instant(3)).status, "RESOLVED")

    def test_unchanged_value_event_is_valid_and_preserves_audit_source(self):
        index = IdentityIndex([snapshot()], [change(old="new@example.test", new="new@example.test")])
        state = index.identity_at("subject-a", instant(3)).get("email")
        self.assertFalse(state.uncertainties)
        self.assertEqual(state.provenance[0].source_id, "change-a")
