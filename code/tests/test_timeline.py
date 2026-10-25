"""Time-field structural checks and activated as-of acceptance slot."""
from datetime import datetime
import unittest
from _support import rows


class TimelineStructureTests(unittest.TestCase):
    def test_csv_timestamps_are_timezone_aware(self):
        columns = {"deletion_requests.csv": ("requested_at", "reported_at", "audit_at"),
                   "sample_deletion_requests.csv": ("requested_at", "reported_at", "audit_at"),
                   "user_identities.csv": ("updated_at",), "user_audit_log.csv": ("event_time",),
                   "system_activity.csv": ("event_time",), "evidence_files.csv": ("captured_at",)}
        for name, fields in columns.items():
            for row in rows(name):
                for field in fields:
                    self.assertIsNotNone(datetime.fromisoformat(row[field].replace("Z", "+00:00")).utcoffset())

    def test_as_of_reconstruction(self):
        from test_state import observation, moment
        from ghost_audit.timeline import reconstruct
        result = reconstruct([observation(day=5, capture=5, result="FOUND"),
                              observation("future", day=6, capture=6, result="NOT_FOUND")], moment(5))
        self.assertEqual(result[0].record_existence, "PRESENT")
