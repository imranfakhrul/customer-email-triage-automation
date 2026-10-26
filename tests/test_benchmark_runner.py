"""Unit tests for Benchmark Runner (Fix C1).

Verifies:
1. Benchmark defaults to offline mode unless --live is explicitly passed.
2. Comprehensive field assertions check 100% of keys in the scenario expected dictionary.
3. Natural duplicate delivery without artificial database state tampering.
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from db.database import TriageDatabase
import main as main_mod
from pipeline import create_triage_pipeline, run_triage_pipeline
from utils.jev_client import JevClient


class TestBenchmarkRunnerC1(unittest.TestCase):
    """Test suite for Fix C1 benchmark runner enhancements."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_bench_c1.db")
        self.db = TriageDatabase(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_offline_mode_in_argument_parsing(self):
        """main.py CLI parser must default to offline=True unless --live is passed."""
        test_cases = [
            ([], True),                           # default: offline
            (["--offline"], True),                # explicit --offline: offline
            (["--live"], False),                  # explicit --live: online
            (["--live", "--offline"], True),      # both: safety offline wins
        ]

        for argv, expected_offline in test_cases:
            with self.subTest(argv=argv):
                with patch.object(sys, "argv", ["main.py"] + argv), \
                     patch("main.prepare_runtime") as mock_prep, \
                     patch("main.run_benchmark_suite", return_value=True) as mock_bench:
                    main_mod.main()
                    mock_prep.assert_called_once_with(offline=expected_offline)
                    mock_bench.assert_called_once()
                    self.assertEqual(mock_bench.call_args[1]["offline"], expected_offline)

    def test_natural_duplicate_delivery(self):
        """Verifies duplicate delivery is detected naturally without manual db.mark_done."""
        client = JevClient(api_key="your_placeholder_key", groq_api_key="your_placeholder_key")
        pipeline = create_triage_pipeline(db=self.db, client=client, offline=True)

        payload = {
            "email_id": "em_c1_dup_test",
            "message_id": "<c1-dup@example.com>",
            "thread_id": "th_c1_dup",
            "sender_email": "sender@example.com",
            "email_subject": "Initial transmission",
            "email_body": "This is a legitimate question.",
        }

        # 1st transmission: processed to gatekeeper_approved
        res1 = run_triage_pipeline(payload, pipeline=pipeline, db=self.db, client=client, offline=True)
        self.assertEqual(res1.get("routing_status"), "gatekeeper_approved")
        self.assertEqual(res1.get("dispatch_status"), "done")

        # 2nd transmission: naturally recognized as duplicate without manual DB editing
        res2 = run_triage_pipeline(payload, pipeline=pipeline, db=self.db, client=client, offline=True)
        self.assertEqual(res2.get("routing_status"), "duplicate_skipped")
        self.assertEqual(res2.get("dispatch_status"), "done")

    def test_comprehensive_field_assertions_fail_on_mismatch(self):
        """Asserts that run_benchmark_suite catches any field mismatch in expected."""
        # Create a single-scenario benchmark with an unmatchable expected field
        fake_scenario = {
            "id": "bench_test_failure",
            "name": "Test Failure Scenario",
            "email_id": "em_fail_test",
            "message_id": "<fail@example.com>",
            "thread_id": "th_fail",
            "sender_email": "user@example.com",
            "email_subject": "General question",
            "email_body": "Hello support, this is a clean query.",
            "expected": {
                "routing_status": "gatekeeper_approved",
                "dispatch_status": "done",
                "dispatch_target": "NONEXISTENT_TARGET",  # This must fail assertion
            },
        }

        bench_file = os.path.join(self.temp_dir.name, "fake_bench.json")
        with open(bench_file, "w", encoding="utf-8") as f:
            json.dump([fake_scenario], f)

        # Run benchmark suite with the mismatched expectation
        passed = main_mod.run_benchmark_suite(benchmark_path=bench_file, offline=True)
        self.assertFalse(passed, "Benchmark suite must fail when dispatch_target does not match")


if __name__ == "__main__":
    unittest.main()
