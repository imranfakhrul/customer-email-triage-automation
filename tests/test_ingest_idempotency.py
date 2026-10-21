"""Unit tests for SQLite idempotency store and Node 01 Ingest logic."""

from datetime import datetime, timezone, timedelta
import os
import tempfile
import unittest

from db.database import TriageDatabase
from nodes.ingest import ingest_node, should_continue_triage
from state import TriageState


class TestIdempotencyAndIngest(unittest.TestCase):
    def setUp(self):
        """Creates a temporary SQLite database for isolated test execution."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_triage.db")
        self.db = TriageDatabase(db_path=self.db_path)

    def tearDown(self):
        """Cleans up temporary directory and database."""
        self.temp_dir.cleanup()

    def test_database_initialization(self):
        """Verifies schema is created with proper indices and columns."""
        record = self.db.get_record("nonexistent_id")
        self.assertIsNone(record)

    def test_acquire_new_email(self):
        """Verifies brand new email is acquired with status 'processing' and retry_count 0."""
        allowed, outcome, record = self.db.check_and_acquire(
            email_id="msg_001",
            thread_id="th_001",
            message_id="raw_msg_001",
            sender_email="alice@acme.com",
        )
        self.assertTrue(allowed)
        self.assertEqual(outcome, "acquired_new")
        self.assertEqual(record["status"], "processing")
        self.assertEqual(record["retry_count"], 0)

        # Check DB directly
        stored = self.db.get_record("msg_001")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["sender_email"], "alice@acme.com")
        self.assertEqual(stored["status"], "processing")

    def test_in_flight_lock_skipped(self):
        """Verifies that an email currently in-flight (< 10 minutes) cannot be re-acquired."""
        self.db.check_and_acquire("msg_002", "th_002")

        # Second check immediately after
        allowed, outcome, record = self.db.check_and_acquire("msg_002", "th_002")
        self.assertFalse(allowed)
        self.assertEqual(outcome, "in_flight")
        self.assertEqual(record["status"], "processing")

    def test_already_completed_skipped(self):
        """Verifies that a completed ('done') email is treated as duplicate and skipped."""
        self.db.check_and_acquire("msg_003", "th_003")
        self.db.mark_done("msg_003", routing_status="routed", dispatch_target="github")

        allowed, outcome, record = self.db.check_and_acquire("msg_003", "th_003")
        self.assertFalse(allowed)
        self.assertEqual(outcome, "already_completed")
        self.assertEqual(record["status"], "done")
        self.assertEqual(record["dispatch_target"], "github")

    def test_stale_lock_recovery(self):
        """Verifies that an in-flight record older than 10m is recovered and retry_count incremented."""
        self.db.check_and_acquire("msg_004", "th_004", stale_minutes=10, max_retries=3)

        # Manually backdate updated_at by 15 minutes
        stale_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE email_triage SET updated_at = ? WHERE email_id = ?",
                (stale_time, "msg_004"),
            )

        # Attempt acquire with 10 min stale threshold
        allowed, outcome, record = self.db.check_and_acquire(
            "msg_004", "th_004", stale_minutes=10, max_retries=3
        )
        self.assertTrue(allowed)
        self.assertEqual(outcome, "recovered_stale")
        self.assertEqual(record["retry_count"], 1)
        self.assertEqual(record["routing_status"], "stale_recovery")

    def test_stale_lock_max_retries_exceeded(self):
        """Verifies that stale lock fails when retry count reaches max_retries."""
        self.db.check_and_acquire("msg_005", "th_005", stale_minutes=10, max_retries=2)

        # Backdate and simulate retry_count = 2 (max retries)
        stale_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE email_triage SET updated_at = ?, retry_count = 2 WHERE email_id = ?",
                (stale_time, "msg_005"),
            )

        allowed, outcome, record = self.db.check_and_acquire(
            "msg_005", "th_005", stale_minutes=10, max_retries=2
        )
        self.assertFalse(allowed)
        self.assertEqual(outcome, "max_retries_exceeded")
        self.assertEqual(record["status"], "failed")

    def test_failed_retry_eligibility(self):
        """Verifies that failed email can be retried until max_retries is reached."""
        self.db.check_and_acquire("msg_006", "th_006")
        self.db.mark_failed("msg_006", error_message="API connection timeout")

        # Retry attempt 1
        allowed, outcome, record = self.db.check_and_acquire(
            "msg_006", "th_006", max_retries=2
        )
        self.assertTrue(allowed)
        self.assertEqual(outcome, "retry_failed")
        self.assertEqual(record["retry_count"], 1)

        # Mark failed again
        self.db.mark_failed("msg_006", error_message="API connection timeout")

        # Retry attempt 2
        allowed, outcome, record = self.db.check_and_acquire(
            "msg_006", "th_006", max_retries=2
        )
        self.assertTrue(allowed)
        self.assertEqual(outcome, "retry_failed")
        self.assertEqual(record["retry_count"], 2)

        # Mark failed again
        self.db.mark_failed("msg_006", error_message="API connection timeout")

        # Retry attempt 3 -> should exceed max_retries
        allowed, outcome, record = self.db.check_and_acquire(
            "msg_006", "th_006", max_retries=2
        )
        self.assertFalse(allowed)
        self.assertEqual(outcome, "max_retries_exceeded")

    def test_active_thread_detection(self):
        """Verifies active thread bypass logic when a thread has prior completed emails."""
        thread_id = "thread_customer_99"

        # Email 1 in thread: arrives and completes
        self.db.check_and_acquire("email_first", thread_id)
        self.db.mark_done(
            "email_first", routing_status="routed", dispatch_target="freescout"
        )

        # Email 2 in same thread: check active thread
        self.assertTrue(
            self.db.is_active_thread(thread_id, exclude_email_id="email_second")
        )
        # Check an unrelated thread
        self.assertFalse(self.db.is_active_thread("thread_unknown"))

    def test_ingest_node_flow_and_domain_extraction(self):
        """Tests ingest_node end-to-end normalization, domain extraction, and state setup."""
        input_state: TriageState = {
            "email_id": "test_mail_1",
            "message_id": "msg_head_1",
            "thread_id": "th_head_1",
            "sender_email": "John.Doe@Enterprise-Client.co.uk",
            "sender_domain": "",
            "email_subject": "Urgent: Payment Failed",
            "email_body": "Our wire transfer did not go through.",
            "raw_body": "",
            "has_attachments": True,
            "cleaned_body": None,
            "masked_body": None,
            "token_map": {},
            "is_sensitive": False,
            "sensitive_reason": None,
            "is_spam": None,
            "gatekeeper_decision": None,
            "gatekeeper_confidence": None,
            "is_threat": None,
            "threat_details": None,
            "customer_tier": None,
            "sla_target": None,
            "classification": None,
            "labels_to_apply": [],
            "is_starred": False,
            "dispatch_target": None,
            "dispatch_status": None,
            "retry_count": 0,
            "error_message": None,
            "routing_status": None,
            "is_active_thread": None,
        }

        output = ingest_node(input_state, db=self.db)

        self.assertEqual(output["email_id"], "test_mail_1")
        self.assertEqual(output["sender_domain"], "enterprise-client.co.uk")
        self.assertEqual(output["raw_body"], "Our wire transfer did not go through.")
        self.assertEqual(output["dispatch_status"], "processing")
        self.assertEqual(output["routing_status"], "processing")
        self.assertFalse(output["is_active_thread"])
        self.assertEqual(output["retry_count"], 0)

        # Route decision
        self.assertEqual(should_continue_triage(output), "continue")

    def test_ingest_node_duplicate_skipping(self):
        """Tests ingest_node with duplicate email already marked 'done'."""
        self.db.check_and_acquire("test_dup_1", "th_dup")
        self.db.mark_done("test_dup_1")

        state: TriageState = {
            "email_id": "test_dup_1",
            "message_id": "test_dup_1",
            "thread_id": "th_dup",
            "sender_email": "dup@example.com",
            "sender_domain": "example.com",
            "email_subject": "Test",
            "email_body": "Hello",
            "raw_body": "Hello",
            "has_attachments": False,
            "cleaned_body": None,
            "masked_body": None,
            "token_map": {},
            "is_sensitive": False,
            "sensitive_reason": None,
            "is_spam": None,
            "gatekeeper_decision": None,
            "gatekeeper_confidence": None,
            "is_threat": None,
            "threat_details": None,
            "customer_tier": None,
            "sla_target": None,
            "classification": None,
            "labels_to_apply": [],
            "is_starred": False,
            "dispatch_target": None,
            "dispatch_status": None,
            "retry_count": 0,
            "error_message": None,
            "routing_status": None,
            "is_active_thread": None,
        }

        output = ingest_node(state, db=self.db)
        self.assertEqual(output["dispatch_status"], "done")
        self.assertEqual(output["routing_status"], "duplicate_skipped")
        self.assertEqual(should_continue_triage(output), "end")

    def test_ingest_node_active_thread_continuation(self):
        """Tests ingest_node recognizing an active conversation continuation."""
        # Initial message completed in thread
        self.db.check_and_acquire("thread_msg_1", "thread_active_42")
        self.db.mark_done("thread_msg_1")

        # Second message in same thread
        followup_state: TriageState = {
            "email_id": "thread_msg_2",
            "message_id": "thread_msg_2",
            "thread_id": "thread_active_42",
            "sender_email": "client@acme.com",
            "sender_domain": "acme.com",
            "email_subject": "Re: Support ticket",
            "email_body": "Following up on the above ticket",
            "raw_body": "Following up on the above ticket",
            "has_attachments": False,
            "cleaned_body": None,
            "masked_body": None,
            "token_map": {},
            "is_sensitive": False,
            "sensitive_reason": None,
            "is_spam": None,
            "gatekeeper_decision": None,
            "gatekeeper_confidence": None,
            "is_threat": None,
            "threat_details": None,
            "customer_tier": None,
            "sla_target": None,
            "classification": None,
            "labels_to_apply": [],
            "is_starred": False,
            "dispatch_target": None,
            "dispatch_status": None,
            "retry_count": 0,
            "error_message": None,
            "routing_status": None,
            "is_active_thread": None,
        }

        output = ingest_node(followup_state, db=self.db)
        self.assertTrue(output["is_active_thread"])
        self.assertEqual(output["routing_status"], "active_thread_continuation")
        self.assertEqual(output["dispatch_status"], "processing")
        self.assertEqual(should_continue_triage(output), "continue")


if __name__ == "__main__":
    unittest.main()
