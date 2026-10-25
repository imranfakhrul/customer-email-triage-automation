"""Unit tests for Fix B4: State and SQLite Agreement, Atomic Persistence, and Migration."""

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from db.database import TriageDatabase, PersistenceError
from nodes.jev_gatekeeper import jev_gatekeeper_node, should_route_after_gatekeeper
from nodes.sensitive_skip import sensitive_skip_node
from state import TriageState


class TestFixB4StateDbSync(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_b4.db")
        self.db = TriageDatabase(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_b4_approved_email_and_active_thread_state_db_agreement(self):
        """Verifies state and DB row agree on gatekeeper_approved and done, for both fresh and thread emails."""
        # 1. Fresh approved email
        self.db.check_and_acquire("em_fresh_01", "th_fresh_01", sender_email="alice@corp.com")
        state_fresh: TriageState = {
            "email_id": "em_fresh_01",
            "message_id": "<msg-01@corp.com>",
            "thread_id": "th_fresh_01",
            "sender_email": "alice@corp.com",
            "sender_domain": "corp.com",
            "email_subject": "Need help with API",
            "masked_subject": "Need help with API",
            "email_body": "Can you advise on endpoint rate limits?",
            "masked_body": "Can you advise on endpoint rate limits?",
            "is_active_thread": False,
            "labels_to_apply": ["inbound"],
        }
        res_fresh = jev_gatekeeper_node(state_fresh, db=self.db, offline=True)
        self.assertEqual(res_fresh["routing_status"], "gatekeeper_approved")
        self.assertEqual(res_fresh["dispatch_status"], "done")
        self.assertFalse(res_fresh["is_active_thread"])

        row_fresh = self.db.get_record("em_fresh_01")
        self.assertEqual(row_fresh["routing_status"], "gatekeeper_approved")
        self.assertEqual(row_fresh["status"], "done")
        self.assertEqual(row_fresh["is_active_thread"], 0)

        # 2. Active thread reply
        self.db.check_and_acquire("em_reply_01", "th_fresh_01", sender_email="alice@corp.com")
        state_reply: TriageState = {
            "email_id": "em_reply_01",
            "message_id": "<msg-02@corp.com>",
            "thread_id": "th_fresh_01",
            "sender_email": "alice@corp.com",
            "sender_domain": "corp.com",
            "email_subject": "Re: Need help with API",
            "masked_subject": "Re: Need help with API",
            "email_body": "Thanks, that worked!",
            "masked_body": "Thanks, that worked!",
            "is_active_thread": True,
            "labels_to_apply": ["inbound"],
        }
        res_reply = jev_gatekeeper_node(state_reply, db=self.db, offline=True)
        self.assertEqual(res_reply["routing_status"], "gatekeeper_approved")
        self.assertEqual(res_reply["dispatch_status"], "done")
        self.assertTrue(res_reply["is_active_thread"])

        row_reply = self.db.get_record("em_reply_01")
        self.assertEqual(row_reply["routing_status"], "gatekeeper_approved")
        self.assertEqual(row_reply["status"], "done")
        self.assertEqual(row_reply["is_active_thread"], 1)

    def test_b4_persisted_masked_text_contains_no_raw_pii(self):
        """Verifies persisted text equals masked state values and contains none of the raw PII."""
        email_id = "em_pii_check_01"
        self.db.check_and_acquire(email_id, "th_pii_01", sender_email="john.smith@example.com")

        raw_name = "Johnathan Q. Smith"
        raw_email = "john.smith@example.com"
        raw_card = "4111 1111 1111 1111"

        state: TriageState = {
            "email_id": email_id,
            "message_id": "<pii-01@example.com>",
            "thread_id": "th_pii_01",
            "sender_email": raw_email,
            "sender_domain": "example.com",
            "email_subject": f"Billing issue for {raw_name}",
            "email_body": f"My card {raw_card} was billed twice. Contact me at {raw_email}.",
            "raw_body": f"My card {raw_card} was billed twice. Contact me at {raw_email}.",
            "cleaned_body": f"My card {raw_card} was billed twice. Contact me at {raw_email}.",
            "masked_subject": "Billing issue for [PERSON_1_a1b2]",
            "masked_body": "My card [CREDIT_CARD_1_a1b2] was billed twice. Contact me at [EMAIL_1_a1b2].",
            "is_active_thread": False,
        }

        jev_gatekeeper_node(state, db=self.db, offline=True)
        record = self.db.get_record(email_id)

        # Check equivalence to masked state values
        self.assertEqual(record["masked_subject"], state["masked_subject"])
        self.assertEqual(record["masked_body"], state["masked_body"])

        # Assert no raw PII exists in DB row
        self.assertNotIn(raw_name, record["masked_subject"])
        self.assertNotIn(raw_name, record["masked_body"])
        self.assertNotIn(raw_card, record["masked_body"])
        self.assertNotIn(raw_email, record["masked_body"])

    def test_b4_text_persistence_policy_outcomes(self):
        """Verifies manual_review persists masked text, while spam_skipped and sensitive_diverted persist NULL."""
        # 1. manual_review
        self.db.check_and_acquire("em_man_01", "th_man_01")
        state_man: TriageState = {
            "email_id": "em_man_01",
            "masked_subject": "Suspicious inquiry",
            "masked_body": "Claim your prize now!",
            "is_active_thread": False,
        }
        mock_client = MagicMock()
        mock_client.classify.return_value = {
            "decision": "manual_review",
            "confidence": 0.50,
            "is_threat": False,
            "is_spam": False,
            "classifier_used": "groq",
        }
        jev_gatekeeper_node(state_man, client=mock_client, db=self.db)
        rec_man = self.db.get_record("em_man_01")
        self.assertEqual(rec_man["routing_status"], "manual_review")
        self.assertEqual(rec_man["masked_subject"], "Suspicious inquiry")
        self.assertEqual(rec_man["masked_body"], "Claim your prize now!")

        # 2. spam_skipped
        self.db.check_and_acquire("em_spam_01", "th_spam_01")
        state_spam: TriageState = {
            "email_id": "em_spam_01",
            "masked_subject": "Cheap viagra meds",
            "masked_body": "Buy cheap meds without prescription",
            "is_active_thread": False,
        }
        mock_spam_client = MagicMock()
        mock_spam_client.classify.return_value = {
            "decision": "spam",
            "confidence": 0.99,
            "is_threat": False,
            "is_spam": True,
            "classifier_used": "jev",
        }
        jev_gatekeeper_node(state_spam, client=mock_spam_client, db=self.db)
        rec_spam = self.db.get_record("em_spam_01")
        self.assertEqual(rec_spam["routing_status"], "spam_skipped")
        self.assertIsNone(rec_spam["masked_subject"])
        self.assertIsNone(rec_spam["masked_body"])

        # 3. sensitive_diverted
        self.db.check_and_acquire("em_sens_01", "th_sens_01")
        state_sens: TriageState = {
            "email_id": "em_sens_01",
            "email_subject": "Formal Subpoena Served",
            "email_body": "Please find the attached subpoena.",
            "masked_subject": "Formal Subpoena Served",
            "masked_body": "Please find the attached subpoena.",
            "raw_body": "Please find the attached subpoena.",
            "token_map": {},
        }
        sensitive_skip_node(state_sens, db=self.db)
        rec_sens = self.db.get_record("em_sens_01")
        self.assertEqual(rec_sens["routing_status"], "sensitive_diverted")
        self.assertIsNone(rec_sens["masked_subject"])
        self.assertIsNone(rec_sens["masked_body"])

    def test_b4_persist_masked_text_false_stores_null(self):
        """Verifies persist_masked_text=false in config stores NULL for masked_subject and masked_body."""
        email_id = "em_no_persist_01"
        self.db.check_and_acquire(email_id, "th_01")
        custom_config = {"system": {"persist_masked_text": False}}

        self.db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            masked_subject="Masked Subject",
            masked_body="Masked Body",
            config=custom_config,
        )
        rec = self.db.get_record(email_id)
        self.assertEqual(rec["routing_status"], "gatekeeper_approved")
        self.assertIsNone(rec["masked_subject"])
        self.assertIsNone(rec["masked_body"])

    def test_b4_schema_migration_preserves_rows_and_is_idempotent(self):
        """Verifies schema migration on old database preserves existing rows and runs idempotently."""
        old_db_path = os.path.join(self.temp_dir.name, "old_schema.db")
        # 1. Create table with legacy schema (pre-B4)
        conn = sqlite3.connect(old_db_path)
        conn.execute("""
            CREATE TABLE email_triage (
                email_id TEXT PRIMARY KEY,
                message_id TEXT,
                thread_id TEXT,
                sender_email TEXT,
                status TEXT NOT NULL CHECK(status IN ('processing', 'done', 'failed')),
                retry_count INTEGER DEFAULT 0,
                routing_status TEXT,
                dispatch_target TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email, status, retry_count,
                routing_status, dispatch_target, error_message, created_at, updated_at
            ) VALUES (
                'old_email_1', '<msg-1@legacy.com>', 'th_legacy_1', 'user@legacy.com',
                'done', 0, 'gatekeeper_approved', NULL, NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
        """)
        conn.commit()
        conn.close()

        # 2. Open with TriageDatabase (triggers migration in _init_db)
        legacy_db = TriageDatabase(db_path=old_db_path)

        # Assert new columns exist
        with legacy_db.get_connection() as c:
            cur = c.execute("PRAGMA table_info(email_triage);")
            columns = {row["name"] for row in cur.fetchall()}

        for col in [
            "masked_subject",
            "masked_body",
            "is_active_thread",
            "gatekeeper_decision",
            "gatekeeper_confidence",
            "classifier_used",
        ]:
            self.assertIn(col, columns)

        # Assert old row is intact
        old_rec = legacy_db.get_record("old_email_1")
        self.assertIsNotNone(old_rec)
        self.assertEqual(old_rec["sender_email"], "user@legacy.com")
        self.assertIsNone(old_rec["masked_body"])

        # 3. Opening a second time is harmless (idempotent)
        reopened_db = TriageDatabase(db_path=old_db_path)
        reopened_rec = reopened_db.get_record("old_email_1")
        self.assertEqual(reopened_rec["email_id"], "old_email_1")

    def test_b4_mark_done_missing_email_raises_persistence_error(self):
        """Verifies mark_done on missing email_id raises PersistenceError."""
        with self.assertRaises(PersistenceError):
            self.db.mark_done("non_existent_email_id_999", routing_status="gatekeeper_approved")

    def test_b4_mark_done_database_failure_handling_and_safe_logging(self):
        """Verifies DB write failure returns persist_failed / failed, router ends, mark_failed called, and safe log."""
        email_id = "em_db_fail_01"
        self.db.check_and_acquire(email_id, "th_01")

        state: TriageState = {
            "email_id": email_id,
            "masked_subject": "Confidential customer inquiry for John Doe",
            "masked_body": "Sensitive details with card 4111-1111-1111-1111",
            "is_active_thread": False,
        }

        # Mock mark_done to raise OperationalError
        with patch.object(self.db, "mark_done", side_effect=sqlite3.OperationalError("disk I/O error")):
            with patch.object(self.db, "mark_failed") as mock_mark_failed:
                with self.assertLogs("nodes.jev_gatekeeper", level="ERROR") as cm:
                    res = jev_gatekeeper_node(state, db=self.db, offline=True)

                    # State contract on failure
                    self.assertEqual(res["routing_status"], "persist_failed")
                    self.assertEqual(res["dispatch_status"], "failed")
                    self.assertEqual(res["error_message"], "database write failed")

                    # Router aborts workflow
                    self.assertEqual(should_route_after_gatekeeper(res), "end")

                    # Best-effort mark_failed was called
                    mock_mark_failed.assert_called_once_with(email_id, error_message="database write failed")

                    # Verify log output: contains exception class name, does NOT contain error message or email text
                    log_output = "\n".join(cm.output)
                    self.assertIn("OperationalError", log_output)
                    self.assertIn(email_id, log_output)
                    self.assertNotIn("disk I/O error", log_output)
                    self.assertNotIn("Confidential customer inquiry", log_output)
                    self.assertNotIn("4111-1111-1111-1111", log_output)

    def test_b4_get_gatekeeper_approved_returns_masked_body(self):
        """Verifies get_gatekeeper_approved returns masked_body and new triage metadata."""
        email_id = "em_approved_retrieve_01"
        self.db.check_and_acquire(email_id, "th_retrieve_01", sender_email="dev@example.com")
        self.db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            masked_subject="Feature request: Webhook retries",
            masked_body="Could you add exponential backoff for [PERSON_1_a2b3]?",
            is_active_thread=True,
            gatekeeper_decision="legitimate",
            gatekeeper_confidence=0.98,
            classifier_used="regex",
        )

        records = self.db.get_gatekeeper_approved()
        matching = [r for r in records if r["email_id"] == email_id]
        self.assertEqual(len(matching), 1)
        rec = matching[0]

        self.assertEqual(rec["masked_subject"], "Feature request: Webhook retries")
        self.assertEqual(rec["masked_body"], "Could you add exponential backoff for [PERSON_1_a2b3]?")
        self.assertEqual(rec["is_active_thread"], 1)
        self.assertEqual(rec["gatekeeper_decision"], "legitimate")
        self.assertEqual(rec["gatekeeper_confidence"], 0.98)
        self.assertEqual(rec["classifier_used"], "regex")


if __name__ == "__main__":
    unittest.main()
