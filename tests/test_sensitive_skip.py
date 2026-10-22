"""Unit tests for Node 04 Sensitive-Skip Rules and Diversion Handler."""

import os
import tempfile
import unittest

from db.database import TriageDatabase
from nodes.sensitive_skip import (
    evaluate_sensitive,
    sensitive_skip_node,
    should_route_after_sensitive,
)
from state import TriageState


class TestSensitiveSkip(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_sensitive.db")
        self.db = TriageDatabase(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sensitive_keyword_in_body(self):
        """Verifies sensitive keywords in body trigger sensitive diversion."""
        body = "Please update my account. Here is a scan of my passport and driver's license."
        is_sensitive, reason = evaluate_sensitive(text=body)

        self.assertTrue(is_sensitive)
        self.assertIn("passport", reason.lower())

    def test_sensitive_keyword_in_subject(self):
        """Verifies sensitive keywords in subject trigger sensitive diversion."""
        subject = "Urgent: Court Order and Subpoena Served"
        body = "See attached legal documents."
        is_sensitive, reason = evaluate_sensitive(text=body, subject=subject)

        self.assertTrue(is_sensitive)
        self.assertTrue("court order" in reason.lower() or "subpoena" in reason.lower())

    def test_false_positive_prevention(self):
        """Verifies word boundaries prevent false triggers on 'policy' (police) and 'denied' (nid)."""
        body = (
            "Our company security policy requires two-factor authentication. "
            "My login attempt was denied because my password expired."
        )
        is_sensitive, reason = evaluate_sensitive(text=body)

        self.assertFalse(is_sensitive)
        self.assertIsNone(reason)

    def test_high_credential_density_triggers_sensitive(self):
        """Verifies high concentration of sensitive tokens (> max_code_density 4) triggers diversion."""
        text = "Multiple credentials compromised."
        token_map = {
            "[API_KEY_1]": "sk_test_dummy_12345",
            "[API_KEY_2]": "rk_test_dummy_12345",
            "[CREDIT_CARD_1]": "4000-0000-0000-0001",
            "[CREDIT_CARD_2]": "4000-0000-0000-0002",
            "[SSN_1]": "000-00-0001",
        }
        is_sensitive, reason = evaluate_sensitive(
            text=text,
            token_map=token_map,
            config={"privacy": {"max_code_density": 4}},
        )

        self.assertTrue(is_sensitive)
        self.assertIn("High credential density", reason)

    def test_normal_support_email_not_sensitive(self):
        """Verifies regular customer support inquiries pass through without trigger."""
        body = "Can you help me export my analytics reports to CSV? Thanks."
        is_sensitive, reason = evaluate_sensitive(text=body, subject="CSV Export Help")

        self.assertFalse(is_sensitive)
        self.assertIsNone(reason)

    def test_sensitive_skip_node_state_updates(self):
        """Verifies LangGraph node execution updates state with Review/Sensitive label and target."""
        # Create record in DB first
        self.db.check_and_acquire("email_sens_01", "th_sens_01")

        state: TriageState = {
            "email_id": "email_sens_01",
            "message_id": "msg_sens_01",
            "thread_id": "th_sens_01",
            "sender_email": "lawyer@legalcorp.com",
            "sender_domain": "legalcorp.com",
            "email_subject": "Formal Lawsuit Notice",
            "email_body": "This is a formal lawsuit notice regarding breach of contract.",
            "raw_body": "This is a formal lawsuit notice regarding breach of contract.",
            "has_attachments": True,
            "cleaned_body": "This is a formal lawsuit notice regarding breach of contract.",
            "masked_body": "This is a formal lawsuit notice regarding breach of contract.",
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
            "labels_to_apply": ["inbound"],
            "is_starred": False,
            "dispatch_target": None,
            "dispatch_status": "processing",
            "retry_count": 0,
            "error_message": None,
            "routing_status": "processing",
            "is_active_thread": False,
        }

        output = sensitive_skip_node(state, db=self.db)

        self.assertTrue(output["is_sensitive"])
        self.assertIn("lawsuit", output["sensitive_reason"].lower())
        self.assertIn("Review/Sensitive", output["labels_to_apply"])
        self.assertIn("inbound", output["labels_to_apply"])
        self.assertTrue(output["is_starred"])
        self.assertEqual(output["dispatch_target"], "Review/Sensitive")
        self.assertEqual(output["dispatch_status"], "done")
        self.assertEqual(output["routing_status"], "sensitive_diverted")

        # Verify SQLite record is updated to done and diverted
        record = self.db.get_record("email_sens_01")
        self.assertEqual(record["status"], "done")
        self.assertEqual(record["routing_status"], "sensitive_diverted")
        self.assertEqual(record["dispatch_target"], "Review/Sensitive")

    def test_should_route_after_sensitive(self):
        """Verifies conditional router directs sensitive emails to 'end' and others to 'continue'."""
        sens_state: TriageState = {
            "is_sensitive": True,
            "sensitive_reason": "Matched keyword",
        }  # type: ignore
        self.assertEqual(should_route_after_sensitive(sens_state), "end")

        normal_state: TriageState = {
            "is_sensitive": False,
            "sensitive_reason": None,
        }  # type: ignore
        self.assertEqual(should_route_after_sensitive(normal_state), "continue")

    def test_billing_intent_phrases_vs_benign_refund(self):
        """Verifies polite refund requests mentioning chargebacks are not quarantined,
        while explicit threats to file a chargeback are quarantined."""
        benign_refund = "Please refund my $20, I don't want to file a chargeback."
        is_sensitive, reason = evaluate_sensitive(text=benign_refund)
        self.assertFalse(is_sensitive)
        self.assertIsNone(reason)

        hostile_dispute = "I will file a chargeback if this isn't fixed today!"
        is_sensitive_hostile, hostile_reason = evaluate_sensitive(text=hostile_dispute)
        self.assertTrue(is_sensitive_hostile)
        self.assertIn("chargeback", hostile_reason.lower())


if __name__ == "__main__":
    unittest.main()
