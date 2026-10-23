"""Unit tests for Node 04 Sensitive-Skip Rules and Diversion Handler."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock

from db.database import TriageDatabase
from nodes.sensitive_skip import (
    evaluate_sensitive,
    sensitive_skip_node,
    should_route_after_sensitive,
)
from nodes.jev_gatekeeper import jev_gatekeeper_node
from state import TriageState
from utils.jev_client import JevClient


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

    def test_billing_intent_and_broad_chargeback(self):
        """Verifies polite refund requests without chargebacks pass,
        while any variation of chargeback triggers diversion under broad chargeback rule."""
        benign_refund = "Please refund my $20 for last month's unused seat licenses."
        is_sensitive, reason = evaluate_sensitive(text=benign_refund)
        self.assertFalse(is_sensitive)
        self.assertIsNone(reason)

        for phrase in [
            "I'm going to file a chargeback.",
            "I am going to do a chargeback with my bank",
            "Please refund my $20, I don't want to file a chargeback.",
            "I will file a chargeback if this isn't fixed today!",
        ]:
            with self.subTest(phrase=phrase):
                is_sens, r = evaluate_sensitive(text=phrase)
                self.assertTrue(is_sens)
                self.assertIn("chargeback", r.lower())

    def test_a7_unicode_and_homoglyph_evasion(self):
        """Verifies that Cyrillic, Greek, zero-width, full-width, and case homoglyphs divert."""
        evasion_cases = [
            ("Cyrillic homoglyph 'о'", "Contacting the p\u043elice department.", "police"),
            ("Greek homoglyph 'ο'", "Alerted the p\u03bflice immediately.", "police"),
            ("Zero-width space evasion", "Received a sub\u200bpoena today.", "subpoena"),
            ("Full-width characters", "Notice: ｓｕｂｐｏｅｎａ served.", "subpoena"),
            ("Uppercase Cyrillic variant", "\u041eFFICIAL SUBPOENA delivered.", "subpoena"),
            ("Double space phrase", "Violating a court  order from judge.", "court order"),
            ("Newline phrase", "This is a formal legal\nnotice regarding breach.", "legal notice"),
            ("Hyphenated phrase in email", "Sending a cease-and-desist letter.", "cease and desist"),
            ("Spaced phrase in email", "Sending a cease and desist letter.", "cease and desist"),
        ]

        for name, text, expected_kw in evasion_cases:
            with self.subTest(name=name):
                is_sensitive, reason = evaluate_sensitive(text=text)
                self.assertTrue(is_sensitive, f"Failed to divert for {name}: {text}")
                self.assertIn(expected_kw.lower(), reason.lower())

    def test_a7_subpoena_stripped_by_signature_still_diverts(self):
        """Verifies that a subpoena line appearing after 'Thanks,' (which signature stripper removes)
        is still caught and diverted because evaluate_sensitive inspects raw_body as well."""
        raw_body = (
            "Please find the invoice attached.\n\n"
            "Thanks,\n"
            "John Doe\n"
            "...we will serve a subpoena tomorrow morning..."
        )
        cleaned_body = "Please find the invoice attached."

        state: TriageState = {
            "email_id": "em_subpoena_raw_01",
            "message_id": "msg_001",
            "thread_id": "th_001",
            "sender_email": "john@example.com",
            "sender_domain": "example.com",
            "email_subject": "Invoice Followup",
            "email_body": cleaned_body,
            "raw_body": raw_body,
            "has_attachments": False,
            "cleaned_body": cleaned_body,
            "masked_body": cleaned_body,
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
            "dispatch_status": "processing",
            "retry_count": 0,
            "error_message": None,
            "routing_status": "processing",
            "is_active_thread": False,
        }

        output = sensitive_skip_node(state, db=self.db)
        self.assertTrue(output["is_sensitive"])
        self.assertIn("subpoena", output["sensitive_reason"].lower())
        self.assertEqual(output["routing_status"], "sensitive_diverted")
        # Ensure state body texts were not mutated
        self.assertEqual(state["cleaned_body"], cleaned_body)
        self.assertEqual(state["raw_body"], raw_body)

    def test_a7_russian_text_does_not_crash_or_false_positive(self):
        """Verifies normal Russian text containing letters from homoglyph map does not crash or divert."""
        russian_body = "Привет, как дела? У меня вопрос по подписке и тарифам."
        is_sensitive, reason = evaluate_sensitive(text=russian_body, subject="Вопрос по тарифу")
        self.assertFalse(is_sensitive)
        self.assertIsNone(reason)

    def test_a7_config_punctuation_treated_literally(self):
        """Verifies that keywords containing punctuation (e.g. 'a.b(c)') are treated literally."""
        custom_config = {
            "privacy": {
                "sensitive_keywords": ["a.b(c)"],
                "max_code_density": 4,
            }
        }
        # Literal match
        match_body = "Encountered a critical bug in a.b(c) module."
        is_sens, reason = evaluate_sensitive(text=match_body, config=custom_config)
        self.assertTrue(is_sens)
        self.assertIn("a.b(c)", reason)

        # Regex wildcard attempt: 'aXb(c)' should NOT match
        wildcard_body = "Encountered a critical bug in aXb(c) module."
        is_sens2, reason2 = evaluate_sensitive(text=wildcard_body, config=custom_config)
        self.assertFalse(is_sens2)
        self.assertIsNone(reason2)

    def test_a7_normalized_text_does_not_leave_sensitive_check(self):
        """Proves that homoglyph-normalized text is strictly internal and never leaves sensitive check.
        After evaluating an email containing Greek/Cyrillic characters:
        - The input of the next node (Node 05 Gatekeeper),
        - The payload sent to Jev / Groq client (mocked),
        - And the database row
        all contain the original text, never the normalized or casefolded representation."""
        original_greek_cyrillic = "Hello, parameter \u03b1=10 and token \u043fp\u0438\u0432\u0435\u0442 are valid."
        subject_line = "Inquiry regarding \u03b1 parameters"

        self.db.check_and_acquire("em_leak_test_01", "th_leak_01")

        state: TriageState = {
            "email_id": "em_leak_test_01",
            "message_id": "msg_leak_01",
            "thread_id": "th_leak_01",
            "sender_email": "dev@greek-corp.com",
            "sender_domain": "greek-corp.com",
            "email_subject": subject_line,
            "email_body": original_greek_cyrillic,
            "raw_body": original_greek_cyrillic,
            "has_attachments": False,
            "cleaned_body": original_greek_cyrillic,
            "masked_body": original_greek_cyrillic,
            "masked_subject": subject_line,
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

        # 1. Run Node 04 (Sensitive Skip)
        sens_output = sensitive_skip_node(state, db=self.db)
        state.update(sens_output)

        # Assert next node input retains original characters (NOT normalized Latin)
        self.assertFalse(state["is_sensitive"])
        self.assertEqual(state["masked_body"], original_greek_cyrillic)
        self.assertIn("\u03b1=10", state["masked_body"])
        self.assertIn("\u043fp\u0438\u0432\u0435\u0442", state["masked_body"])

        # 2. Mock Jev/Groq client and run Node 05 (Gatekeeper)
        mock_client = MagicMock(spec=JevClient)
        mock_client.classify.return_value = {
            "decision": "legitimate",
            "confidence": 0.95,
            "is_threat": False,
            "threat_details": None,
            "classifier_used": "jev",
            "raw_response": {},
        }

        gatekeeper_output = jev_gatekeeper_node(state, client=mock_client, db=self.db)
        state.update(gatekeeper_output)

        # Assert payload sent to Jev / Groq contains original masked text, not normalized
        mock_client.classify.assert_called_once()
        called_kwargs = mock_client.classify.call_args.kwargs
        self.assertEqual(called_kwargs["body"], original_greek_cyrillic)
        self.assertEqual(called_kwargs["subject"], subject_line)
        self.assertIn("\u03b1=10", called_kwargs["body"])
        self.assertIn("\u043fp\u0438\u0432\u0435\u0442", called_kwargs["body"])

        # 3. Assert database row preserves original state
        record = self.db.get_record("em_leak_test_01")
        self.assertEqual(record["status"], "done")
        self.assertEqual(record["routing_status"], "gatekeeper_approved")


if __name__ == "__main__":
    unittest.main()
