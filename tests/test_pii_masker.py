"""Unit tests for Node 03 Local spaCy NER and Regex PII Masker."""

import unittest

from nodes.pii_masker import mask_pii, pii_masker_node, unmask_text
from state import TriageState


class TestPiiMasker(unittest.TestCase):
    def test_mask_email_addresses(self):
        """Verifies email addresses are replaced with [EMAIL_N] and duplicates reuse the same token."""
        text = (
            "Please contact alice@acme.com for billing or support@corp.co.uk. "
            "You can also reach alice@acme.com later."
        )
        masked, token_map = mask_pii(text)

        self.assertIn("[EMAIL_1]", masked)
        self.assertIn("[EMAIL_2]", masked)
        self.assertNotIn("alice@acme.com", masked)
        self.assertNotIn("support@corp.co.uk", masked)

        # Verify duplicate reuse
        self.assertEqual(token_map["[EMAIL_1]"], "alice@acme.com")
        self.assertEqual(token_map["[EMAIL_2]"], "support@corp.co.uk")
        self.assertEqual(masked.count("[EMAIL_1]"), 2)

    def test_mask_phone_numbers(self):
        """Verifies US and international phone numbers are redacted."""
        text = (
            "Call our support line at (555) 123-4567 or cell +1-555-987-6543. "
            "Our UK office is +44 20 7946 0958."
        )
        masked, token_map = mask_pii(text)

        self.assertNotIn("(555) 123-4567", masked)
        self.assertNotIn("+1-555-987-6543", masked)
        self.assertNotIn("+44 20 7946 0958", masked)
        self.assertTrue(any(k.startswith("[PHONE_") for k in token_map.keys()))

    def test_mask_api_keys_and_bearer_tokens(self):
        """Verifies common API keys, Bearer tokens, and secrets are masked."""
        text = (
            "My service key is sk_test_dummy_12345 and alternate is rk_test_dummy_12345. "
            "Use Bearer dummy_test_bearer_token_12345."
        )
        masked, token_map = mask_pii(text)

        self.assertNotIn("sk_test_dummy_12345", masked)
        self.assertNotIn("rk_test_dummy_12345", masked)
        self.assertNotIn("dummy_test_bearer_token_12345", masked)
        self.assertTrue(any(k.startswith("[API_KEY_") for k in token_map.keys()))

    def test_mask_credit_cards(self):
        """Verifies credit card numbers (16 digits and Amex 15 digits) are redacted."""
        text = "Card details: 4111 2222 3333 4444 and Amex 3782-822463-10005."
        masked, token_map = mask_pii(text)

        self.assertNotIn("4111 2222 3333 4444", masked)
        self.assertNotIn("3782-822463-10005", masked)
        self.assertTrue(any(k.startswith("[CREDIT_CARD_") for k in token_map.keys()))

    def test_mask_ssn(self):
        """Verifies US Social Security Numbers are redacted."""
        text = "Customer SSN is 123-45-6789 on file."
        masked, token_map = mask_pii(text)

        self.assertNotIn("123-45-6789", masked)
        self.assertEqual(token_map.get("[SSN_1]"), "123-45-6789")

    def test_mask_ip_addresses(self):
        """Verifies IPv4 addresses are redacted."""
        text = "Database connection error connecting to server 192.168.1.105."
        masked, token_map = mask_pii(text)

        self.assertNotIn("192.168.1.105", masked)
        self.assertEqual(token_map.get("[IP_ADDRESS_1]"), "192.168.1.105")

    def test_mask_person_names_via_spacy(self):
        """Verifies spaCy NER detects person names and masks them as [PERSON_N]."""
        text = "My name is John Doe and my colleague is Jane Miller."
        masked, token_map = mask_pii(text)

        # Check that person names are removed
        self.assertNotIn("John Doe", masked)
        self.assertNotIn("Jane Miller", masked)
        self.assertTrue(any(k.startswith("[PERSON_") for k in token_map.keys()))

    def test_unmask_text_bidirectional(self):
        """Verifies unmask_text restores all tokens back to their exact original text."""
        original = (
            "Hello, my name is John Doe. Email me at john@example.com or "
            "call 555-432-1098. Our server is 10.0.0.1."
        )
        masked, token_map = mask_pii(original)
        restored = unmask_text(masked, token_map)

        self.assertEqual(restored, original)

    def test_empty_and_whitespace_inputs(self):
        """Verifies empty or None inputs return empty string and empty token map."""
        m1, t1 = mask_pii("")
        self.assertEqual(m1, "")
        self.assertEqual(t1, {})

        m2, t2 = mask_pii(None)
        self.assertEqual(m2, "")
        self.assertEqual(t2, {})

        self.assertEqual(unmask_text("", {}), "")
        self.assertEqual(unmask_text(None, {}), "")

    def test_pii_masker_node_state_update(self):
        """Verifies LangGraph node updates masked_body and token_map in TriageState."""
        state: TriageState = {
            "email_id": "em_pii_1",
            "message_id": "msg_pii_1",
            "thread_id": "th_pii_1",
            "sender_email": "client@acme.com",
            "sender_domain": "acme.com",
            "email_subject": "Leaked Token Issue",
            "email_body": "Cleaned body from prior node",
            "raw_body": "Cleaned body from prior node",
            "has_attachments": False,
            "cleaned_body": "Please contact Robert at robert@client.com or call 555-888-9999.",
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
            "dispatch_status": "processing",
            "retry_count": 0,
            "error_message": None,
            "routing_status": "processing",
            "is_active_thread": False,
        }

        output = pii_masker_node(state)

        self.assertIn("masked_body", output)
        self.assertIn("token_map", output)
        self.assertNotIn("robert@client.com", output["masked_body"])
        self.assertNotIn("555-888-9999", output["masked_body"])
        self.assertIn("[EMAIL_1]", output["masked_body"])


if __name__ == "__main__":
    unittest.main()
