"""Unit tests for Node 03 Local spaCy NER and Regex PII Masker."""

import unittest

from nodes.pii_masker import (
    load_tech_terms_whitelist,
    mask_pii,
    pii_masker_node,
    reset_tech_terms_cache,
    unmask_text,
)
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

    def test_tech_terms_whitelist_prevents_person_masking(self):
        """Verifies tech whitelist keeps infrastructure and tool names intact while masking person names."""
        reset_tech_terms_cache()

        # 1. "Our Postgres and Kubernetes cluster is down" -> no [PERSON_*], text unchanged
        text1 = "Our Postgres and Kubernetes cluster is down."
        m1, t1 = mask_pii(text1)
        self.assertNotIn("[PERSON", m1)
        self.assertIn("Postgres", m1)
        self.assertIn("Kubernetes", m1)
        self.assertEqual(m1, text1)

        # 2. "Hi, I'm John Doe, our Postgres pool is exhausted" -> "John Doe" is masked, "Postgres" is not
        text2 = "Hi, I'm John Doe, our Postgres pool is exhausted"
        m2, t2 = mask_pii(text2)
        self.assertNotIn("John Doe", m2)
        self.assertIn("[PERSON_1]", m2)
        self.assertEqual(t2.get("[PERSON_1]"), "John Doe")
        self.assertIn("Postgres", m2)
        self.assertNotIn("Postgres", t2.values())

        # 3. "Please contact Apollo Chen" -> "Apollo Chen" (full person name) is still masked
        text3 = "Please contact Apollo Chen"
        m3, t3 = mask_pii(text3)
        self.assertNotIn("Apollo Chen", m3)
        self.assertIn("[PERSON_1]", m3)
        self.assertEqual(t3.get("[PERSON_1]"), "Apollo Chen")

        # 4. Case variations: "postgres", "POSTGRES" are not masked
        text4 = "Our postgres instance failed while POSTGRES replica was restarting."
        m4, t4 = mask_pii(text4)
        self.assertNotIn("[PERSON", m4)
        self.assertIn("postgres", m4)
        self.assertIn("POSTGRES", m4)

        # 5. Tool names like Grafana which spaCy tags as PERSON when starting sentence
        text5 = "Grafana is not loading on port 3000."
        m5, t5 = mask_pii(text5)
        self.assertNotIn("[PERSON", m5)
        self.assertIn("Grafana", m5)

        # 6. Full person name with tech term like "Grafana Smith" must still be masked
        text6 = "Please escalate this to Grafana Smith immediately."
        m6, t6 = mask_pii(text6)
        self.assertNotIn("Grafana Smith", m6)
        self.assertIn("[PERSON_1]", m6)
        self.assertEqual(t6.get("[PERSON_1]"), "Grafana Smith")

    def test_tech_terms_whitelist_loading(self):
        """Verifies loading external tech terms file populates whitelist correctly."""
        whitelist = load_tech_terms_whitelist()
        expected_terms = [
            "postgres",
            "postgresql",
            "mysql",
            "redis",
            "kafka",
            "kubernetes",
            "docker",
            "terraform",
            "grafana",
            "prometheus",
            "jenkins",
            "github",
            "gitlab",
            "jira",
            "slack",
            "zendesk",
            "freescout",
            "nginx",
            "apache",
            "elasticsearch",
            "mongodb",
            "rabbitmq",
            "django",
            "flask",
            "fastapi",
            "react",
            "node.js",
            "apollo",
        ]
        for term in expected_terms:
            self.assertIn(term, whitelist)


if __name__ == "__main__":
    unittest.main()
