"""Unit tests for Node 03 Local spaCy NER and Regex PII Masker."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from db.database import TriageDatabase
from nodes.pii_masker import (
    get_spacy_nlp,
    is_external_ai_enabled,
    load_tech_terms_whitelist,
    mask_pii,
    pii_masker_node,
    reset_spacy_cache,
    reset_tech_terms_cache,
    unmask_text,
    validate_startup,
)
from pipeline import create_triage_pipeline, run_triage_pipeline
from state import TriageState
from utils.jev_client import JevClient


class TestPiiMasker(unittest.TestCase):
    def test_mask_email_addresses(self):
        """Verifies email addresses are replaced with [EMAIL_N_nonce] and duplicates reuse the same token."""
        text = (
            "Please contact alice@acme.com for billing or support@corp.co.uk. "
            "You can also reach alice@acme.com later."
        )
        masked, token_map = mask_pii(text)

        self.assertNotIn("alice@acme.com", masked)
        self.assertNotIn("support@corp.co.uk", masked)

        email_1 = [k for k, v in token_map.items() if v == "alice@acme.com"][0]
        email_2 = [k for k, v in token_map.items() if v == "support@corp.co.uk"][0]
        self.assertIn(email_1, masked)
        self.assertIn(email_2, masked)
        self.assertRegex(email_1, r"^\[EMAIL_1_[0-9a-f]{4}\]$")
        self.assertRegex(email_2, r"^\[EMAIL_2_[0-9a-f]{4}\]$")
        self.assertEqual(masked.count(email_1), 2)

    def test_mask_phone_numbers(self):
        """Verifies US and international phone numbers are redacted."""
        text = (
            "Call our support line at (415) 555-2671 or cell +1-212-555-0188. "
            "Our UK office is +44 20 7946 0958."
        )
        masked, token_map = mask_pii(text)

        self.assertNotIn("(415) 555-2671", masked)
        self.assertNotIn("+1-212-555-0188", masked)
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
        text = "Card details: 4111 1111 1111 1111 and Amex 3782-822463-10005."
        masked, token_map = mask_pii(text)

        self.assertNotIn("4111 1111 1111 1111", masked)
        self.assertNotIn("3782-822463-10005", masked)
        self.assertTrue(any(k.startswith("[CREDIT_CARD_") for k in token_map.keys()))

    def test_mask_ssn(self):
        """Verifies US Social Security Numbers are redacted."""
        text = "Customer SSN is 123-45-6789 on file."
        masked, token_map = mask_pii(text)

        self.assertNotIn("123-45-6789", masked)
        self.assertTrue(any(k.startswith("[SSN_1_") and v == "123-45-6789" for k, v in token_map.items()))

    def test_mask_ip_addresses(self):
        """Verifies IPv4 addresses are redacted."""
        text = "Database connection error connecting to server 192.168.1.105."
        masked, token_map = mask_pii(text)

        self.assertNotIn("192.168.1.105", masked)
        self.assertTrue(any(k.startswith("[IP_ADDRESS_1_") and v == "192.168.1.105" for k, v in token_map.items()))

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
            "call (415) 555-2671. Our server is 10.0.0.1."
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
            "cleaned_body": "Please contact Robert at robert@client.com or call (415) 555-2671.",
            "masked_body": None,
            "masked_subject": None,
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
        self.assertIn("masked_subject", output)
        self.assertEqual(output["masked_subject"], "Leaked Token Issue")
        self.assertIn("token_map", output)
        self.assertNotIn("robert@client.com", output["masked_body"])
        self.assertNotIn("(415) 555-2671", output["masked_body"])
        self.assertTrue(any(k.startswith("[EMAIL_1_") for k in output["token_map"].keys()))

    def test_subject_and_body_shared_token_map(self):
        """Verifies subject and body share the same token_map, matching the same entities."""
        state: TriageState = {
            "email_id": "em_pii_shared_01",
            "message_id": "msg_pii_shared_01",
            "thread_id": "th_pii_shared_01",
            "sender_email": "alice.smith@corporate.com",
            "sender_domain": "corporate.com",
            "email_subject": "Billing issue for Alice Smith (alice.smith@corporate.com) card 4111 1111 1111 1111",
            "email_body": "Hello, my name is Alice Smith and my email is alice.smith@corporate.com.",
            "raw_body": "Hello, my name is Alice Smith and my email is alice.smith@corporate.com.",
            "has_attachments": False,
            "cleaned_body": "Hello, my name is Alice Smith and my email is alice.smith@corporate.com.",
            "masked_body": None,
            "masked_subject": None,
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

        # Subject assertions
        self.assertNotIn("Alice Smith", output["masked_subject"])
        self.assertNotIn("alice.smith@corporate.com", output["masked_subject"])
        self.assertNotIn("4111 1111 1111 1111", output["masked_subject"])

        # Body assertions
        self.assertNotIn("Alice Smith", output["masked_body"])
        self.assertNotIn("alice.smith@corporate.com", output["masked_body"])

        # Token map consistency: same entity gets same token in subject and body
        person_token = [k for k, v in output["token_map"].items() if v == "Alice Smith"][0]
        self.assertIn(person_token, output["masked_subject"])
        self.assertIn(person_token, output["masked_body"])

        email_token = [k for k, v in output["token_map"].items() if v == "alice.smith@corporate.com"][0]
        self.assertIn(email_token, output["masked_subject"])
        self.assertIn(email_token, output["masked_body"])

        # Credit card token present in token_map
        card_token = [k for k, v in output["token_map"].items() if v == "4111 1111 1111 1111"][0]
        self.assertIn(card_token, output["masked_subject"])

        # Bidirectional unmasking restores original strings exactly
        self.assertEqual(unmask_text(output["masked_subject"], output["token_map"]), state["email_subject"])
        self.assertEqual(unmask_text(output["masked_body"], output["token_map"]), state["cleaned_body"])

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
        self.assertTrue(any(k.startswith("[PERSON_1_") and v == "John Doe" for k, v in t2.items()))
        self.assertIn("Postgres", m2)
        self.assertNotIn("Postgres", t2.values())

        # 3. "Please contact Apollo Chen" -> "Apollo Chen" (full person name) is still masked
        text3 = "Please contact Apollo Chen"
        m3, t3 = mask_pii(text3)
        self.assertNotIn("Apollo Chen", m3)
        self.assertTrue(any(k.startswith("[PERSON_1_") and v == "Apollo Chen" for k, v in t3.items()))

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
        self.assertTrue(any(k.startswith("[PERSON_1_") and v == "Grafana Smith" for k, v in t6.items()))

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


class TestPiiMaskerSpacySafeguardA8(unittest.TestCase):
    """Test suite for Fix A8: Never send unmasked names to external AI when spaCy is unavailable."""

    def setUp(self):
        reset_spacy_cache()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_pii_a8.db")
        self.db = TriageDatabase(db_path=self.db_path)

    def tearDown(self):
        reset_spacy_cache()
        self.temp_dir.cleanup()

    @patch.dict(os.environ, {"JEV_API_KEY": "fake_real_jev_key", "GROQ_API_KEY": ""})
    @patch("spacy.load", side_effect=OSError("spacy model 'en_core_web_sm' not found"))
    def test_a8_startup_guard_raises_runtime_error_with_fake_jev_key(self, mock_load):
        """Mock spacy.load to raise; with a fake Jev key set, startup raises RuntimeError."""
        reset_spacy_cache()

        # 1. Direct validate_startup call
        with self.assertRaises(RuntimeError) as ctx:
            validate_startup(offline=False)
        self.assertIn("Startup guard failed: spaCy model could not be loaded", str(ctx.exception))

        # 2. Pipeline creation invocation
        with self.assertRaises(RuntimeError) as ctx2:
            create_triage_pipeline(db=self.db, offline=False)
        self.assertIn("Startup guard failed: spaCy model could not be loaded", str(ctx2.exception))

        # 3. SpaCy failure is remembered and not retried on every email
        self.assertIsNone(get_spacy_nlp())
        # spacy.load should only have been called once
        self.assertEqual(mock_load.call_count, 1)

    @patch.dict(
        os.environ,
        {"JEV_API_KEY": "fake_real_jev_key", "GROQ_API_KEY": "fake_real_groq_key"},
    )
    @patch("requests.post")
    def test_a8_runtime_guard_prevents_jev_and_groq_and_routes_to_manual_review(
        self, mock_requests_post
    ):
        """Mock spacy so it fails at runtime; with a fake key, assert mocked Jev and Groq are never called and email ends in manual_review."""
        reset_spacy_cache()

        mock_nlp = MagicMock()
        mock_nlp.side_effect = RuntimeError("Simulated spaCy C-extension/OOM runtime crash")

        with patch("spacy.load", return_value=mock_nlp):
            with patch("langchain_groq.ChatGroq") as mock_groq_cls:
                client = JevClient()
                with patch.object(
                    client, "_call_jev_api", wraps=client._call_jev_api
                ) as spy_jev, patch.object(
                    client, "_call_groq_fallback", wraps=client._call_groq_fallback
                ) as spy_groq:
                    pipeline = create_triage_pipeline(
                        db=self.db, client=client, offline=False
                    )

                    payload = {
                        "email_id": "em_test_runtime_fail",
                        "sender_email": "customer@acme.com",
                        "email_subject": "Urgent Question about Service Outage",
                        "email_body": "Hello my name is John Doe and our server is down.",
                    }

                    with self.assertLogs(level="WARNING") as log_capture:
                        result = run_triage_pipeline(
                            payload, pipeline=pipeline, db=self.db, offline=False
                        )

                    # Assert mocked Jev and Groq were never called
                    mock_requests_post.assert_not_called()
                    mock_groq_cls.assert_not_called()
                    spy_jev.assert_not_called()
                    spy_groq.assert_not_called()

                    # Assert routed to manual_review and dispatch_status is done
                    self.assertEqual(result.get("routing_status"), "manual_review")
                    self.assertEqual(result.get("dispatch_status"), "done")
                    self.assertEqual(result.get("dispatch_target"), "Review/Manual")

                    # Assert DB record marked done with manual_review
                    record = self.db.get_record("em_test_runtime_fail")
                    self.assertIsNotNone(record)
                    self.assertEqual(record["status"], "done")
                    self.assertEqual(record["routing_status"], "manual_review")

                    # Check warning log contains email_id only, and zero email content
                    combined_logs = " ".join(log_capture.output)
                    self.assertIn("em_test_runtime_fail", combined_logs)
                    self.assertNotIn("John Doe", combined_logs)
                    self.assertNotIn("Service Outage", combined_logs)
                    self.assertNotIn("customer@acme.com", combined_logs)

    @patch.dict(os.environ, {"JEV_API_KEY": "", "GROQ_API_KEY": ""})
    @patch("spacy.load", side_effect=OSError("spacy model not found"))
    def test_a8_no_keys_and_spacy_unavailable_runs_and_logs_one_warning(self, mock_load):
        """With no keys and spaCy unavailable, pipeline still runs and logs exactly one warning."""
        reset_spacy_cache()

        client = JevClient(api_key="", groq_api_key="")

        with self.assertLogs("nodes.pii_masker", level="WARNING") as log_capture:
            pipeline = create_triage_pipeline(db=self.db, client=client, offline=True)

            payload_1 = {
                "email_id": "em_no_ai_1",
                "sender_email": "user1@example.com",
                "email_subject": "General inquiry 1",
                "email_body": "Looking for pricing details please.",
            }
            res1 = run_triage_pipeline(payload_1, pipeline=pipeline, db=self.db, offline=True)
            self.assertIsNotNone(res1)

            payload_2 = {
                "email_id": "em_no_ai_2",
                "sender_email": "user2@example.com",
                "email_subject": "General inquiry 2",
                "email_body": "Another question about features.",
            }
            res2 = run_triage_pipeline(payload_2, pipeline=pipeline, db=self.db, offline=True)
            self.assertIsNotNone(res2)

        # Check that the startup warning appeared exactly once
        warning_matches = [
            msg
            for msg in log_capture.output
            if "names will only be masked by regex rules" in msg
        ]
        self.assertEqual(
            len(warning_matches),
            1,
            f"Expected exactly ONE startup warning, but got {len(warning_matches)}: {warning_matches}",
        )

    def test_a8_normal_path_spacy_available_behavior_unchanged(self):
        """Normal path: spaCy available, behavior unchanged (all existing tests still pass)."""
        reset_spacy_cache()

        validate_startup()

        nlp = get_spacy_nlp()
        self.assertIsNotNone(nlp)

        text = "Please reach out to Alexander Hamilton regarding the project update."
        masked, token_map = mask_pii(text)
        self.assertNotIn("Alexander Hamilton", masked)
        self.assertTrue(any(k.startswith("[PERSON_1_") and v == "Alexander Hamilton" for k, v in token_map.items()))

        restored = unmask_text(masked, token_map)
        self.assertEqual(restored, text)


class TestFixA9PrecisionPiiMasking(unittest.TestCase):
    """Dedicated test suite for Fix A9: Precision PII masking in nodes/pii_masker.py."""

    def test_a9_table_driven_detection_rules(self):
        """Table-driven test with every specified A9 example asserting masking or unchanged state."""
        cases = [
            # 1. Phones: valid international format (+country code) must always be masked
            ("+44 7911 123456", "Contact us at +44 7911 123456 for help", True),
            ("+880 1712-345678", "Call Dhaka office at +880 1712-345678 now", True),
            ("+49 30 1234567", "Berlin office line is +49 30 1234567", True),
            ("+33 6 12 34 56 78", "Paris hotline: +33 6 12 34 56 78", True),
            ("+91 98765 43210", "India support: +91 98765 43210", True),
            # National-format (no +): masked if valid US number and not preceded by indicator
            ("(415) 555-2671", "Direct desk phone: (415) 555-2671", True),
            ("415-555-2671", "Reach me on mobile 415-555-2671 please", True),
            # National-format preceded within ~15 chars by indicator words must stay unchanged
            ("4155552671", "Invoice 4155552671 is due tomorrow", False),
            ("4155552671", "Please check order 4155552671 status", False),
            ("4155552671", "Support ticket 4155552671 updated", False),
            ("4155552671", "Internal ref 4155552671 assigned", False),
            ("4155552671", "Account id 4155552671 confirmed", False),
            ("4155552671", "Shipment no 4155552671 dispatched", False),
            ("4155552671", "Ref # 4155552671 processed", False),
            ("4155552671", "FedEx tracking 4155552671 delivered", False),
            # 2. Cards: 13-19 digits masked only if passing Luhn check
            ("4111 1111 1111 1111", "Visa card 4111 1111 1111 1111 charged", True),
            ("1234567890123456", "Fails Luhn 1234567890123456 must stay", False),
            # 3. IBAN: ISO mod-97 check; mask the WHOLE IBAN (no partial leftovers)
            ("GB82 WEST 1234 5698 7654 32", "Wire funds to GB82 WEST 1234 5698 7654 32 today", True),
            ("GB82 WEST 1234 5698 7654 33", "Invalid IBAN GB82 WEST 1234 5698 7654 33 stays", False),
            # 4. Keys and secrets
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J_dummy", "JWT token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J_dummy issued", True),
            ("AIza00000000000000000000000000000000000", "Google API key AIza00000000000000000000000000000000000 active", True),
            ("sk-proj-abc1234567890def1234567890", "OpenAI key sk-proj-abc1234567890def1234567890 leaked", True),
            ("sk-1234567890abcdef1234567890", "OpenAI key sk-1234567890abcdef1234567890 leaked", True),
            ("xoxb-1234567890-abcdef12345", "Slack bot token xoxb-1234567890-abcdef12345 registered", True),
            ("AKIAIOSFODNN7EXAMPLE", "AWS root access key AKIAIOSFODNN7EXAMPLE in config", True),
            ("ghp_1234567890abcdefghijklmnopqrstuvwxyz12", "GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz12 exposed", True),
            ("SuperSecretPass123!", "login password: SuperSecretPass123! confirmed", True),
            ("AdminP@ss999", "admin passwd: AdminP@ss999 confirmed", True),
            ("VaultPwd456!", "server pwd = VaultPwd456! confirmed", True),
            # 5. IPv6 & IPv4
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IPv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334 down", True),
            ("2001:db8::1", "IPv6 router 2001:db8::1 unreachable", True),
            ("192.168.1.1", "IPv4 gateway 192.168.1.1 responsive", True),
            ("10.2.33.4", "Running version 10.2.33.4 on production", False),
            ("10.2.33.4", "Deployed build 10.2.33.4 yesterday", False),
            ("10.2.33.4", "Current release 10.2.33.4 stable", False),
            ("10.2.33.4", "Upgraded ver 10.2.33.4 smoothly", False),
            ("10.2.33.4", "Kernel v 10.2.33.4 active", False),
        ]

        for target_val, input_text, should_mask in cases:
            with self.subTest(target_val=target_val, should_mask=should_mask, input_text=input_text):
                masked, token_map = mask_pii(input_text)
                if should_mask:
                    self.assertNotIn(
                        target_val,
                        masked,
                        f"Expected '{target_val}' to be masked in: '{input_text}', but got '{masked}'"
                    )
                    # For IBAN: assert no partial leftover words
                    if "WEST" in target_val:
                        self.assertNotIn("WEST", masked)
                        self.assertNotIn("7654", masked)
                else:
                    self.assertIn(
                        target_val,
                        masked,
                        f"Expected '{target_val}' to stay unchanged in: '{input_text}', but got '{masked}'"
                    )

    def test_a9_round_trip_preserves_literal_token(self):
        """A literal '[EMAIL_1]' typed by the customer must survive mask -> unmask unchanged."""
        original = (
            "Hi Support, our automated template shows [EMAIL_1] when contacting "
            "alice.smith@corporate-domain.com about issue #99."
        )
        masked, token_map = mask_pii(original)

        # Literal '[EMAIL_1]' typed by customer was NOT replaced by an entity token
        self.assertIn("[EMAIL_1]", masked)
        # Real email address was masked with a nonce
        self.assertNotIn("alice.smith@corporate-domain.com", masked)
        self.assertTrue(any(k.startswith("[EMAIL_1_") for k in token_map.keys()))

        # Unmask restores original text exactly
        restored = unmask_text(masked, token_map)
        self.assertEqual(restored, original)

    def test_a9_subject_and_body_share_tokens_and_nonce(self):
        """Subject and body of the same email share the same tokens and the same 4-hex-char nonce."""
        state: TriageState = {
            "email_id": "em_a9_nonce_test_01",
            "message_id": "<a9_nonce@example.com>",
            "thread_id": "th_a9_nonce_01",
            "sender_email": "jane.doe@example.com",
            "sender_domain": "example.com",
            "email_subject": "Urgent inquiry from Jane Doe (jane.doe@example.com)",
            "email_body": "Hello, my name is Jane Doe and my email is jane.doe@example.com. Server 192.168.1.1 is down.",
            "raw_body": "Hello, my name is Jane Doe and my email is jane.doe@example.com. Server 192.168.1.1 is down.",
            "has_attachments": False,
            "cleaned_body": "Hello, my name is Jane Doe and my email is jane.doe@example.com. Server 192.168.1.1 is down.",
            "masked_body": None,
            "masked_subject": None,
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
        token_map = output["token_map"]

        # 1. Nonce exists and is exactly 4 hex characters
        nonce = token_map.get("__nonce__")
        self.assertIsNotNone(nonce)
        self.assertEqual(len(nonce), 4)
        self.assertTrue(all(c in "0123456789abcdef" for c in nonce))

        # 2. Both subject and body contain the identical person token with this nonce
        person_token = [k for k, v in token_map.items() if v == "Jane Doe"][0]
        self.assertEqual(person_token, f"[PERSON_1_{nonce}]")
        self.assertIn(person_token, output["masked_subject"])
        self.assertIn(person_token, output["masked_body"])

        # 3. Both subject and body contain the identical email token with this nonce
        email_token = [k for k, v in token_map.items() if v == "jane.doe@example.com"][0]
        self.assertEqual(email_token, f"[EMAIL_1_{nonce}]")
        self.assertIn(email_token, output["masked_subject"])
        self.assertIn(email_token, output["masked_body"])

        # 4. Bidirectional restoration reproduces original strings
        self.assertEqual(unmask_text(output["masked_subject"], token_map), state["email_subject"])
        self.assertEqual(unmask_text(output["masked_body"], token_map), state["cleaned_body"])

    def test_a9_egress_behavior_holds(self):
        """Fix A1 egress behavior still holds: outbound payloads to external AI contain zero raw PII."""
        temp_dir = tempfile.TemporaryDirectory()
        try:
            db_path = os.path.join(temp_dir.name, "egress_a9.db")
            db = TriageDatabase(db_path=db_path)

            raw_person = "Dr. Marcus Brody"
            raw_email = "marcus.brody@archeology-trust.org"
            raw_card = "4111 1111 1111 1111"
            raw_phone = "+44 7911 123456"

            payload = {
                "email_id": "em_a9_egress_01",
                "message_id": "<a9_egress@trust.org>",
                "thread_id": "th_a9_egress_01",
                "sender_email": f"{raw_person} <{raw_email}>",
                "sender_domain": "archeology-trust.org",
                "email_subject": f"Inquiry from {raw_person} card {raw_card}",
                "email_body": f"Please call me at {raw_phone} or email {raw_email}. Card {raw_card}.",
            }

            from pipeline import create_triage_pipeline, run_triage_pipeline
            pipeline = create_triage_pipeline(db=db, offline=True)
            res = run_triage_pipeline(payload, pipeline=pipeline, db=db, offline=True)

            self.assertNotIn(raw_person, res["masked_subject"])
            self.assertNotIn(raw_card, res["masked_subject"])
            self.assertNotIn(raw_phone, res["masked_body"])
            self.assertNotIn(raw_email, res["masked_body"])
            self.assertNotIn(raw_card, res["masked_body"])
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
