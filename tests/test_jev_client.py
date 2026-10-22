"""Unit tests for JevClient with TypeSafe System One API and Fallbacks.

Tests all probability mappings, HTTP error handling, session disabling on 401,
missing/placeholder key skipping, and configuration threshold validation.
All tests use mock HTTP responses to run completely offline with zero API calls.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

import requests
from utils.config import validate_config
from utils.jev_client import JevClient


class TestJevClient(unittest.TestCase):
    def setUp(self):
        self.mock_config = {
            "gatekeeper": {
                "timeout_seconds": 5.0,
                "max_retries": 1,
                "api_key_env": "JEV_API_KEY",
                "fallback_model": "openai/gpt-oss-20b",
                "groq_api_key_env": "GROQ_API_KEY",
                "jev": {
                    "model": "jev-1.13.0",
                    "api_url": "https://api.typesafe.ai/v1/systemone",
                    "hi_threshold": 0.85,
                    "lo_threshold": 0.15,
                    "max_body_chars": 20000,
                },
            }
        }

    def _make_mock_response(self, status_code: int, p_spam: float = 0.0, p_threat: float = 0.0, text: str = ""):
        mock = MagicMock()
        mock.status_code = status_code
        mock.text = text
        if status_code == 200:
            mock.json.return_value = {
                "answers": {
                    "is_spam": {"type": "noul", "noul": p_spam},
                    "is_threat": {"type": "noul", "noul": p_threat},
                },
                "usage": {"input_tokens": 42},
            }
        else:
            mock.json.side_effect = Exception("HTTP error")
        return mock

    @patch("requests.post")
    def test_probability_mapping_table(self, mock_post):
        """Verifies exact probability mapping table specified by architecture."""
        cases = [
            # p_spam, p_threat, expected_decision, expected_confidence
            (0.03, 0.01, "legitimate", 0.97),
            (0.95, 0.02, "spam", 0.95),
            (0.50, 0.10, "manual_review", 0.50),
            (0.10, 0.80, "manual_review", 0.80),
        ]

        client = JevClient(config=self.mock_config, api_key="test_real_key_123")

        for p_spam, p_threat, exp_decision, exp_conf in cases:
            with self.subTest(p_spam=p_spam, p_threat=p_threat):
                mock_post.return_value = self._make_mock_response(200, p_spam=p_spam, p_threat=p_threat)
                result = client.classify(
                    subject="Test Subject",
                    body="Test email body text.",
                    sender="alice@example.com",
                )

                self.assertEqual(result["decision"], exp_decision)
                self.assertAlmostEqual(result["confidence"], exp_conf, places=2)
                self.assertEqual(result["classifier_used"], "jev")

    @patch("requests.post")
    def test_output_schema_keys(self, mock_post):
        """Verifies output contains exactly the 5 triage fields plus classifier_used."""
        mock_post.return_value = self._make_mock_response(200, p_spam=0.01, p_threat=0.01)
        client = JevClient(config=self.mock_config, api_key="test_real_key_123")

        result = client.classify(subject="Hello", body="Inquiry", sender="test@example.com")
        expected_keys = {
            "decision",
            "confidence",
            "is_spam",
            "is_threat",
            "threat_details",
            "classifier_used",
        }
        self.assertEqual(set(result.keys()), expected_keys)

    @patch("requests.post")
    def test_http_401_disables_jev_for_session(self, mock_post):
        """Verifies HTTP 401 Unauthorized disables Jev for subsequent calls and uses fallback."""
        mock_post.return_value = self._make_mock_response(401, text="Unauthorized: invalid api key")
        client = JevClient(config=self.mock_config, api_key="invalid_key", groq_api_key="")

        # First call hits 401 and falls back to regex
        result1 = client.classify(subject="Inquiry", body="Can you help me with billing?", sender="user@corp.com")
        self.assertTrue(client._jev_disabled)
        self.assertEqual(result1["classifier_used"], "regex")
        self.assertEqual(mock_post.call_count, 1)

        # Second call does not even attempt requests.post because Jev is disabled for the session
        result2 = client.classify(subject="Followup", body="Any updates on my ticket?", sender="user@corp.com")
        self.assertEqual(result2["classifier_used"], "regex")
        self.assertEqual(mock_post.call_count, 1)

    @patch("requests.post")
    def test_http_error_codes_fallback(self, mock_post):
        """Verifies HTTP 422, 429, and 529 trigger fallback cleanly without crashing."""
        for error_code in (422, 429, 529):
            with self.subTest(status_code=error_code):
                mock_post.reset_mock()
                mock_post.return_value = self._make_mock_response(error_code, text=f"Error {error_code}")
                client = JevClient(config=self.mock_config, api_key="valid_key", groq_api_key="")

                result = client.classify(subject="Hello", body="Please quote 10 seats.", sender="lead@corp.com")
                self.assertEqual(result["classifier_used"], "regex")
                self.assertEqual(result["decision"], "legitimate")

    @patch("requests.post")
    def test_timeout_and_malformed_json_fallback(self, mock_post):
        """Verifies network timeout and malformed responses trigger fallback cleanly."""
        # Timeout scenario
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")
        client = JevClient(config=self.mock_config, api_key="valid_key", groq_api_key="")
        result = client.classify(subject="Hello", body="Need assistance.", sender="user@corp.com")
        self.assertEqual(result["classifier_used"], "regex")

        # Malformed JSON scenario
        mock_post.side_effect = None
        bad_response = MagicMock()
        bad_response.status_code = 200
        bad_response.json.return_value = {"bad_payload": True}
        mock_post.return_value = bad_response
        result2 = client.classify(subject="Hello", body="Need assistance.", sender="user@corp.com")
        self.assertEqual(result2["classifier_used"], "regex")

    @patch("requests.post")
    def test_placeholder_key_skips_jev(self, mock_post):
        """Verifies placeholder or missing key never calls Jev API and falls back cleanly."""
        placeholders = [
            "",
            None,
            "your_jev_api_key_here",
            "your_placeholder_key",
        ]
        for key in placeholders:
            with self.subTest(key=key):
                mock_post.reset_mock()
                client = JevClient(config=self.mock_config, api_key=key, groq_api_key="")
                result = client.classify(subject="Pricing", body="What is cost?", sender="user@corp.com")

                self.assertEqual(result["classifier_used"], "regex")
                mock_post.assert_not_called()

    def test_config_threshold_validation(self):
        """Verifies 0.0 < LO < HI < 1.0 constraint validation on configuration."""
        # Valid config
        valid_cfg = {
            "gatekeeper": {
                "jev": {"lo_threshold": 0.15, "hi_threshold": 0.85}
            }
        }
        validate_config(valid_cfg)

        # Invalid: LO >= HI
        inverted_cfg = {
            "gatekeeper": {
                "jev": {"lo_threshold": 0.85, "hi_threshold": 0.15}
            }
        }
        with self.assertRaises(ValueError):
            validate_config(inverted_cfg)

        # Invalid: HI >= 1.0
        out_of_bounds_cfg = {
            "gatekeeper": {
                "jev": {"lo_threshold": 0.10, "hi_threshold": 1.50}
            }
        }
        with self.assertRaises(ValueError):
            validate_config(out_of_bounds_cfg)


if __name__ == "__main__":
    unittest.main()
