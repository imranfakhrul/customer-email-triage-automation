"""Unit tests for JevClient with TypeSafe System One API and Fallbacks.

Tests all probability mappings, HTTP error handling, session disabling on 401,
missing/placeholder key skipping, and configuration threshold validation.
All tests use mock HTTP responses to run completely offline with zero API calls.
"""

import logging
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest
import requests
from utils.config import validate_config
from utils.jev_client import JevClient, normalize_result


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

    @patch("requests.post")
    def test_jev_api_negative_p_spam_returns_manual_review(self, mock_post):
        """Verifies fix A4: Jev API returning p_spam = -1 fails closed to manual_review."""
        mock_post.return_value = self._make_mock_response(200, p_spam=-1.0, p_threat=0.01)
        client = JevClient(config=self.mock_config, api_key="test_real_key_123")

        result = client.classify(
            subject="Hello",
            body="Normal billing inquiry",
            sender="customer@corp.com",
        )

        self.assertEqual(result["decision"], "manual_review")
        self.assertEqual(result["confidence"], 0.0)
        self.assertFalse(result["is_spam"])
        self.assertEqual(result["classifier_used"], "jev")

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


class TestNormalizeResultTableDriven(unittest.TestCase):
    def test_normalize_result_table_driven_cases(self):
        """Table-driven test looping over all required classifier normalization cases.

        Verifies:
        - unknown decision
        - missing decision
        - confidence 5.0 / -3 / None / NaN
        - Jev p_spam = -1
        - is_threat true with decision legitimate
        - legitimate with confidence 0.30
        - a normal legitimate 0.95 (must stay legitimate)
        - a normal spam 0.95 (must stay spam)
        """
        cases = [
            {
                "name": "unknown decision",
                "raw": {"decision": "quarantine", "confidence": 0.85},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.85,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "missing decision",
                "raw": {"confidence": 0.85},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.85,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "confidence 5.0",
                "raw": {"decision": "legitimate", "confidence": 5.0},
                "config": None,
                "expected_decision": "legitimate",
                "expected_confidence": 1.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "confidence -3",
                "raw": {"decision": "legitimate", "confidence": -3},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "confidence None",
                "raw": {"decision": "legitimate", "confidence": None},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "confidence NaN",
                "raw": {"decision": "legitimate", "confidence": float("nan")},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "Jev p_spam = -1",
                "raw": {"decision": "legitimate", "confidence": 0.95, "p_spam": -1},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "is_threat true with decision legitimate",
                "raw": {"decision": "legitimate", "confidence": 0.95, "is_threat": True},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.95,
                "expected_is_threat": True,
                "expected_is_spam": False,
            },
            {
                "name": "legitimate with confidence 0.30",
                "raw": {"decision": "legitimate", "confidence": 0.30},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.30,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "a normal legitimate 0.95 (must stay legitimate)",
                "raw": {"decision": "legitimate", "confidence": 0.95},
                "config": None,
                "expected_decision": "legitimate",
                "expected_confidence": 0.95,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
            {
                "name": "a normal spam 0.95 (must stay spam)",
                "raw": {"decision": "spam", "confidence": 0.95},
                "config": None,
                "expected_decision": "spam",
                "expected_confidence": 0.95,
                "expected_is_threat": False,
                "expected_is_spam": True,
            },
            {
                "name": "non-numeric confidence",
                "raw": {"decision": "legitimate", "confidence": "not-a-number"},
                "config": None,
                "expected_decision": "manual_review",
                "expected_confidence": 0.0,
                "expected_is_threat": False,
                "expected_is_spam": False,
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                res = normalize_result(case["raw"], case["config"])
                self.assertEqual(
                    res["decision"],
                    case["expected_decision"],
                    f"Case '{case['name']}' failed decision: expected {case['expected_decision']}, got {res['decision']}",
                )
                self.assertEqual(
                    res["confidence"],
                    case["expected_confidence"],
                    f"Case '{case['name']}' failed confidence: expected {case['expected_confidence']}, got {res['confidence']}",
                )
                self.assertEqual(
                    res["is_threat"],
                    case["expected_is_threat"],
                    f"Case '{case['name']}' failed is_threat",
                )
                self.assertEqual(
                    res["is_spam"],
                    case["expected_is_spam"],
                    f"Case '{case['name']}' failed is_spam",
                )


# ============================================================================
# [A13] Secrets Hardening & Endpoint Controls Tests
# ============================================================================

def test_a13_env_var_already_set_wins_over_dotenv(tmp_path, monkeypatch):
    """Verifies fix A13: Real environment variable wins over .env with load_dotenv(override=False)."""
    import inspect
    import utils.config as config_module
    from dotenv import load_dotenv

    # 1. Assert utils/config.py specifies override=False
    source = inspect.getsource(config_module)
    assert "load_dotenv(override=False)" in source

    # 2. Simulate env var already set before .env
    test_key = "TRIAGE_TEST_ENV_KEY_A13"
    env_file = tmp_path / ".env"
    env_file.write_text(f"{test_key}=value_from_dotenv\nTRIAGE_NEW_VAR=only_in_file\n", encoding="utf-8")

    monkeypatch.setenv(test_key, "value_from_real_environment")

    load_dotenv(dotenv_path=str(env_file), override=False)

    # Environment variable value must win over .env
    assert os.environ.get(test_key) == "value_from_real_environment"
    # Unset variable in environment is loaded from .env
    assert os.environ.get("TRIAGE_NEW_VAR") == "only_in_file"


def test_a13_disallowed_jev_api_urls_trigger_fallback_and_leak_no_secret():
    """Verifies fix A13: Disallowed JEV_API_URL prevents HTTP call, never sends key, and falls back."""
    disallowed_urls = [
        "https://evil.example.com",
        "https://evil.example.com/v1/systemone?secret=super_secret_token_leak",
        "http://api.typesafe.ai",
        "http://api.typesafe.ai/v1/systemone",
        "://malformed-url-format",
        "not_a_valid_url_at_all",
        "ftp://localhost",
        "https://api.typesafe.ai.evil.com",
    ]

    distinctive_secret_key = "secret_jev_key_classified_12345"
    mock_config = {
        "gatekeeper": {
            "timeout_seconds": 1.0,
            "max_retries": 1,
            "fallback_model": "openai/gpt-oss-20b",
            "jev": {
                "hi_threshold": 0.85,
                "lo_threshold": 0.15,
            },
        }
    }

    for url in disallowed_urls:
        with patch("requests.post") as mock_post:
            client = JevClient(
                config=mock_config,
                api_key=distinctive_secret_key,
                groq_api_key="",  # fallback directly to regex
                api_url=url,
            )

            result = client.classify(
                subject="Inquiry regarding licensing",
                body="Hello, what are your enterprise license options?",
                sender="user@corp.com",
            )

            # Assert no HTTP request was made
            mock_post.assert_not_called()

            # Assert secret key was never passed to any call
            for mock_call in mock_post.mock_calls:
                assert distinctive_secret_key not in str(mock_call)

            # Assert result was produced by the fallback path
            assert result["classifier_used"] == "regex"
            assert result["decision"] == "legitimate"


def test_a13_allowed_urls_work_mocked():
    """Verifies fix A13: Allowed endpoints (https://api.typesafe.ai, localhost, 127.0.0.1) work properly."""
    allowed_urls = [
        "https://api.typesafe.ai",
        "https://api.typesafe.ai/v1/systemone",
        "http://localhost:8000/v1/systemone",
        "https://localhost:8000/v1/systemone",
        "http://127.0.0.1:8000/v1/systemone",
        "https://127.0.0.1:8000/v1/systemone",
        "http://localhost",
        "http://127.0.0.1",
    ]

    mock_config = {
        "gatekeeper": {
            "timeout_seconds": 1.0,
            "max_retries": 1,
            "jev": {
                "hi_threshold": 0.85,
                "lo_threshold": 0.15,
            },
        }
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "answers": {
            "is_spam": {"type": "noul", "noul": 0.02},
            "is_threat": {"type": "noul", "noul": 0.01},
        }
    }

    for url in allowed_urls:
        with patch("requests.post", return_value=mock_resp) as mock_post:
            client = JevClient(
                config=mock_config,
                api_key="valid_test_key_123",
                api_url=url,
            )

            result = client.classify(
                subject="Allowed URL test",
                body="Testing allowed URL endpoint resolution",
                sender="user@corp.com",
            )

            mock_post.assert_called_once()
            called_url = mock_post.call_args[0][0]
            assert called_url == url
            assert result["classifier_used"] == "jev"
            assert result["decision"] == "legitimate"


def test_a13_smoke_test_output_contains_no_key_characters(capsys, monkeypatch):
    """Verifies fix A13: scripts/jev_smoke_test.py prints 'Jev key: present' and zero key characters."""
    import scripts.jev_smoke_test as smoke_test

    distinctive_fake_key = "JEV_DISTINCTIVE_SECRET_998877_ALPHA"
    monkeypatch.setenv("JEV_API_KEY", distinctive_fake_key)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "answers": {
            "is_spam": {"type": "noul", "noul": 0.05},
            "is_threat": {"type": "noul", "noul": 0.01},
        }
    }

    with patch("requests.post", return_value=mock_resp):
        smoke_test.main()

    captured = capsys.readouterr()
    combined_output = captured.out + captured.err

    # Assert "Jev key: present" is printed
    assert "Jev key: present" in combined_output

    # Assert none of the key characters or parts appear anywhere in stdout/stderr
    assert distinctive_fake_key not in combined_output
    assert "JEV_DISTINCTIVE" not in combined_output
    assert "998877" not in combined_output
    assert "ALPHA" not in combined_output

    # Check all 4-character slices of the key
    for i in range(len(distinctive_fake_key) - 3):
        slice_4 = distinctive_fake_key[i : i + 4]
        assert slice_4 not in combined_output


def test_a13_smoke_test_missing_key_output(capsys, monkeypatch):
    """Verifies fix A13: scripts/jev_smoke_test.py prints 'Jev key: missing' when key is missing."""
    import scripts.jev_smoke_test as smoke_test

    monkeypatch.setenv("JEV_API_KEY", "")

    with pytest.raises(SystemExit) as exc_info:
        smoke_test.main()

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Jev key: missing" in captured.out


def test_a13_logging_status_code_only_on_http_errors(caplog):
    """Verifies fix A13: 401 and 500 log status code only, never response body text with customer PII."""
    caplog.set_level(logging.INFO)
    mock_config = {
        "gatekeeper": {
            "timeout_seconds": 1.0,
            "max_retries": 1,
            "jev": {
                "hi_threshold": 0.85,
                "lo_threshold": 0.15,
            },
        }
    }

    # 1. Test HTTP 401
    caplog.clear()
    fake_body_401 = '{"error": "Unauthorized customer account for sarah.connor@cyberdyne.com with CC 4111 2222 3333 4444"}'
    with patch("requests.post") as mock_post:
        mock_resp_401 = MagicMock()
        mock_resp_401.status_code = 401
        mock_resp_401.text = fake_body_401
        mock_post.return_value = mock_resp_401

        client = JevClient(config=mock_config, api_key="valid_jev_key", groq_api_key="")
        client.classify(subject="Billing", body="Please refund my payment", sender="sarah.connor@cyberdyne.com")

        log_text = caplog.text
        assert "401" in log_text
        assert "sarah.connor@cyberdyne.com" not in log_text
        assert "4111 2222 3333 4444" not in log_text
        assert "Unauthorized customer account" not in log_text

    # 2. Test HTTP 500
    caplog.clear()
    fake_body_500 = '{"error": "Internal database crash for customer john.doe@example.org with phone +1-555-867-5309"}'
    with patch("requests.post") as mock_post:
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_500.text = fake_body_500
        mock_post.return_value = mock_resp_500

        client = JevClient(config=mock_config, api_key="valid_jev_key_2", groq_api_key="")
        client.classify(subject="Support", body="Service is down", sender="john.doe@example.org")

        log_text = caplog.text
        assert "500" in log_text
        assert "john.doe@example.org" not in log_text
        assert "555-867-5309" not in log_text
        assert "Internal database crash" not in log_text


def test_a13_logging_connection_error_has_class_name_only(caplog):
    """Verifies fix A13: ConnectionError logs only the class name, never exception text."""
    caplog.set_level(logging.INFO)
    mock_config = {
        "gatekeeper": {
            "timeout_seconds": 1.0,
            "max_retries": 1,
            "jev": {
                "hi_threshold": 0.85,
                "lo_threshold": 0.15,
            },
        }
    }

    sensitive_exception_msg = "Connection failed to https://api.typesafe.ai?token=CONFIDENTIAL_API_TOKEN_XYZ"

    # 1. Jev ConnectionError
    caplog.clear()
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError(sensitive_exception_msg)):
        client = JevClient(config=mock_config, api_key="valid_jev_key", groq_api_key="")
        client.classify(subject="Query", body="Test email content", sender="customer@company.com")

        log_text = caplog.text
        assert "ConnectionError" in log_text
        assert "CONFIDENTIAL_API_TOKEN_XYZ" not in log_text
        assert sensitive_exception_msg not in log_text

    # 2. Groq ConnectionError
    caplog.clear()
    with patch("langchain_groq.ChatGroq") as mock_groq_cls:
        mock_groq_instance = MagicMock()
        mock_groq_instance.invoke.side_effect = ConnectionError("Groq failure on payload with customer credit card 4111")
        mock_groq_cls.return_value = mock_groq_instance

        # Client with empty Jev key to invoke Groq fallback
        client = JevClient(config=mock_config, api_key="", groq_api_key="gsk_valid_key_123")
        client.classify(subject="Query", body="Test email content", sender="customer@company.com")

        log_text = caplog.text
        assert "ConnectionError" in log_text
        assert "4111" not in log_text
        assert "Groq failure on payload" not in log_text


if __name__ == "__main__":
    unittest.main()
