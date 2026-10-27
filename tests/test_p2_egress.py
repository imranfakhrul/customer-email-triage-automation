"""Egress security and PII privacy tests for [P2-01] Classifier."""

import json
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
from nodes.classifier import classifier_node
from state import TriageState
from utils.classifier_client import ClassifierClient


def test_classifier_egress_rejects_disallowed_hosts():
    """A13 Security Guardrail: Asserts that non-allowlisted URLs are rejected before network egress."""
    client = ClassifierClient()

    # Disallowed hosts
    assert not client._is_allowed_url("http://malicious-site.com", ["api.typesafe.ai"])
    assert not client._is_allowed_url("https://malicious-site.com/api", ["api.typesafe.ai"])
    assert not client._is_allowed_url("http://api.typesafe.ai", ["api.typesafe.ai"])  # HTTP rejected
    assert not client._is_allowed_url("https://evil-groq.com", ["api.groq.com"])

    # Allowed hosts
    assert client._is_allowed_url("https://api.typesafe.ai/v1/systemone", ["api.typesafe.ai"])
    assert client._is_allowed_url("https://api.groq.com/openai/v1/chat/completions", ["api.groq.com"])
    assert client._is_allowed_url("http://localhost:8080/test", ["api.typesafe.ai"])
    assert client._is_allowed_url("http://127.0.0.1:8000/v1", ["api.typesafe.ai"])


@patch.dict("os.environ", {"JEV_API_KEY": "test-key"})
def test_classifier_egress_payload_carries_only_masked_text():
    """Privacy Invariant: Asserts that outbound requests to Jev contain only masked text and no raw PII."""
    client = ClassifierClient()
    client.jev_enabled = True
    client.jev_api_url = "https://api.typesafe.ai/v1/systemone"

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "jev-1.13.0",
            "answers": {
                "gmail_router": {
                    "choice": "github_issue_create",
                    "confidence": 0.95,
                }
            },
        }
        mock_post.return_value = mock_resp

        masked_subject = "Urgent: Billing issue for {{PERSON_1}}"
        masked_body = "Customer {{EMAIL_1}} reported issue with card {{CREDIT_CARD_1}}."

        client.classify(masked_subject, masked_body)

        assert mock_post.called
        call_args, call_kwargs = mock_post.call_args
        target_url = call_args[0]
        sent_json = call_kwargs.get("json", {})

        # Assert URL is allowed
        assert target_url == "https://api.typesafe.ai/v1/systemone"

        # Assert payload contains masked tokens, not raw text
        state_text = sent_json.get("state", "")
        assert "{{PERSON_1}}" in state_text
        assert "{{EMAIL_1}}" in state_text
        assert "{{CREDIT_CARD_1}}" in state_text
        assert "token_map" not in sent_json


@patch.dict("os.environ", {"GROQ_API_KEY": "fake-groq-key", "JEV_API_KEY": "fake-jev-key"})
def test_classifier_egress_check_runner_forbid_raw_strings():
    """Test (f): tools/egress_check.py style verification.

    Asserts that:
    1. Only allowlisted hosts (api.groq.com, or api.typesafe.ai if enabled) are contacted.
    2. Zero raw forbidden PII strings ever escape over the wire.
    3. Outbound payload contains strictly sanitized/masked tokens.
    """
    captured_requests = []
    forbid = [
        "Johnathan Smith",
        "johnny@secret-corp.com",
        "4111-2222-3333-4444",
        "555-0199-SECRET",
    ]

    groq_reply = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "category": "Bug Report",
                        "priority": "Medium",
                        "sentiment": "Neutral",
                        "customer_emotion": "Calm",
                        "summary": "Sanitized issue",
                        "suggested_team": "Engineering",
                        "confidence": 0.92,
                    })
                }
            }
        ]
    }

    state: TriageState = {
        "email_id": "test-egress-f",
        "email_subject": "Raw Subject: Johnathan Smith credit card 4111-2222-3333-4444",
        "email_body": "Raw Body: please email johnny@secret-corp.com or call 555-0199-SECRET",
        "raw_body": "Raw Body: please email johnny@secret-corp.com",
        "masked_subject": "Masked Subject: {{PERSON_1}} credit card {{CREDIT_CARD_1}}",
        "masked_body": "Masked Body: please email {{EMAIL_1}} or call {{PHONE_1}}",
    }

    def fake_post(url, json=None, **kwargs):
        captured_requests.append((url, json))
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = groq_reply
        return resp

    with patch("requests.post", side_effect=fake_post):
        res = classifier_node(state)

    # 1. Assert requests were made to Groq (Jev disabled by default)
    assert len(captured_requests) == 1
    target_url, target_payload = captured_requests[0]

    # Verify only allowed host was contacted
    parsed = urlparse(target_url)
    assert parsed.hostname in ("api.groq.com", "api.typesafe.ai")
    assert parsed.scheme == "https"

    # 2. Check for leaks in the outgoing payload text
    payload_str = json.dumps(target_payload)
    for forbidden_text in forbid:
        assert forbidden_text not in payload_str, f"LEAK DETECTED: {forbidden_text} found in egress payload!"

    # 3. Verify only masked tokens are sent
    assert "{{PERSON_1}}" in payload_str
    assert "{{CREDIT_CARD_1}}" in payload_str
    assert "{{EMAIL_1}}" in payload_str
    assert "{{PHONE_1}}" in payload_str

    # 4. Assert classification finished cleanly
    assert res["classification"].category == "Bug Report"
    assert res["p2_classifier_used"] == "groq"
