"""Unit tests for Webhook Alert Destination Adapter."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests
import urllib3.exceptions

from utils.adapters.base import (
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.webhook_adapter import WebhookAdapter

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "webhook"


def _load_fixture(filename: str) -> dict:
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def _make_payload(
    email_id: str = "em_wh_test_001",
    idempotency_key: str = "idemp_wh_test_001",
    category: str = "Bug Report",
    priority: str = "Critical",
) -> DispatchPayload:
    record = {
        "email_id": email_id,
        "message_id": f"<{email_id}@enterprise.com>",
        "thread_id": f"th_{email_id}",
        "category": category,
        "priority": priority,
        "sentiment": "Negative",
        "customer_emotion": "Angry",
        "summary": "Production server outage reported",
        "suggested_team": "Engineering",
        "confidence": 0.99,
        "masked_subject": "Production outage in us-east-1",
        "masked_body": "All database connections are exhausted.",
        "sender_email": "ops@enterprise.com",
        "sender_domain": "enterprise.com",
        "p2_classifier_used": "jev",
    }
    return DispatchPayload.from_record(
        record=record,
        action_type="alert",
        idempotency_key=idempotency_key,
    )


def test_webhook_adapter_inheritance_and_defaults():
    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="my_secret_token_123",
        allowed_hosts=["events.example.com"],
    )
    assert isinstance(adapter, BaseDestinationAdapter)
    assert adapter.name == "webhook"
    assert adapter.validate_config() is True


def test_webhook_adapter_validate_config_rejects_insecure_or_unlisted_hosts():
    # Insecure HTTP
    a_http = WebhookAdapter(target="http://events.example.com/alerts", secret_key="sec")
    assert a_http.validate_config() is False

    # Unlisted host
    a_host = WebhookAdapter(
        target="https://evil.attacker.com/webhook",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
    )
    assert a_host.validate_config() is False

    # Missing target
    a_notarget = WebhookAdapter(target="")
    assert a_notarget.validate_config() is False


def test_webhook_dispatch_success_standard_json():
    mock_session = MagicMock()
    post_res = MagicMock(status_code=200)
    post_res.json.return_value = _load_fixture("alert_200.json")
    mock_session.request.return_value = post_res

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="my_test_secret_123",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert result.remote_id == f"webhook:{payload.email_id}"
    assert mock_session.request.call_count == 1

    # Verify security headers were included
    call_kwargs = mock_session.request.call_args[1]
    headers = call_kwargs["headers"]
    assert "X-Signature-SHA256" in headers
    assert headers["X-Signature-SHA256"].startswith("sha256=")
    assert "X-Timestamp-ISO" in headers
    assert headers["Idempotency-Key"] == payload.idempotency_key
    assert headers["X-Correlation-ID"] == payload.email_id


def test_webhook_dispatch_success_slack_auto_detected():
    mock_session = MagicMock()
    post_res = MagicMock(status_code=200)
    post_res.json.return_value = _load_fixture("alert_slack_200.json")
    mock_session.request.return_value = post_res

    adapter = WebhookAdapter(
        target="https://hooks.slack.com/services/T00/B00/X00",
        secret_key="slack_sec",
        allowed_hosts=["hooks.slack.com"],
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert result.remote_id == f"webhook:{payload.email_id}"

    # Verify Slack payload format was used
    call_kwargs = mock_session.request.call_args[1]
    raw_data = call_kwargs["data"]
    json_data = json.loads(raw_data.decode("utf-8") if isinstance(raw_data, bytes) else raw_data)
    assert "attachments" in json_data


def test_webhook_dispatch_429_transient_error():
    mock_session = MagicMock()
    mock_session.request.return_value = MagicMock(status_code=429)

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_rate_limited" in str(exc_info.value)


def test_webhook_dispatch_503_transient_error():
    mock_session = MagicMock()
    mock_session.request.return_value = MagicMock(status_code=503)

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_service_unavailable" in str(exc_info.value)


def test_webhook_dispatch_400_permanent_error():
    mock_session = MagicMock()
    mock_session.request.return_value = MagicMock(status_code=400)

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterPermanentError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_invalid_payload" in str(exc_info.value)


def test_webhook_dispatch_401_permanent_error():
    mock_session = MagicMock()
    mock_session.request.return_value = MagicMock(status_code=401)

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterPermanentError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_auth_failed" in str(exc_info.value)


def test_webhook_dispatch_timeout_unknown_outcome():
    mock_session = MagicMock()
    mock_session.request.side_effect = requests.exceptions.ReadTimeout("Timeout connecting")

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_network_timeout" in str(exc_info.value)


def test_webhook_dispatch_connection_failed_transient():
    mock_session = MagicMock()
    mock_session.request.side_effect = requests.exceptions.ConnectionError(
        urllib3.exceptions.NewConnectionError(None, "Connection refused")
    )

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key="sec",
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )
    with pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "webhook_connection_failed" in str(exc_info.value)


def test_webhook_adapter_target_env_resolution(monkeypatch):
    """Assert WebhookAdapter prioritizes target_env environment variable when configured."""
    monkeypatch.setenv("TEST_WEBHOOK_URL", "https://hooks.slack.com/services/T1/B2/secret")
    adapter = WebhookAdapter(
        target_env="TEST_WEBHOOK_URL",
        secret_key="sec",
        allowed_hosts=["hooks.slack.com"],
    )
    assert adapter._target == "https://hooks.slack.com/services/T1/B2/secret"

