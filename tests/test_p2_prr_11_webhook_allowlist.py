"""Tests for PRR-11: Webhook host allowlist enforcement and secret validation."""

from unittest.mock import MagicMock

import pytest

from utils.adapters.base import AdapterPermanentError, DispatchPayload
from utils.adapters.webhook_adapter import WebhookAdapter


def _make_payload(
    email_id: str = "em_wh_prr11_01",
    idempotency_key: str = "idemp_wh_prr11_01",
    category: str = "Billing Issue",
    priority: str = "Critical",
) -> DispatchPayload:
    record = {
        "email_id": email_id,
        "message_id": f"<{email_id}@company.com>",
        "thread_id": f"th_{email_id}",
        "category": category,
        "priority": priority,
        "sentiment": "Negative",
        "customer_emotion": "Frustrated",
        "summary": "Urgent chargeback dispute",
        "suggested_team": "Billing",
        "confidence": 0.95,
        "masked_subject": "Urgent double charge",
        "masked_body": "I was billed twice on card ending in [CREDIT_CARD_1].",
        "sender_email": "customer@company.com",
        "sender_domain": "company.com",
        "p2_classifier_used": "jev",
    }
    return DispatchPayload.from_record(
        record=record,
        action_type="alert",
        idempotency_key=idempotency_key,
    )


class TestWebhookHostAllowlistAndSecretValidation:
    """Verifies PRR-11: target_host is never auto-injected and secret is strictly required."""

    def test_unlisted_target_host_not_in_allowed_hosts(self):
        """Target host must not be auto-injected into _allowed_hosts."""
        adapter = WebhookAdapter(
            target="https://evil.attacker.com/webhook",
            secret_key="valid_secret_key_123",
        )
        assert "evil.attacker.com" not in adapter._allowed_hosts
        assert adapter.validate_config() is False

    def test_unlisted_host_dispatch_fails_closed(self):
        """Dispatching to an unlisted host must fail closed with AdapterPermanentError."""
        mock_session = MagicMock()
        adapter = WebhookAdapter(
            target="https://evil.attacker.com/webhook",
            secret_key="valid_secret_key_123",
            session=mock_session,
        )
        with pytest.raises(AdapterPermanentError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "webhook_not_configured" in str(exc_info.value)
        assert mock_session.request.call_count == 0

    def test_empty_secret_fails_validate_config(self):
        """Empty secret string must cause validate_config to return False."""
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal/triage-alerts",
            secret_key="",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is False

    def test_whitespace_secret_fails_validate_config(self):
        """Whitespace-only secret must cause validate_config to return False."""
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal/triage-alerts",
            secret_key="    ",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is False

    def test_missing_env_secret_fails_validate_config(self, monkeypatch):
        """Missing environment variable secret must cause validate_config to return False."""
        monkeypatch.delenv("WEBHOOK_SECRET_KEY_MISSING_TEST", raising=False)
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal/triage-alerts",
            secret_key=None,
            secret_env="WEBHOOK_SECRET_KEY_MISSING_TEST",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is False

    def test_empty_secret_dispatch_fails_closed(self):
        """Attempting to dispatch with empty secret must fail closed before HTTP request."""
        mock_session = MagicMock()
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal/triage-alerts",
            secret_key="",
            allowed_hosts=["events.mycompany.internal"],
            session=mock_session,
        )
        with pytest.raises(AdapterPermanentError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "webhook_not_configured" in str(exc_info.value)
        assert mock_session.request.call_count == 0

    def test_allowlisted_host_and_valid_secret_passes_validation(self):
        """Valid HTTPS URL on allowlisted host with non-empty secret must pass."""
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal/triage-alerts",
            secret_key="my_super_secret_key_123",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is True

    def test_insecure_http_rejected_even_if_host_allowlisted(self):
        """Insecure HTTP URL must be rejected even if host is in allowlist."""
        adapter = WebhookAdapter(
            target="http://events.mycompany.internal/triage-alerts",
            secret_key="my_super_secret_key_123",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is False

    def test_subdomain_spoof_fails_allowlist(self):
        """Attacker host prepending or appending allowlisted domain must fail."""
        adapter = WebhookAdapter(
            target="https://events.mycompany.internal.attacker.com/leak",
            secret_key="valid_secret_key_123",
            allowed_hosts=["events.mycompany.internal"],
        )
        assert adapter.validate_config() is False
