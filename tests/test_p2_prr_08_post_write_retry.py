"""Tests for PRR-08: Error classification of connection setup vs post-write connection resets."""

import socket
from unittest.mock import MagicMock

import pytest
import requests
import urllib3.exceptions

from utils.adapters.base import (
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    DispatchPayload,
    is_connection_setup_error,
)
from utils.adapters.crm_adapter import CRMAdapter
from utils.adapters.freescout_adapter import FreeScoutAdapter
from utils.adapters.webhook_adapter import WebhookAdapter


def _make_payload(email_id: str = "em_prr08_test") -> DispatchPayload:
    return DispatchPayload(
        email_id=email_id,
        message_id="<msg_prr08@example.com>",
        thread_id="th_prr08_123",
        category="Bug Report",
        priority="High",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Database query timeout on report export",
        suggested_team="Engineering",
        confidence=0.95,
        masked_subject="Export error",
        masked_body="Queries timing out during export",
        sender_domain="example.com",
        p2_classifier_used="jev",
        action_type="create_issue",
        idempotency_key=f"github:org/repo:idem_{email_id}",
    )


class TestIsConnectionSetupError:
    """Verifies is_connection_setup_error correctly differentiates setup vs post-write failures."""

    def test_new_connection_error_is_setup(self):
        exc = requests.exceptions.ConnectionError(
            urllib3.exceptions.NewConnectionError(None, "Connection refused")
        )
        assert is_connection_setup_error(exc) is True

    def test_name_resolution_error_is_setup(self):
        name_err = urllib3.exceptions.NameResolutionError(
            "api.example.com", None, "DNS resolution failed"
        )
        exc = requests.exceptions.ConnectionError(
            urllib3.exceptions.MaxRetryError(None, "https://api.example.com", name_err)
        )
        assert is_connection_setup_error(exc) is True

    def test_connect_timeout_is_setup(self):
        exc = requests.exceptions.ConnectTimeout("Connect timeout to remote port")
        assert is_connection_setup_error(exc) is True

    def test_connection_refused_os_error_is_setup(self):
        exc = requests.exceptions.ConnectionError(ConnectionRefusedError(111, "Connection refused"))
        assert is_connection_setup_error(exc) is True

    def test_socket_gaierror_is_setup(self):
        exc = requests.exceptions.ConnectionError(socket.gaierror(-2, "Name or service not known"))
        assert is_connection_setup_error(exc) is True

    def test_connection_reset_by_peer_is_not_setup(self):
        exc = requests.exceptions.ConnectionError("Connection reset by peer")
        assert is_connection_setup_error(exc) is False

    def test_connection_reset_os_error_is_not_setup(self):
        os_err = ConnectionResetError(104, "Connection reset by peer")
        exc = requests.exceptions.ConnectionError(os_err)
        assert is_connection_setup_error(exc) is False

    def test_protocol_error_is_not_setup(self):
        proto_err = urllib3.exceptions.ProtocolError(
            "Connection aborted.", ConnectionResetError(104, "Connection reset")
        )
        exc = requests.exceptions.ConnectionError(proto_err)
        assert is_connection_setup_error(exc) is False

    def test_bare_connection_error_is_not_setup(self):
        exc = requests.exceptions.ConnectionError("Connection dropped unexpectedly")
        assert is_connection_setup_error(exc) is False


class TestWebhookAdapterErrorClassification:
    """Verifies WebhookAdapter classifies setup vs post-write connection failures."""

    def test_webhook_setup_failure_raises_transient(self):
        mock_session = MagicMock()
        mock_session.request.side_effect = requests.exceptions.ConnectionError(
            urllib3.exceptions.NewConnectionError(None, "Connection refused")
        )
        adapter = WebhookAdapter(
            target="https://events.example.com/alerts",
            secret_key="secret",
            allowed_hosts=["events.example.com"],
            session=mock_session,
        )
        with pytest.raises(AdapterTransientError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "webhook_connection_failed" in str(exc_info.value)

    def test_webhook_post_write_reset_raises_unknown_outcome(self):
        mock_session = MagicMock()
        mock_session.request.side_effect = requests.exceptions.ConnectionError(
            "Connection reset by peer"
        )
        adapter = WebhookAdapter(
            target="https://events.example.com/alerts",
            secret_key="secret",
            allowed_hosts=["events.example.com"],
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "webhook_connection_error" in str(exc_info.value)

    def test_webhook_ambiguous_500_raises_unknown_outcome(self):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(status_code=500)
        adapter = WebhookAdapter(
            target="https://events.example.com/alerts",
            secret_key="secret",
            allowed_hosts=["events.example.com"],
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError):
            adapter.dispatch(_make_payload())

    def test_webhook_ambiguous_502_raises_unknown_outcome(self):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(status_code=502)
        adapter = WebhookAdapter(
            target="https://events.example.com/alerts",
            secret_key="secret",
            allowed_hosts=["events.example.com"],
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError):
            adapter.dispatch(_make_payload())


class TestFreeScoutAdapterErrorClassification:
    """Verifies FreeScoutAdapter classifies setup vs post-write connection failures."""

    def test_freescout_setup_failure_raises_transient(self):
        mock_session = MagicMock()
        mock_session.request.side_effect = requests.exceptions.ConnectionError(
            urllib3.exceptions.NewConnectionError(None, "Connection refused")
        )
        adapter = FreeScoutAdapter(
            target="https://helpdesk.example.com",
            api_key="api_key_secret",
            mailbox_id=1,
            session=mock_session,
        )
        with pytest.raises(AdapterTransientError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "freescout_connection_failed" in str(exc_info.value)

    def test_freescout_post_write_reset_raises_unknown_outcome(self):
        mock_session = MagicMock()
        mock_session.request.side_effect = requests.exceptions.ConnectionError(
            "Connection reset by peer"
        )
        adapter = FreeScoutAdapter(
            target="https://helpdesk.example.com",
            api_key="api_key_secret",
            mailbox_id=1,
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "freescout_connection_error" in str(exc_info.value)

    def test_freescout_ambiguous_500_raises_unknown_outcome(self):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(status_code=500)
        adapter = FreeScoutAdapter(
            target="https://helpdesk.example.com",
            api_key="api_key_secret",
            mailbox_id=1,
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError):
            adapter.dispatch(_make_payload())


class TestCRMAdapterErrorClassification:
    """Verifies CRMAdapter classifies setup vs post-write connection failures."""

    def test_crm_setup_failure_raises_transient(self):
        mock_session = MagicMock()
        get_res = MagicMock(status_code=404)
        mock_session.request.side_effect = [
            get_res,
            requests.exceptions.ConnectionError(
                urllib3.exceptions.NewConnectionError(None, "Connection refused")
            ),
        ]
        adapter = CRMAdapter(
            target="https://api.hubapi.com",
            api_key="api_key_secret",
            session=mock_session,
        )
        with pytest.raises(AdapterTransientError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "crm_connection_failed" in str(exc_info.value)

    def test_crm_post_write_reset_raises_unknown_outcome(self):
        mock_session = MagicMock()
        get_res = MagicMock(status_code=404)
        mock_session.request.side_effect = [
            get_res,
            requests.exceptions.ConnectionError("Connection reset by peer"),
        ]
        adapter = CRMAdapter(
            target="https://api.hubapi.com",
            api_key="api_key_secret",
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
            adapter.dispatch(_make_payload())
        assert "crm_connection_error" in str(exc_info.value)

    def test_crm_ambiguous_500_raises_unknown_outcome(self):
        mock_session = MagicMock()
        get_res = MagicMock(status_code=404)
        post_res = MagicMock(status_code=500)
        mock_session.request.side_effect = [get_res, post_res]
        adapter = CRMAdapter(
            target="https://api.hubapi.com",
            api_key="api_key_secret",
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError):
            adapter.dispatch(_make_payload())

    def test_crm_ambiguous_502_raises_unknown_outcome(self):
        mock_session = MagicMock()
        get_res = MagicMock(status_code=404)
        post_res = MagicMock(status_code=502)
        mock_session.request.side_effect = [get_res, post_res]
        adapter = CRMAdapter(
            target="https://api.hubapi.com",
            api_key="api_key_secret",
            session=mock_session,
        )
        with pytest.raises(AdapterUnknownOutcomeError):
            adapter.dispatch(_make_payload())
