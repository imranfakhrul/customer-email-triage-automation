"""Tests for FreeScout Helpdesk adapter (utils/adapters/freescout_adapter.py)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from utils.adapters.base import (
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.freescout_adapter import FreeScoutAdapter

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "freescout"


def load_fixture(filename: str) -> dict:
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def sample_payload(
    email_id="em_fs_01",
    action_type="create_ticket",
    idempotency_key="em_fs_01:freescout:create_ticket",
    thread_id="th_fs_01",
) -> DispatchPayload:
    return DispatchPayload(
        email_id=email_id,
        message_id="<msg_fs_01@example.com>",
        thread_id=thread_id,
        category="General Query",
        priority="Medium",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Need help resetting password",
        suggested_team="Support",
        confidence=0.92,
        masked_subject="Password reset request [PERSON_1_1111]",
        masked_body="Please reset my password for [EMAIL_1_1111].",
        sender_domain="example.com",
        p2_classifier_used="offline_heuristic",
        action_type=action_type,
        idempotency_key=idempotency_key,
    )


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "valid-api-key"})
def test_freescout_adapter_inheritance_and_config():
    """Verify FreeScoutAdapter subclasses BaseDestinationAdapter and validates configuration."""
    adapter = FreeScoutAdapter(
        target="https://support.example.com",
        mailbox_id=1,
    )
    assert isinstance(adapter, BaseDestinationAdapter)
    assert adapter.validate_config() is True


def test_freescout_adapter_validate_config_rejects_insecure_or_missing_keys():
    """Security Invariant: Rejects plain HTTP or missing API key."""
    # Missing API Key
    with patch.dict("os.environ", {}, clear=True):
        adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
        assert adapter.validate_config() is False

    # HTTP rejected (must be HTTPS)
    with patch.dict("os.environ", {"FREESCOUT_API_KEY": "valid-key"}):
        adapter_http = FreeScoutAdapter(target="http://support.example.com", mailbox_id=1)
        assert adapter_http.validate_config() is False


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_dispatch_creates_new_conversation():
    """Verify dispatch creates conversation when no duplicate or thread match exists."""
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    payload = sample_payload()

    created_fixture = load_fixture("create_conversation_201.json")

    with patch.object(adapter, "_request") as mock_req:
        # 1. Pre-check search returns empty list
        resp_list = MagicMock()
        resp_list.status_code = 200
        resp_list.json.return_value = {"page": 1, "pages": 1, "_embedded": {"conversations": []}}

        # 2. POST create returns 201 Created
        resp_post = MagicMock()
        resp_post.status_code = 201
        resp_post.json.return_value = created_fixture

        mock_req.side_effect = [resp_list, resp_post]

        result = adapter.dispatch(payload)

        assert isinstance(result, DispatchResult)
        assert result.remote_id == "freescout:8812"

        # Check POST call payload
        call_args, call_kwargs = mock_req.call_args_list[1]
        assert call_args[0] == "POST"
        assert call_args[1] == "/api/conversations"
        sent_body = call_kwargs.get("json_data", {})
        assert sent_body["mailboxId"] == 1
        assert sent_body["type"] == "email"


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_deduplication_precheck_finds_existing_ticket():
    """Deduplication: If existing conversation contains the idempotency key marker,

    returns remote_id with zero POST calls.
    """
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    payload = sample_payload(idempotency_key="em_test_1:freescout:create_ticket")

    list_fixture = load_fixture("list_conversations_200.json")

    with patch.object(adapter, "_request") as mock_req:
        resp_list = MagicMock()
        resp_list.status_code = 200
        resp_list.json.return_value = list_fixture
        mock_req.return_value = resp_list

        result = adapter.dispatch(payload)

        assert isinstance(result, DispatchResult)
        assert result.remote_id == "freescout:8812"
        # Only GET was called, zero POST calls
        assert mock_req.call_count == 1
        assert mock_req.call_args[0][0] == "GET"


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_thread_continuity_appends_to_existing_conversation():
    """Thread Continuity: When thread_id matches existing conversation,

    appends message instead of creating new ticket.
    """
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    # Different idempotency key but same thread_id
    payload = sample_payload(
        email_id="em_test_2",
        idempotency_key="em_test_2:freescout:create_ticket",
        thread_id="th_test_1",
    )

    list_fixture = load_fixture("list_conversations_200.json")
    thread_append_fixture = load_fixture("thread_append_201.json")

    with patch.object(adapter, "_request") as mock_req:
        resp_list = MagicMock()
        resp_list.status_code = 200
        resp_list.json.return_value = list_fixture

        resp_append = MagicMock()
        resp_append.status_code = 201
        resp_append.json.return_value = thread_append_fixture

        mock_req.side_effect = [resp_list, resp_append]

        result = adapter.dispatch(payload)

        assert isinstance(result, DispatchResult)
        assert result.remote_id == "freescout:8812#thread:19483"

        # Check append call
        call_args, _call_kwargs = mock_req.call_args_list[1]
        assert call_args[0] == "POST"
        assert call_args[1] == "/api/conversations/8812/threads"


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_rate_limiting_raises_transient_error():
    """Verify HTTP 429 raises AdapterTransientError."""
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    payload = sample_payload()

    with patch.object(adapter, "_request") as mock_req:
        resp = MagicMock()
        resp.status_code = 429
        resp.text = json.dumps({"message": "Too Many Requests"})
        mock_req.return_value = resp

        with pytest.raises(AdapterTransientError) as exc_info:
            adapter.dispatch(payload)
        assert "freescout_rate_limited" in str(exc_info.value)


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_validation_failure_raises_permanent_error():
    """Verify HTTP 422 raises AdapterPermanentError."""
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    payload = sample_payload()

    with patch.object(adapter, "_request") as mock_req:
        # Precheck passes
        resp_list = MagicMock()
        resp_list.status_code = 200
        resp_list.json.return_value = {"_embedded": {"conversations": []}}

        # POST returns 422
        resp_post = MagicMock()
        resp_post.status_code = 422
        resp_post.text = json.dumps(load_fixture("error_422.json"))

        mock_req.side_effect = [resp_list, resp_post]

        with pytest.raises(AdapterPermanentError) as exc_info:
            adapter.dispatch(payload)
        assert "freescout_validation_failed" in str(exc_info.value)


@patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
def test_freescout_timeout_raises_unknown_outcome_error():
    """Verify timeout on POST raises AdapterUnknownOutcomeError."""
    adapter = FreeScoutAdapter(target="https://support.example.com", mailbox_id=1)
    payload = sample_payload()

    with patch.object(adapter, "_request") as mock_req:
        resp_list = MagicMock()
        resp_list.status_code = 200
        resp_list.json.return_value = {"_embedded": {"conversations": []}}

        mock_req.side_effect = [resp_list, requests.exceptions.ReadTimeout("Timeout")]

        with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
            adapter.dispatch(payload)
        assert "freescout_network_timeout" in str(exc_info.value)
