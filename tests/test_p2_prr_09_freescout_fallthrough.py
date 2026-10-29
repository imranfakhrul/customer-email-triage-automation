"""Tests for PRR-09: Elimination of FreeScout thread append unhandled error fallthrough."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from utils.adapters.base import (
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.freescout_adapter import FreeScoutAdapter

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "freescout"


def _load_fixture(filename: str) -> dict:
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def _sample_payload(
    email_id: str = "em_prr09_reply",
    thread_id: str = "th_test_1",
    idempotency_key: str = "idem_prr09_reply",
) -> DispatchPayload:
    return DispatchPayload(
        email_id=email_id,
        message_id="<msg_prr09@example.com>",
        thread_id=thread_id,
        category="General Query",
        priority="Medium",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Follow up on previous support inquiry",
        suggested_team="Support",
        confidence=0.95,
        masked_subject="Follow up on reset",
        masked_body="Still waiting for response",
        sender_domain="example.com",
        p2_classifier_used="offline_heuristic",
        action_type="create_ticket",
        idempotency_key=idempotency_key,
    )


class TestFreeScoutThreadAppendFallthrough:
    """Verifies that unhandled HTTP status codes in thread append never create new conversations."""

    @pytest.mark.parametrize("status_code", [500, 502, 504])
    def test_thread_append_5xx_raises_unknown_outcome_and_no_fallthrough(self, status_code: int):
        """Thread append 5xx raises AdapterUnknownOutcomeError and avoids fallthrough."""
        adapter = FreeScoutAdapter(
            target="https://support.example.com",
            api_key="valid-key",
            mailbox_id=1,
        )
        payload = _sample_payload()
        list_fixture = _load_fixture("list_conversations_200.json")

        with patch.object(adapter, "_request") as mock_req:
            resp_list = MagicMock()
            resp_list.status_code = 200
            resp_list.json.return_value = list_fixture

            resp_append = MagicMock()
            resp_append.status_code = status_code

            # In fallthrough bug, 3rd call would be made to create conversation
            resp_create = MagicMock()
            resp_create.status_code = 201
            resp_create.json.return_value = {"id": 99999}

            mock_req.side_effect = [resp_list, resp_append, resp_create]

            with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
                adapter.dispatch(payload)

            assert f"freescout_server_error_{status_code}" in str(exc_info.value)
            # Must only call GET search and POST thread append; NEVER call POST /api/conversations
            assert mock_req.call_count == 2
            called_paths = [call[0][1] for call in mock_req.call_args_list]
            assert called_paths == ["/api/conversations", "/api/conversations/8812/threads"]

    @pytest.mark.parametrize("status_code", [400, 404])
    def test_thread_append_4xx_raises_permanent_and_no_fallthrough(self, status_code: int):
        """Thread append unhandled 4xx raises AdapterPermanentError and avoids fallthrough."""
        adapter = FreeScoutAdapter(
            target="https://support.example.com",
            api_key="valid-key",
            mailbox_id=1,
        )
        payload = _sample_payload()
        list_fixture = _load_fixture("list_conversations_200.json")

        with patch.object(adapter, "_request") as mock_req:
            resp_list = MagicMock()
            resp_list.status_code = 200
            resp_list.json.return_value = list_fixture

            resp_append = MagicMock()
            resp_append.status_code = status_code

            resp_create = MagicMock()
            resp_create.status_code = 201
            resp_create.json.return_value = {"id": 99999}

            mock_req.side_effect = [resp_list, resp_append, resp_create]

            with pytest.raises(AdapterPermanentError) as exc_info:
                adapter.dispatch(payload)

            assert f"freescout_http_{status_code}" in str(exc_info.value)
            assert mock_req.call_count == 2
            called_paths = [call[0][1] for call in mock_req.call_args_list]
            assert called_paths == ["/api/conversations", "/api/conversations/8812/threads"]

    @pytest.mark.parametrize("status_code, expected_reason", [
        (429, "freescout_rate_limited"),
        (503, "freescout_service_unavailable"),
    ])
    def test_thread_append_transient_errors_no_fallthrough(
        self, status_code: int, expected_reason: str
    ):
        """Thread append 429/503 raises AdapterTransientError and avoids fallthrough."""
        adapter = FreeScoutAdapter(
            target="https://support.example.com",
            api_key="valid-key",
            mailbox_id=1,
        )
        payload = _sample_payload()
        list_fixture = _load_fixture("list_conversations_200.json")

        with patch.object(adapter, "_request") as mock_req:
            resp_list = MagicMock(status_code=200)
            resp_list.json.return_value = list_fixture

            resp_append = MagicMock(status_code=status_code)
            mock_req.side_effect = [resp_list, resp_append]

            with pytest.raises(AdapterTransientError) as exc_info:
                adapter.dispatch(payload)

            assert expected_reason in str(exc_info.value)
            assert mock_req.call_count == 2

    def test_thread_append_success_returns_dispatch_result(self):
        """Thread append 201 returns DispatchResult with thread marker."""
        adapter = FreeScoutAdapter(
            target="https://support.example.com",
            api_key="valid-key",
            mailbox_id=1,
        )
        payload = _sample_payload()
        list_fixture = _load_fixture("list_conversations_200.json")
        append_fixture = _load_fixture("thread_append_201.json")

        with patch.object(adapter, "_request") as mock_req:
            resp_list = MagicMock(status_code=200)
            resp_list.json.return_value = list_fixture

            resp_append = MagicMock(status_code=201)
            resp_append.json.return_value = append_fixture

            mock_req.side_effect = [resp_list, resp_append]

            result = adapter.dispatch(payload)
            assert isinstance(result, DispatchResult)
            assert result.remote_id == "freescout:8812#thread:19483"
            assert mock_req.call_count == 2
