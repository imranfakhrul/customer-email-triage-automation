"""Unit tests for HubSpot CRM Destination Adapter."""

import json
from pathlib import Path
from unittest.mock import MagicMock

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
from utils.adapters.crm_adapter import CRMAdapter

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "crm"


def _load_fixture(filename: str) -> dict:
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def _make_payload(
    email_id: str = "em_crm_test_001",
    idempotency_key: str = "idemp_crm_test_001",
    category: str = "Demo Request",
    priority: str = "High",
    sender_email: str = "jane.prospect@enterprise.com",
) -> DispatchPayload:
    record = {
        "email_id": email_id,
        "message_id": f"<{email_id}@enterprise.com>",
        "thread_id": f"th_{email_id}",
        "category": category,
        "priority": priority,
        "sentiment": "Positive",
        "customer_emotion": "curious",
        "summary": "Enterprise demo inquiry",
        "suggested_team": "Sales",
        "confidence": 0.95,
        "masked_subject": "Demo request for 500 seats",
        "masked_body": "Hello, we would like a live demo for our enterprise team.",
        "sender_email": sender_email,
        "sender_domain": "enterprise.com",
        "p2_classifier_used": "jev",
    }
    return DispatchPayload.from_record(
        record=record,
        action_type="create_lead",
        idempotency_key=idempotency_key,
    )


def test_crm_adapter_inheritance_and_config():
    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test_token_123",
        allowed_hosts=["api.hubapi.com"],
    )
    assert isinstance(adapter, BaseDestinationAdapter)
    assert adapter.name == "crm"
    assert adapter.validate_config() is True


def test_crm_adapter_validate_config_rejects_insecure_or_missing_keys():
    # Insecure HTTP
    a_http = CRMAdapter(target="http://api.hubapi.com", api_key="valid_key")
    assert a_http.validate_config() is False

    # Unlisted host
    a_host = CRMAdapter(
        target="https://evil.attacker.com",
        api_key="valid_key",
        allowed_hosts=["api.hubapi.com"],
    )
    assert a_host.validate_config() is False

    # Missing API key
    a_nokey = CRMAdapter(target="https://api.hubapi.com", api_key="")
    assert a_nokey.validate_config() is False


def test_crm_dispatch_creates_new_contact():
    mock_session = MagicMock()

    # 1. Pre-check GET returns 404 (not found)
    get_res = MagicMock(status_code=404)

    # 2. POST returns 201 Created
    post_res = MagicMock(status_code=201)
    post_res.json.return_value = _load_fixture("create_contact_201.json")

    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test_key",
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert result.remote_id == "crm:1059281"
    assert mock_session.request.call_count == 2


def test_crm_deduplication_precheck_finds_existing_contact():
    mock_session = MagicMock()

    # Pre-check GET returns 200 with existing contact
    get_res = MagicMock(status_code=200)
    get_res.json.return_value = _load_fixture("get_contact_200.json")
    mock_session.request.return_value = get_res

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test_key",
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert result.remote_id == "crm:1059281"
    # Should skip POST
    assert mock_session.request.call_count == 1


def test_crm_409_conflict_recovers_existing_contact():
    mock_session = MagicMock()

    # Pre-check GET returns 404
    get_res = MagicMock(status_code=404)

    # POST returns 409 Conflict with existingId
    post_res = MagicMock(status_code=409)
    post_res.json.return_value = _load_fixture("error_409_conflict.json")

    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test_key",
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert result.remote_id == "crm:1059281"


def test_crm_rate_limiting_raises_transient_error():
    mock_session = MagicMock()
    get_res = MagicMock(status_code=404)
    post_res = MagicMock(status_code=429)
    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(target="https://api.hubapi.com", api_key="key", session=mock_session)
    with pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "crm_rate_limited" in str(exc_info.value)


def test_crm_503_raises_transient_error():
    mock_session = MagicMock()
    get_res = MagicMock(status_code=404)
    post_res = MagicMock(status_code=503)
    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(target="https://api.hubapi.com", api_key="key", session=mock_session)
    with pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "crm_service_unavailable" in str(exc_info.value)


def test_crm_validation_failure_raises_permanent_error():
    mock_session = MagicMock()
    get_res = MagicMock(status_code=404)
    post_res = MagicMock(status_code=422)
    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(target="https://api.hubapi.com", api_key="key", session=mock_session)
    with pytest.raises(AdapterPermanentError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "crm_validation_failed" in str(exc_info.value)


def test_crm_timeout_raises_unknown_outcome_error():
    mock_session = MagicMock()
    get_res = MagicMock(status_code=404)
    mock_session.request.side_effect = [get_res, requests.exceptions.ReadTimeout("timed out")]

    adapter = CRMAdapter(target="https://api.hubapi.com", api_key="key", session=mock_session)
    with pytest.raises(AdapterUnknownOutcomeError) as exc_info:
        adapter.dispatch(_make_payload())
    assert "crm_network_timeout" in str(exc_info.value)


def test_crm_dispatch_from_record_with_unmask_pii_sends_real_customer_email():
    """Verify that DispatchPayload.from_record passes sender_email to CRM."""
    mock_session = MagicMock()
    search_res = MagicMock(status_code=200)
    search_res.json.return_value = {"total": 0, "results": []}

    post_res = MagicMock(status_code=201)
    post_res.json.return_value = {"id": "1059281"}

    mock_session.request.side_effect = [search_res, post_res]

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test-api-key",
        session=mock_session,
        unmask_pii=True,
    )
    record = {
        "email_id": "em_crm_unmask_01",
        "message_id": "<msg_unmask_01@enterprise.com>",
        "thread_id": "th_crm_unmask_01",
        "sender_email": "jane@acmecorp.com",
        "masked_subject": "Enterprise Demo Request for [PERSON_1_2222]",
        "masked_body": "Hi, I am [PERSON_1_2222]. Please call [PHONE_1_2222].",
        "token_map": {
            "[PERSON_1_2222]": "Jane Doe",
            "[PHONE_1_2222]": "+1-555-0144",
            "[CREDIT_CARD_1_2222]": "4111111111111111",
        },
        "category": "Demo Request",
        "priority": "High",
    }
    payload = DispatchPayload.from_record(
        record,
        action_type="create_lead",
        idempotency_key="em_crm_unmask_01:crm:create_lead",
    )

    result = adapter.dispatch(payload)
    assert result.remote_id == "crm:1059281"

    post_call = mock_session.request.call_args_list[1]
    sent_json = post_call.kwargs.get("json") or post_call[1].get("json")
    props = sent_json["properties"]
    assert props["email"] == "jane@acmecorp.com"
    assert props["firstname"] == "Jane"
    assert props["lastname"] == "Doe"
    assert props["phone"] == "+1-555-0144"


def test_crm_400_property_doesnt_exist_prunes_and_recovers_contact():
    """Verify that 400 PROPERTY_DOESNT_EXIST prunes unconfigured custom properties and retries."""
    mock_session = MagicMock()
    # 1. Pre-check GET returns 404
    get_res = MagicMock(status_code=404)

    # 2. First POST returns 400 with missing properties
    err_res = MagicMock(status_code=400)
    err_res.json.return_value = {
        "status": "error",
        "errors": [
            {
                "code": "PROPERTY_DOESNT_EXIST",
                "context": {"propertyName": ["lead_score"]},
            },
            {
                "code": "PROPERTY_DOESNT_EXIST",
                "context": {"propertyName": ["triage_idempotency_key"]},
            },
        ],
    }

    # 3. Second POST returns 201 Created
    ok_res = MagicMock(status_code=201)
    ok_res.json.return_value = {"id": "999888"}

    mock_session.request.side_effect = [get_res, err_res, ok_res]

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="test-api-key",
        session=mock_session,
    )
    payload = _make_payload()
    result = adapter.dispatch(payload)

    assert result.remote_id == "crm:999888"
    assert mock_session.request.call_count == 3
    # Verify retry POST did not contain the missing properties
    retry_call = mock_session.request.call_args_list[2]
    retry_props = (retry_call.kwargs.get("json") or retry_call[1].get("json"))["properties"]
    assert "lead_score" not in retry_props
    assert "triage_idempotency_key" not in retry_props
    assert "email" in retry_props


