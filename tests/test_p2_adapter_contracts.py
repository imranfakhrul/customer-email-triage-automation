"""Adapter contract and JSON schema verification test suite for Phase 2.

Milestone [P2-10]:
Verifies schema, header, and error response contract conformance across all 4 destination adapters:
1. GitHub Issues Adapter (docs/contracts/github_issues.md)
2. FreeScout Helpdesk Adapter (docs/contracts/freescout.md)
3. HubSpot CRM Adapter (docs/contracts/crm_hubspot.md)
4. Webhook Alert Adapter (docs/contracts/webhook_alert.md)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from utils.adapters.base import (
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.crm_adapter import CRMAdapter
from utils.adapters.crm_format import build_hubspot_payload
from utils.adapters.freescout_adapter import FreeScoutAdapter
from utils.adapters.freescout_format import build_conversation_payload
from utils.adapters.github_adapter import GitHubAdapter
from utils.adapters.github_format import build_issue_body, build_labels, sanitize_title
from utils.adapters.webhook_adapter import WebhookAdapter
from utils.config import BASE_DIR, get_config


@pytest.fixture
def base_config() -> dict[str, Any]:
    cfg = get_config()
    cfg_copy = json.loads(json.dumps(cfg))
    cfg_copy["dispatch"]["dry_run"] = False
    return cfg_copy


def _make_payload(
    email_id: str = "em_test",
    destination: str = "github",
    action_type: str = "create_issue",
    category: str = "Bug Report",
    priority: str = "High",
    subject: str = "Test Subject",
    body: str = "Test Body",
    sender_domain: str = "domain.com",
    confidence: float = 0.95,
) -> DispatchPayload:
    return DispatchPayload(
        email_id=email_id,
        message_id=f"<{email_id}@ex.com>",
        thread_id=f"th_{email_id}",
        category=category,
        priority=priority,
        sentiment="Neutral",
        customer_emotion="Calm",
        summary=subject,
        suggested_team="Engineering",
        confidence=confidence,
        masked_subject=subject,
        masked_body=body,
        sender_domain=sender_domain,
        p2_classifier_used="jev",
        action_type=action_type,
        idempotency_key=f"{email_id}:{destination}:{action_type}",
    )


def test_github_adapter_contract_conformance(
    base_config: dict[str, Any], monkeypatch: pytest.MonkeyPatch
):
    """Verifies GitHub issue creation conforms to docs/contracts/github_issues.md."""
    fixture_path = BASE_DIR / "tests" / "fixtures" / "github" / "create_issue_201.json"
    with open(fixture_path, encoding="utf-8") as f:
        mock_resp_data = json.load(f)

    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 201
    mock_resp.json.return_value = mock_resp_data
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_session.request.return_value = mock_resp

    adapter = GitHubAdapter(config=base_config, session=mock_session)
    monkeypatch.setenv(adapter._token_env, "ghp_mock_token_12345")

    payload = _make_payload(
        email_id="em_gh_contract_01",
        destination="github",
        action_type="create_issue",
        category="Bug Report",
        priority="High",
        subject="Memory leak in data processor",
        body="OOM crash on node [IP_ADDRESS_1].",
        sender_domain="fintech.de",
    )

    title = sanitize_title(payload.masked_subject, payload.category)
    body = build_issue_body(payload)
    labels = build_labels(payload, base_labels=adapter._labels)

    assert title.startswith(f"[{payload.category}] ")
    assert "<!-- triage-bot:v1" in body
    assert "type:bug" in labels
    assert "urgency:high" in labels

    with patch.object(adapter, "check_duplicate", return_value=None):
        result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert "#42" in result.remote_id

    call_args, call_kwargs = mock_session.request.call_args
    method = call_kwargs.get("method") or (call_args[0] if call_args else None)
    assert method == "POST"
    headers = call_kwargs["headers"]
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["Authorization"] == "Bearer ghp_mock_token_12345"


def test_freescout_adapter_contract_conformance(base_config: dict[str, Any]):
    """Verifies FreeScout ticket payload conforms to docs/contracts/freescout.md."""
    fixture_path = BASE_DIR / "tests" / "fixtures" / "freescout" / "create_conversation_201.json"
    with open(fixture_path, encoding="utf-8") as f:
        mock_resp_data = json.load(f)

    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 201
    mock_resp.json.return_value = mock_resp_data
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_session.request.return_value = mock_resp

    adapter = FreeScoutAdapter(
        target="https://support.example.com",
        api_key="fs_mock_key_999",
        mailbox_id=1,
        allowed_hosts=["support.example.com"],
        session=mock_session,
    )

    payload = _make_payload(
        email_id="em_fs_contract_01",
        destination="freescout",
        action_type="create_ticket",
        category="General Query",
        priority="Medium",
        subject="Help setting up custom SSO",
        body="Hi, how do we configure SAML? Call us at [PHONE_1].",
        sender_domain="acme.com",
    )

    conv_payload = build_conversation_payload(
        record={
            "email_id": payload.email_id,
            "masked_subject": payload.masked_subject,
            "masked_body": payload.masked_body,
            "sender_email": "admin@acme.com",
            "sender_domain": payload.sender_domain,
            "thread_id": payload.thread_id,
        },
        mailbox_id=1,
        idempotency_key=payload.idempotency_key,
        unmask_pii=False,
    )

    assert conv_payload["mailboxId"] == 1
    assert conv_payload["type"] == "email"
    thread_text = conv_payload["threads"][0]["text"]
    assert thread_text.startswith("<!-- triage-bot:v1\nkey: ")

    with patch.object(adapter, "check_duplicate", return_value=None):
        result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert result.remote_id == "freescout:8812"

    _, call_kwargs = mock_session.request.call_args
    headers = call_kwargs["headers"]
    assert headers["X-FreeScout-API-Key"] == "fs_mock_key_999"


def test_crm_adapter_contract_conformance(base_config: dict[str, Any]):
    """Verifies HubSpot CRM contact payload conforms to docs/contracts/crm_hubspot.md."""
    fixture_path = BASE_DIR / "tests" / "fixtures" / "crm" / "create_contact_201.json"
    with open(fixture_path, encoding="utf-8") as f:
        mock_resp_data = json.load(f)

    record = {
        "email_id": "em_crm_contract_01",
        "sender_email": "elena@enterprise.com",
        "customer_email": "elena@enterprise.com",
        "sender_domain": "enterprise.com",
        "masked_subject": "Enterprise Demo Inquiry",
        "masked_body": "We need a demo for our team.",
        "category": "Demo Request",
        "priority": "High",
        "sentiment": "Positive",
        "confidence": 0.92,
        "token_map": {"[PERSON_1]": "Elena Rostova", "[PHONE_1]": "+1 555 234 5678"},
    }
    hubspot_payload = build_hubspot_payload(
        record=record,
        idempotency_key="em_crm_contract_01:crm:create_lead",
        unmask_pii=True,
    )
    contact_props = hubspot_payload["properties"]

    assert contact_props["email"] == "elena@enterprise.com"
    assert contact_props["firstname"] == "Elena"
    assert contact_props["lastname"] == "Rostova"
    assert contact_props["hs_lead_status"] == "NEW"
    assert int(contact_props["lead_score"]) >= 70

    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 201
    mock_resp.json.return_value = mock_resp_data
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_session.request.return_value = mock_resp

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="pat_mock_hubspot_token",
        allowed_hosts=["api.hubapi.com"],
        session=mock_session,
    )

    payload = _make_payload(
        email_id="em_crm_contract_01",
        destination="crm",
        action_type="create_lead",
        category="Demo Request",
        priority="High",
        subject="Enterprise Demo Inquiry",
        body="We need a demo for our team.",
        sender_domain="enterprise.com",
    )

    with patch.object(adapter, "check_duplicate", return_value=None):
        result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert result.remote_id == "crm:1059281"

    _, call_kwargs = mock_session.request.call_args
    headers = call_kwargs["headers"]
    assert headers["Authorization"] == "Bearer pat_mock_hubspot_token"


def test_webhook_adapter_contract_conformance(base_config: dict[str, Any]):
    """Verifies Webhook alert payload conforms to docs/contracts/webhook_alert.md."""
    fixture_path = BASE_DIR / "tests" / "fixtures" / "webhook" / "alert_200.json"
    with open(fixture_path, encoding="utf-8") as f:
        mock_resp_data = json.load(f)

    secret = "test_signing_secret_key"
    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_resp_data
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_session.request.return_value = mock_resp

    adapter = WebhookAdapter(
        target="https://events.example.com/alerts",
        secret_key=secret,
        allowed_hosts=["events.example.com"],
        session=mock_session,
    )

    payload = _make_payload(
        email_id="em_wh_contract_01",
        destination="webhook",
        action_type="alert",
        category="Billing Issue",
        priority="Critical",
        subject="URGENT: Billed twice for invoice INV-100",
        body="Our credit card [CREDIT_CARD_1] was charged twice.",
        sender_domain="acme.com",
    )

    result = adapter.dispatch(payload)

    assert isinstance(result, DispatchResult)
    assert result.remote_id == f"webhook:{payload.email_id}"

    _, call_kwargs = mock_session.request.call_args
    headers = call_kwargs["headers"]
    assert "X-Signature-SHA256" in headers
    assert "X-Timestamp-ISO" in headers
    assert headers["Idempotency-Key"] == payload.idempotency_key

    sent_data = call_kwargs["data"]
    expected_hex = hmac.new(secret.encode("utf-8"), sent_data, hashlib.sha256).hexdigest()
    assert headers["X-Signature-SHA256"] == f"sha256={expected_hex}"


def test_universal_adapter_error_contract_mappings(base_config: dict[str, Any]):
    """Verifies all 4 destination adapters adhere to unified error classification."""
    # 1. 429 Rate Limit -> AdapterTransientError
    # 2. 401 Unauthorized -> AdapterPermanentError
    # 3. 422 Unprocessable Entity -> AdapterPermanentError
    # 4. Timeout -> AdapterUnknownOutcomeError

    adapter_cases = [
        (
            "github",
            GitHubAdapter(config=base_config, session=MagicMock()),
            _make_payload(destination="github", action_type="create_issue"),
        ),
        (
            "freescout",
            FreeScoutAdapter(
                target="https://support.example.com",
                api_key="fs_k",
                mailbox_id=1,
                allowed_hosts=["support.example.com"],
                session=MagicMock(),
            ),
            _make_payload(destination="freescout", action_type="create_ticket"),
        ),
        (
            "crm",
            CRMAdapter(
                target="https://api.hubapi.com",
                api_key="crm_k",
                allowed_hosts=["api.hubapi.com"],
                session=MagicMock(),
            ),
            _make_payload(destination="crm", action_type="create_lead"),
        ),
        (
            "webhook",
            WebhookAdapter(
                target="https://events.example.com/alerts",
                secret_key="wh_k",
                allowed_hosts=["events.example.com"],
                session=MagicMock(),
            ),
            _make_payload(destination="webhook", action_type="alert"),
        ),
    ]

    for _name, adapter, payload in adapter_cases:
        if hasattr(adapter, "_token"):
            adapter._token = "mock_tok"

        # Test 429 -> AdapterTransientError
        mock_resp_429 = MagicMock(
            spec=requests.Response,
            status_code=429,
            headers={"Retry-After": "30"},
            text="rate limited",
        )
        adapter._session.request = MagicMock(return_value=mock_resp_429)
        with (
            patch.object(adapter, "check_duplicate", return_value=None),
            pytest.raises(AdapterTransientError),
        ):
            adapter.dispatch(payload)

        # Test 401 -> AdapterPermanentError
        mock_resp_401 = MagicMock(
            spec=requests.Response,
            status_code=401,
            headers={},
            text="unauthorized",
        )
        adapter._session.request = MagicMock(return_value=mock_resp_401)
        with (
            patch.object(adapter, "check_duplicate", return_value=None),
            pytest.raises(AdapterPermanentError),
        ):
            adapter.dispatch(payload)

        # Test 422 -> AdapterPermanentError
        mock_resp_422 = MagicMock(
            spec=requests.Response,
            status_code=422,
            headers={},
            text="unprocessable",
        )
        adapter._session.request = MagicMock(return_value=mock_resp_422)
        with (
            patch.object(adapter, "check_duplicate", return_value=None),
            pytest.raises(AdapterPermanentError),
        ):
            adapter.dispatch(payload)

        # Test Timeout -> AdapterUnknownOutcomeError
        adapter._session.request = MagicMock(
            side_effect=requests.exceptions.ReadTimeout("Timeout")
        )
        with (
            patch.object(adapter, "check_duplicate", return_value=None),
            pytest.raises(AdapterUnknownOutcomeError),
        ):
            adapter.dispatch(payload)
