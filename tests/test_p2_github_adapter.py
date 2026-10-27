"""Comprehensive test suite for P2-04b: GitHub Issues Destination Adapter."""

import logging
import tempfile
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests.exceptions
import urllib3.exceptions

from db.database import TriageDatabase
from nodes.dispatcher import dispatcher_node
from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    DispatchPayload,
)
from utils.adapters.github_adapter import GitHubAdapter, create_github_adapter
from utils.adapters.github_format import build_marker, parse_marker


# ---------------------------------------------------------------------------
# Test Doubles: FakeResponse and FakeSession
# ---------------------------------------------------------------------------
class FakeResponse:
    """Mock HTTP Response for requests session testing."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.headers = headers or {}

    def json(self) -> Any:
        if self._json_data is not None:
            return self._json_data
        if self.text:
            import json

            return json.loads(self.text)
        raise ValueError("No JSON payload available")


class FakeSession:
    """Scriptable mock requests.Session capturing all request parameters."""

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses: list[Any] = list(responses) if responses is not None else []
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise RuntimeError("FakeSession: No scripted responses remaining in queue")
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        if callable(resp) and not isinstance(resp, type):
            return resp()
        return resp


@pytest.fixture
def temp_db() -> Generator[TriageDatabase, None, None]:
    """Provides a fresh isolated SQLite database instance."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = TriageDatabase(db_path=tmp.name)
        yield db


def base_github_config(
    enabled: bool = True,
    target: str = "my-company/backend-repo",
    api_base_url: str = "https://api.github.com",
    allowed_hosts: list[str] | None = None,
    precheck_duplicates: bool = True,
    bot_login: str | None = "triage-bot",
) -> dict[str, Any]:
    """Returns a valid configuration dictionary for testing the GitHub adapter."""
    return {
        "dispatch": {
            "dry_run": False,
            "kill_switch": False,
            "max_attempts": 3,
            "pending_timeout_minutes": 10,
            "backoff_base_seconds": 0.01,
            "backoff_max_seconds": 0.05,
        },
        "destinations": {
            "github": {
                "enabled": enabled,
                "daily_cap": 200,
                "use_masked_text_only": True,
                "target": target,
                "token_env": "TEST_GITHUB_TOKEN",
                "labels": ["triage:automated"],
                "api_base_url": api_base_url,
                "allowed_hosts": allowed_hosts or ["api.github.com"],
                "request_timeout_seconds": 15.0,
                "duplicate_lookback_hours": 72,
                "duplicate_max_pages": 3,
                "precheck_duplicates": precheck_duplicates,
                "bot_login": bot_login,
                "api_version": "2022-11-28",
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "cooldown_seconds": 60,
                },
            },
            "freescout": {
                "enabled": False,
                "daily_cap": 1000,
                "use_masked_text_only": False,
                "target": "https://support.example.com",
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 60},
            },
            "crm": {
                "enabled": False,
                "daily_cap": 500,
                "use_masked_text_only": False,
                "target_env": "CRM_ENDPOINT",
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 60},
            },
            "webhook": {
                "enabled": False,
                "daily_cap": 200,
                "use_masked_text_only": False,
                "target_env": "WEBHOOK_URL",
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 60},
            },
        },
    }


def make_payload(
    email_id: str = "em_test_001",
    category: str = "Bug Report",
    priority: str = "High",
    subject: str = "Postgres connection pool exhausted",
    body: str = "Hi team, we are seeing connection timeouts on backend service.",
    idempotency_key: str | None = None,
) -> DispatchPayload:
    """Helper constructing a valid DispatchPayload."""
    key = idempotency_key or f"{email_id}:github:create_issue"
    return DispatchPayload(
        email_id=email_id,
        message_id="msg_001@example.com",
        thread_id="thread_001",
        category=category,
        priority=priority,
        sentiment="Negative",
        customer_emotion="Frustrated",
        summary="Postgres pool exhausted on backend",
        suggested_team="Engineering",
        confidence=0.95,
        masked_subject=subject,
        masked_body=body,
        sender_domain="client.com",
        p2_classifier_used="jev",
        action_type="create_issue",
        idempotency_key=key,
    )


# ---------------------------------------------------------------------------
# Unit Tests
# ---------------------------------------------------------------------------

def test_request_details_headers_and_payload_isolation(monkeypatch):
    """Verify HTTP request method, URL, headers, and payload structure."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "ghp_secret_token_123")
    cfg = base_github_config(precheck_duplicates=False)
    session = FakeSession([FakeResponse(status_code=201, json_data={"number": 42})])
    adapter = create_github_adapter(config=cfg, session=session)

    payload = make_payload()
    result = adapter.dispatch(payload)

    assert result.remote_id == "my-company/backend-repo#42"
    assert len(session.calls) == 1

    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://api.github.com/repos/my-company/backend-repo/issues"
    assert call["allow_redirects"] is False
    assert call["timeout"] == (5.0, 15.0)

    # Headers
    headers = call["headers"]
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["Authorization"] == "Bearer ghp_secret_token_123"
    assert headers["User-Agent"] == "email-triage-bot"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"

    # JSON payload structure
    json_body = call["json"]
    assert set(json_body.keys()) == {"title", "body", "labels"}
    assert json_body["title"].startswith("[Bug Report] ")
    assert parse_marker(json_body["body"]) == payload.idempotency_key
    assert "triage:automated" in json_body["labels"]
    assert "type:bug" in json_body["labels"]
    assert "urgency:high" in json_body["labels"]

    # Token isolation: token never in URL or JSON payload
    assert "ghp_secret_token_123" not in call["url"]
    assert "ghp_secret_token_123" not in str(json_body)


def test_precheck_found_avoids_post(monkeypatch):
    """Verify that when precheck finds an existing issue, no POST call is made."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "ghp_secret_token_123")
    cfg = base_github_config(precheck_duplicates=True)
    payload = make_payload(idempotency_key="em_001:github:create_issue")

    # Script precheck GET returning an issue with the matching marker
    marker_body = build_marker(payload.idempotency_key) + "Some earlier issue body"
    issues_list = [
        {"number": 101, "body": marker_body, "user": {"login": "triage-bot"}},
    ]
    session = FakeSession([FakeResponse(status_code=200, json_data=issues_list)])
    adapter = GitHubAdapter(config=cfg, session=session)

    result = adapter.dispatch(payload)
    assert result.remote_id == "my-company/backend-repo#101"

    # Exactly 1 call was made (GET /issues), zero POST calls
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"


def test_precheck_failing_raises_transient_error_and_avoids_post(monkeypatch):
    """Verify precheck failure raises AdapterTransientError without attempting POST."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "ghp_secret_token_123")
    cfg = base_github_config(precheck_duplicates=True)
    payload = make_payload()

    # Precheck GET fails with 500
    session = FakeSession([FakeResponse(status_code=500, text="Internal Server Error")])
    adapter = GitHubAdapter(config=cfg, session=session)

    with pytest.raises(AdapterTransientError, match="github_precheck_failed"):
        adapter.dispatch(payload)

    # Only GET was attempted, zero POST calls
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"


@pytest.mark.parametrize(
    ("status_code", "json_data", "headers", "expected_exc"),
    [
        (200, {"number": 1}, {}, AdapterUnknownOutcomeError),
        (201, "invalid json string", {}, AdapterUnknownOutcomeError),
        (201, {"id": 123}, {}, AdapterUnknownOutcomeError),  # Missing 'number'
        (201, {"number": "42"}, {}, AdapterUnknownOutcomeError),  # 'number' is str, not int
        (301, {}, {}, AdapterPermanentError),
        (302, {}, {}, AdapterPermanentError),
        (400, {}, {}, AdapterPermanentError),
        (401, {}, {}, AdapterPermanentError),
        (403, {}, {}, AdapterPermanentError),  # Plain 403
        (403, {}, {"x-ratelimit-remaining": "0"}, AdapterTransientError),
        (403, {}, {"retry-after": "60"}, AdapterTransientError),
        (404, {}, {}, AdapterPermanentError),
        (410, {}, {}, AdapterPermanentError),
        (422, {}, {}, AdapterPermanentError),
        (429, {}, {}, AdapterTransientError),
        (500, {}, {}, AdapterUnknownOutcomeError),
        (502, {}, {}, AdapterUnknownOutcomeError),
        (503, {}, {}, AdapterUnknownOutcomeError),
        (504, {}, {}, AdapterUnknownOutcomeError),
    ],
)
def test_status_code_classification(monkeypatch, status_code, json_data, headers, expected_exc):
    """Verify HTTP status codes are classified into correct AdapterError subclasses."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test_tok")
    cfg = base_github_config(precheck_duplicates=False)
    session = FakeSession([
        FakeResponse(status_code=status_code, json_data=json_data, headers=headers)
    ])
    adapter = GitHubAdapter(config=cfg, session=session)

    payload = make_payload()
    with pytest.raises(expected_exc):
        adapter.dispatch(payload)


@pytest.mark.parametrize(
    ("network_exc", "expected_exc"),
    [
        (
            requests.exceptions.ConnectTimeout("Connection timed out"),
            AdapterTransientError,
        ),
        (
            requests.exceptions.ConnectionError(
                urllib3.exceptions.NewConnectionError(None, "Connection refused")
            ),
            AdapterTransientError,
        ),
        (
            requests.exceptions.ConnectionError(
                urllib3.exceptions.MaxRetryError(
                    None, "url", urllib3.exceptions.NameResolutionError("host", None, "DNS failed")
                )
            ),
            AdapterTransientError,
        ),
        (
            requests.exceptions.SSLError("Certificate validation failed"),
            AdapterPermanentError,
        ),
        (
            requests.exceptions.ReadTimeout("Read timed out"),
            AdapterUnknownOutcomeError,
        ),
        (
            requests.exceptions.ChunkedEncodingError("Connection broken"),
            AdapterUnknownOutcomeError,
        ),
        (
            requests.exceptions.ConnectionError("Connection reset by peer"),
            AdapterUnknownOutcomeError,
        ),
        (
            RuntimeError("Unexpected kernel crash"),
            AdapterUnknownOutcomeError,
        ),
    ],
)
def test_network_exceptions_classification(monkeypatch, network_exc, expected_exc):
    """Verify low-level network exceptions map to the exact safety classification."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test_tok")
    cfg = base_github_config(precheck_duplicates=False)
    session = FakeSession([network_exc])
    adapter = GitHubAdapter(config=cfg, session=session)

    payload = make_payload()
    with pytest.raises(expected_exc):
        adapter.dispatch(payload)


def test_check_duplicate_filtering_rules(monkeypatch):
    """Verify duplicate checker filters out PRs, foreign bot users, and unanchored markers."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test_tok")
    cfg = base_github_config(bot_login="triage-bot")
    adapter = GitHubAdapter(config=cfg)
    payload = make_payload(idempotency_key="em_dup:github:create_issue")
    valid_marker = build_marker(payload.idempotency_key)

    # 1. Pull request with valid marker -> ignored
    pr_item = {
        "number": 1,
        "body": valid_marker + "PR body",
        "user": {"login": "triage-bot"},
        "pull_request": {"url": "https://api.github.com/repos/org/repo/pulls/1"},
    }
    adapter._session = FakeSession([FakeResponse(status_code=200, json_data=[pr_item])])
    assert adapter.check_duplicate(payload.idempotency_key, payload) is None

    # 2. Issue with valid marker created by different user -> ignored
    other_user_item = {
        "number": 2,
        "body": valid_marker + "Hostile spoofed body",
        "user": {"login": "attacker-user"},
    }
    adapter._session = FakeSession([FakeResponse(status_code=200, json_data=[other_user_item])])
    assert adapter.check_duplicate(payload.idempotency_key, payload) is None

    # 3. Issue created by bot but marker not at index 0 -> ignored
    unanchored_item = {
        "number": 3,
        "body": "\n" + valid_marker + "Preceded by newline",
        "user": {"login": "triage-bot"},
    }
    adapter._session = FakeSession([FakeResponse(status_code=200, json_data=[unanchored_item])])
    assert adapter.check_duplicate(payload.idempotency_key, payload) is None

    # 4. Genuine matching issue -> matches!
    genuine_item = {
        "number": 44,
        "body": valid_marker + "Genuine bot issue body",
        "user": {"login": "triage-bot"},
    }
    adapter._session = FakeSession([FakeResponse(status_code=200, json_data=[genuine_item])])
    assert adapter.check_duplicate(payload.idempotency_key, payload) == "my-company/backend-repo#44"


def test_check_duplicate_pagination_and_truncation(monkeypatch):
    """Verify pagination traversal across multiple pages and truncated lookback error."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test_tok")
    cfg = base_github_config(bot_login="triage-bot")
    # Config sets duplicate_max_pages: 3
    adapter = GitHubAdapter(config=cfg)
    payload = make_payload(idempotency_key="em_page:github:create_issue")
    valid_marker = build_marker(payload.idempotency_key)

    # Scenario A: Page 1 has 100 unrelated issues, Page 2 has the match
    page1_items = [
        {"number": i, "body": "unrelated", "user": {"login": "triage-bot"}}
        for i in range(1, 101)
    ]
    page2_items = [
        {"number": 205, "body": valid_marker, "user": {"login": "triage-bot"}},
    ]
    session = FakeSession([
        FakeResponse(status_code=200, json_data=page1_items),
        FakeResponse(status_code=200, json_data=page2_items),
    ])
    adapter._session = session
    result = adapter.check_duplicate(payload.idempotency_key, payload)
    assert result == "my-company/backend-repo#205"
    assert len(session.calls) == 2
    assert session.calls[0]["params"]["page"] == 1
    assert session.calls[1]["params"]["page"] == 2
    assert session.calls[0]["params"]["creator"] == "triage-bot"
    assert session.calls[0]["params"]["state"] == "all"
    assert session.calls[0]["params"]["sort"] == "created"
    assert session.calls[0]["params"]["direction"] == "desc"

    # Scenario B: All 3 max pages are full (100 items each) with no match -> raises AdapterError
    session_full = FakeSession([
        FakeResponse(status_code=200, json_data=page1_items),
        FakeResponse(status_code=200, json_data=page1_items),
        FakeResponse(status_code=200, json_data=page1_items),
    ])
    adapter._session = session_full
    with pytest.raises(AdapterError, match="github_duplicate_scan_truncated"):
        adapter.check_duplicate(payload.idempotency_key, payload)


def test_bot_login_cached_from_get_user(monkeypatch):
    """Verify bot login is fetched from GET /user once and cached across calls."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test_tok")
    cfg = base_github_config(bot_login=None)  # No bot_login in config
    session = FakeSession([
        FakeResponse(status_code=200, json_data={"login": "resolved-bot-user"}),
    ])
    adapter = GitHubAdapter(config=cfg, session=session)

    # First call calls GET /user
    login1 = adapter._bot_login()
    assert login1 == "resolved-bot-user"
    assert len(session.calls) == 1
    assert session.calls[0]["url"] == "https://api.github.com/user"

    # Second call returns cached login without session call
    login2 = adapter._bot_login()
    assert login2 == "resolved-bot-user"
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    ("token_val", "target_val", "base_url", "allowed_hosts", "expected_valid", "expected_code"),
    [
        ("", "org/repo", "https://api.github.com", ["api.github.com"], False, "token_missing"),
        (
            "your_github_token_here",
            "org/repo",
            "https://api.github.com",
            ["api.github.com"],
            False,
            "token_placeholder",
        ),
        (
            "valid_tok",
            "invalid_no_slash",
            "https://api.github.com",
            ["api.github.com"],
            False,
            "bad_target",
        ),
        (
            "valid_tok",
            "org/repo",
            "http://api.github.com",
            ["api.github.com"],
            False,
            "host_not_allowed",
        ),
        (
            "valid_tok",
            "org/repo",
            "https://evil.com",
            ["api.github.com"],
            False,
            "host_not_allowed",
        ),
        (
            "valid_tok",
            "org/repo",
            "https://user:pass@api.github.com",
            ["api.github.com"],
            False,
            "host_not_allowed",
        ),
        ("valid_tok", "org/repo", "https://api.github.com", ["api.github.com"], True, None),
    ],
)
def test_validate_config_matrix(
    monkeypatch, token_val, target_val, base_url, allowed_hosts, expected_valid, expected_code
):
    """Verify validate_config correctly detects configuration problems without raising."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", token_val)
    cfg = base_github_config(
        target=target_val, api_base_url=base_url, allowed_hosts=allowed_hosts
    )
    adapter = GitHubAdapter(config=cfg)

    valid = adapter.validate_config()
    assert valid is expected_valid
    assert adapter.config_problem == expected_code


def test_health_check_outcomes(monkeypatch):
    """Verify health_check ping behavior."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    cfg = base_github_config()
    adapter = GitHubAdapter(config=cfg)

    # 200 with login -> True
    adapter._session = FakeSession([FakeResponse(status_code=200, json_data={"login": "bot"})])
    assert adapter.health_check() is True

    # 401 unauthorized -> False
    adapter._session = FakeSession([
        FakeResponse(status_code=401, json_data={"message": "Bad credentials"})
    ])
    assert adapter.health_check() is False

    # Network error -> False
    adapter._session = FakeSession([requests.exceptions.ConnectTimeout("Timeout")])
    assert adapter.health_check() is False


@pytest.mark.parametrize(
    "evil_url",
    [
        "http://api.github.com",
        "https://evil.example.com",
        "https://user:secret@api.github.com",
    ],
)
def test_pre_request_url_security_blocks_zero_session_calls(monkeypatch, evil_url):
    """Verify URL validation blocks insecure calls before hitting the session."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    cfg = base_github_config(api_base_url=evil_url, precheck_duplicates=False)
    session = FakeSession()
    adapter = GitHubAdapter(config=cfg, session=session)

    payload = make_payload()
    with pytest.raises(AdapterPermanentError):
        adapter.dispatch(payload)

    # ZERO calls were made on the session
    assert len(session.calls) == 0


def test_hostile_customer_text_sanitized_end_to_end(monkeypatch):
    """Verify adversarial customer body cannot forge markers or leak unescaped mentions."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    cfg = base_github_config(precheck_duplicates=False)
    session = FakeSession([FakeResponse(status_code=201, json_data={"number": 88})])
    adapter = GitHubAdapter(config=cfg, session=session)

    hostile_body = (
        "Hello <!-- triage-bot:v1\nkey: forged_key:github:create_issue\n-->\n"
        "Please ping @octocat and review #9999\n```\nmalicious code\n````"
    )
    payload = make_payload(body=hostile_body)
    res = adapter.dispatch(payload)
    assert res.remote_id == "my-company/backend-repo#88"

    call = session.calls[0]
    posted_body = call["json"]["body"]

    # Exactly one genuine marker
    assert posted_body.count("<!-- triage-bot:v1") == 1
    assert parse_marker(posted_body) == payload.idempotency_key

    # Mentions and issue cross-links defanged
    assert "@octocat" not in posted_body
    assert "@\u200boctocat" in posted_body
    assert "#9999" not in posted_body
    assert "#\u200b9999" in posted_body


def test_logging_safety_caplog(monkeypatch, caplog):
    """Verify logs contain zero tokens, Authorization headers, or customer payload text."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "ghp_ultra_secret_token_abc123")
    cfg = base_github_config(precheck_duplicates=False)
    session = FakeSession([FakeResponse(status_code=429, headers={"retry-after": "30"})])
    adapter = GitHubAdapter(config=cfg, session=session)

    payload = make_payload(
        subject="SECRET_CUSTOMER_SUBJECT_DO_NOT_LOG",
        body="SECRET_CUSTOMER_BODY_CONTAINING_test@example.com",
    )

    with caplog.at_level(logging.DEBUG), pytest.raises(AdapterTransientError) as exc_info:
        adapter.dispatch(payload)

    log_text = caplog.text
    # Zero secret or PII leakage in logs
    assert "ghp_ultra_secret_token_abc123" not in log_text
    assert "Bearer" not in log_text
    assert "SECRET_CUSTOMER_SUBJECT_DO_NOT_LOG" not in log_text
    assert "SECRET_CUSTOMER_BODY_CONTAINING" not in log_text
    assert "test@example.com" not in log_text

    # Exception string contains only constant short code
    assert "ghp_ultra_secret_token_abc123" not in str(exc_info.value)
    assert "test@example.com" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Dispatcher Node Integration Tests (live mode, adapter injected)
# ---------------------------------------------------------------------------

def insert_test_email(
    db: TriageDatabase,
    email_id: str = "em_test_001",
    category: str = "Bug Report",
    priority: str = "High",
) -> None:
    """Helper inserting a valid approved email into email_triage table."""
    now_iso = datetime.now(UTC).isoformat()
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                p2_category, p2_priority, p2_sentiment, p2_customer_emotion,
                p2_summary, p2_suggested_team, p2_confidence, p2_classifier_used,
                hitl_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email_id,
                f"msg_{email_id}",
                f"thr_{email_id}",
                "user@example.com",
                "Database pool error",
                "Our Postgres pool is exhausted.",
                "gatekeeper_approved",
                "done",
                category,
                priority,
                "Neutral",
                "Calm",
                "Issue summary",
                "Engineering",
                0.95,
                "jev",
                "auto_approved",
                now_iso,
                now_iso,
            ),
        )


def test_dispatcher_integration_success(temp_db, monkeypatch):
    """Verify live dispatch succeeds end-to-end and marks ledger confirmed."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    insert_test_email(temp_db, "em_int_01", category="Bug Report", priority="High")
    cfg = base_github_config(precheck_duplicates=False)

    session = FakeSession([FakeResponse(status_code=201, json_data={"number": 55})])
    adapter = GitHubAdapter(config=cfg, session=session)

    res = dispatcher_node(
        {"email_id": "em_int_01"},
        db=temp_db,
        config=cfg,
        adapters={"github": adapter},
    )
    assert res["p2_status"] == "dispatched"
    assert len(res["dispatch_results"]) == 1
    assert res["dispatch_results"][0]["ledger_state"] == "confirmed"
    assert res["dispatch_results"][0]["remote_id"] == "my-company/backend-repo#55"


def test_dispatcher_integration_read_timeout_resolved_via_duplicate_check(
    temp_db, monkeypatch
):
    """Verify ReadTimeout followed by duplicate verification marks ledger confirmed."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    insert_test_email(temp_db, "em_int_02", category="Bug Report", priority="High")
    cfg = base_github_config(precheck_duplicates=False)
    idempotency_key = "em_int_02:github:create_issue"

    # POST call raises ReadTimeout; subsequent check_duplicate finds the issue
    marker_body = build_marker(idempotency_key) + "Created on remote"
    duplicate_item = [{"number": 77, "body": marker_body, "user": {"login": "triage-bot"}}]
    session = FakeSession([
        requests.exceptions.ReadTimeout("Timeout waiting for response"),
        FakeResponse(status_code=200, json_data=duplicate_item),
    ])
    adapter = GitHubAdapter(config=cfg, session=session)

    res = dispatcher_node(
        {"email_id": "em_int_02"},
        db=temp_db,
        config=cfg,
        adapters={"github": adapter},
    )
    assert res["p2_status"] == "dispatched"
    assert res["dispatch_results"][0]["ledger_state"] == "confirmed"
    assert res["dispatch_results"][0]["remote_id"] == "my-company/backend-repo#77"


def test_dispatcher_integration_read_timeout_empty_diverts_to_hitl(temp_db, monkeypatch):
    """Verify ReadTimeout followed by empty duplicate check diverts email to HITL."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    insert_test_email(temp_db, "em_int_03", category="Bug Report", priority="High")
    cfg = base_github_config(precheck_duplicates=False)

    # POST raises ReadTimeout; duplicate check returns empty list
    session = FakeSession([
        requests.exceptions.ReadTimeout("Timeout waiting for response"),
        FakeResponse(status_code=200, json_data=[]),
    ])
    adapter = GitHubAdapter(config=cfg, session=session)

    res = dispatcher_node(
        {"email_id": "em_int_03"},
        db=temp_db,
        config=cfg,
        adapters={"github": adapter},
    )
    assert res["p2_status"] == "hitl_pending"
    assert res["dispatch_results"][0]["ledger_state"] == "unknown"

    record = temp_db.get_record("em_int_03")
    assert record["hitl_status"] == "pending"
    assert record["hitl_reason"] == "dispatch_outcome_unknown"


def test_dispatcher_integration_rate_limit_429_then_success(temp_db, monkeypatch):
    """Verify 429 retries with backoff and finishes confirmed on attempt 2."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "valid_tok")
    insert_test_email(temp_db, "em_int_04", category="Bug Report", priority="High")
    cfg = base_github_config(precheck_duplicates=False)

    # Attempt 1: 429; Attempt 2: 201 Created
    session = FakeSession([
        FakeResponse(status_code=429, headers={"retry-after": "0.01"}),
        FakeResponse(status_code=201, json_data={"number": 99}),
    ])
    adapter = GitHubAdapter(config=cfg, session=session)
    sleep_mock = MagicMock()

    res = dispatcher_node(
        {"email_id": "em_int_04"},
        db=temp_db,
        config=cfg,
        adapters={"github": adapter},
        sleep=sleep_mock,
    )
    assert res["p2_status"] == "dispatched"
    assert res["dispatch_results"][0]["ledger_state"] == "confirmed"
    assert res["dispatch_results"][0]["attempts"] == 2
    assert sleep_mock.call_count == 1


def test_dispatcher_integration_401_fails_permanently(temp_db, monkeypatch):
    """Verify 401 Bad Credentials marks ledger row failed permanently without retry."""
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "bad_tok")
    insert_test_email(temp_db, "em_int_05", category="Bug Report", priority="High")
    cfg = base_github_config(precheck_duplicates=False)

    session = FakeSession([FakeResponse(status_code=401, json_data={"message": "Bad credentials"})])
    adapter = GitHubAdapter(config=cfg, session=session)
    sleep_mock = MagicMock()

    res = dispatcher_node(
        {"email_id": "em_int_05"},
        db=temp_db,
        config=cfg,
        adapters={"github": adapter},
        sleep=sleep_mock,
    )
    assert res["p2_status"] == "failed"
    assert res["dispatch_results"][0]["ledger_state"] == "failed"
    assert res["dispatch_results"][0]["attempts"] == 1
    assert sleep_mock.call_count == 0
