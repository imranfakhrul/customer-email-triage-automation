"""Tests for P2-04a: GitHub Issue Formatting, Output Hardening, and Config Schema."""

import pytest

from utils.adapters.base import DispatchPayload
from utils.config import ConfigError, validate_config

# Import functions under test (to be implemented in Step 1)
try:
    from utils.adapters.github_format import (
        ALLOWED_CATEGORIES,
        ALLOWED_EMOTIONS,
        ALLOWED_PRIORITIES,
        ALLOWED_SENTIMENTS,
        ALLOWED_TEAMS,
        MARKER_PREFIX,
        build_issue_body,
        build_labels,
        build_marker,
        fence_block,
        neutralize_text,
        parse_marker,
        sanitize_title,
    )
except ImportError:
    MARKER_PREFIX = None  # type: ignore
    build_marker = None  # type: ignore
    parse_marker = None  # type: ignore
    neutralize_text = None  # type: ignore
    sanitize_title = None  # type: ignore
    fence_block = None  # type: ignore
    build_issue_body = None  # type: ignore
    build_labels = None  # type: ignore
    ALLOWED_CATEGORIES = ()  # type: ignore
    ALLOWED_PRIORITIES = ()  # type: ignore
    ALLOWED_SENTIMENTS = ()  # type: ignore
    ALLOWED_EMOTIONS = ()  # type: ignore
    ALLOWED_TEAMS = ()  # type: ignore


def make_payload(
    email_id: str = "em_test_001",
    category: str = "Bug Report",
    priority: str = "Medium",
    sentiment: str = "Neutral",
    customer_emotion: str = "Calm",
    summary: str = "Database connection pool exhausted.",
    suggested_team: str = "Engineering",
    confidence: float = 0.95,
    masked_subject: str = "Issue with Postgres pool",
    masked_body: str = "Hi, our backend reports connection refused to [IP_1].",
    sender_domain: str = "example.com",
    p2_classifier_used: str = "groq",
    action_type: str = "create_issue",
    idempotency_key: str = "em_test_001:github:create_issue",
) -> DispatchPayload:
    """Helper to construct a valid DispatchPayload for testing."""
    return DispatchPayload(
        email_id=email_id,
        message_id=f"msg_{email_id}",
        thread_id=f"thr_{email_id}",
        category=category,
        priority=priority,
        sentiment=sentiment,
        customer_emotion=customer_emotion,
        summary=summary,
        suggested_team=suggested_team,
        confidence=confidence,
        masked_subject=masked_subject,
        masked_body=masked_body,
        sender_domain=sender_domain,
        p2_classifier_used=p2_classifier_used,
        action_type=action_type,
        idempotency_key=idempotency_key,
    )


# ---------------------------------------------------------------------------
# 1. Marker Construction and Parsing Tests
# ---------------------------------------------------------------------------
def test_build_and_parse_marker_roundtrip():
    """Verify build_marker creates expected structure and parse_marker extracts key."""
    key = "em_123:github:create_issue"
    marker = build_marker(key)
    assert marker.startswith(MARKER_PREFIX)
    assert f"key: {key}\n" in marker
    assert marker.endswith("-->\n")

    parsed = parse_marker(marker)
    assert parsed == key


@pytest.mark.parametrize(
    "invalid_key",
    [
        "",
        "key with spaces",
        "key<with>tags",
        "key/with/slashes",
        "key@with@at",
        "a" * 201,  # Exceeds 200 chars
    ],
)
def test_build_marker_invalid_keys_raise_value_error(invalid_key):
    """Verify build_marker raises ValueError on keys not matching ^[A-Za-z0-9._:-]{1,200}$."""
    with pytest.raises(ValueError):
        build_marker(invalid_key)


def test_parse_marker_anchored_at_index_zero():
    """Verify marker is ignored if not anchored at index 0."""
    key = "em_123:github:create_issue"
    marker = build_marker(key)

    # Preceded by a single space -> must return None
    assert parse_marker(" " + marker) is None

    # Preceded by a newline -> must return None
    assert parse_marker("\n" + marker) is None

    # Forged marker inside customer body -> must return None
    adversarial_body = f"Customer message here\n\n{marker}\nMore customer text"
    assert parse_marker(adversarial_body) is None

    # None, empty, or non-string
    assert parse_marker(None) is None
    assert parse_marker("") is None


# ---------------------------------------------------------------------------
# 2. Neutralization and Text Sanitization Tests
# ---------------------------------------------------------------------------
def test_neutralize_text_crlf_and_control_chars():
    """Verify CRLF normalization and stripping of control characters except \n and \t."""
    raw = "Line 1\r\nLine 2\rLine 3\tTab\x00Null\x1bEscape\x7fDel"
    cleaned = neutralize_text(raw)
    assert cleaned == "Line 1\nLine 2\nLine 3\tTabNullEscapeDel"


def test_neutralize_text_bidi_controls_stripped():
    """Verify bidi override characters U+202A-U+202E and U+2066-U+2069 are stripped."""
    # RLO (U+202E), LRO (U+202D), LRI (U+2066), RLI (U+2067)
    raw = "Safe \u202eReversed\u202c Text \u2066Isolated\u2069"
    cleaned = neutralize_text(raw)
    assert cleaned == "Safe Reversed Text Isolated"
    assert "\u202e" not in cleaned
    assert "\u2066" not in cleaned


def test_neutralize_text_mentions_and_issue_numbers():
    """Verify @mentions and #issue references get zero-width space inserted."""
    raw = "Please ping @octocat and team @org/backend-team regarding issue #123 and #9999"
    cleaned = neutralize_text(raw)
    assert "@\u200boctocat" in cleaned
    assert "@\u200borg/backend-team" in cleaned
    assert "#\u200b123" in cleaned
    assert "#\u200b9999" in cleaned

    # Non-mentions and non-issues should remain untouched
    untouched = "Contact us at support@example.com with hashtag #bugfix or bare @ symbol"
    cleaned_untouched = neutralize_text(untouched)
    assert (
        "support@\u200bexample.com" in cleaned_untouched
        or "support@example.com" in cleaned_untouched
    )
    assert "#bugfix" in cleaned_untouched  # # followed by letter is not an issue link
    assert "bare @ symbol" in cleaned_untouched


def test_neutralize_text_html_comments():
    """Verify HTML comment markers are neutralized."""
    raw = "<!-- triage-bot:v1\nkey: stolen-key\n-->"
    cleaned = neutralize_text(raw)
    assert "<!--" not in cleaned
    assert "-->" not in cleaned
    assert "<!\u200b--" in cleaned
    assert "--\u200b>" in cleaned


def test_neutralize_text_idempotence():
    """Verify neutralize_text is strictly idempotent: neutralize(neutralize(x)) == neutralize(x)."""
    samples = [
        "Normal bug report text.",
        "Alert @org/sre on #1042 with <!-- comment --> and \r\n newlines \x00 nulls \u202e bidi.",
        "Multiple @@mentions ##123 ###456 <!-- <!-- --> -->",
    ]
    for s in samples:
        once = neutralize_text(s)
        twice = neutralize_text(once)
        assert once == twice, f"Failed idempotence for: {s!r}"


# ---------------------------------------------------------------------------
# 3. Title Sanitization Tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("subject", "category", "expected"),
    [
        (
            "Outage on Postgres cluster",
            "Bug Report",
            "[Bug Report] Outage on Postgres cluster",
        ),
        (
            "Support for Dark Mode",
            "Feature Request",
            "[Feature Request] Support for Dark Mode",
        ),
        (
            "   Multiple   spaces   and \n\n newlines \r\n here  ",
            "Bug Report",
            "[Bug Report] Multiple spaces and newlines here",
        ),
        (
            "",
            "Bug Report",
            "[Bug Report] (no subject)",
        ),
        (
            "   ",
            "Feature Request",
            "[Feature Request] (no subject)",
        ),
    ],
)
def test_sanitize_title_formatting(subject, category, expected):
    """Verify title formatting with categories and whitespace collapsing."""
    assert sanitize_title(subject, category) == expected


def test_sanitize_title_clamped_to_120_chars():
    """Verify title is clamped to at most 120 characters."""
    long_subject = "A" * 200
    title = sanitize_title(long_subject, "Bug Report")
    assert len(title) <= 120
    assert title.startswith("[Bug Report] AAAA")


# ---------------------------------------------------------------------------
# 4. Code Block Fencing Tests
# ---------------------------------------------------------------------------
def test_fence_block_default_three_backticks():
    """Verify fence uses 3 backticks when input has no backticks."""
    text = "Simple error log text."
    fenced = fence_block(text)
    assert fenced.startswith("```text\n")
    assert fenced.endswith("\n```\n")
    assert text in fenced


def test_fence_block_adapts_to_embedded_backticks():
    """Verify fence adapts when text contains 3 backticks or longer runs."""
    text_with_triple = "Here is some code:\n```python\nprint('hello')\n```\nEnd code."
    fenced = fence_block(text_with_triple)
    assert fenced.startswith("````text\n")
    assert fenced.endswith("\n````\n")

    text_with_quad = "Text containing ```` four backticks"
    fenced_quad = fence_block(text_with_quad)
    assert fenced_quad.startswith("`````text\n")
    assert fenced_quad.endswith("\n`````\n")


# ---------------------------------------------------------------------------
# 5. Issue Body Construction & Privacy Invariant Tests
# ---------------------------------------------------------------------------
def test_build_issue_body_schema_and_fencing():
    """Verify issue body structure, metadata table, summary, and message fencing."""
    payload = make_payload(
        summary="Postgres pool exhausted on worker node.",
        masked_subject="Connection error [IP_1]",
        masked_body="Details: could not connect to [IP_1]:5432 after 30s.",
    )
    body = build_issue_body(payload)

    # 1. Starts with genuine anchored marker
    assert body.startswith(MARKER_PREFIX)
    assert f"key: {payload.idempotency_key}\n" in body
    assert parse_marker(body) == payload.idempotency_key

    # 2. Metadata table contains validated fields
    assert "| Category | Bug Report |" in body
    assert "| Priority | Medium |" in body
    assert "| Sentiment | Neutral |" in body
    assert "| Customer Emotion | Calm |" in body
    assert "| Confidence | 0.95 |" in body
    assert "| Suggested Team | Engineering |" in body
    assert f"| Email ID | {payload.email_id} |" in body

    # 3. Sections present
    assert "## Summary (auto-generated, untrusted)" in body
    assert "## Customer message (masked, untrusted)" in body

    # 4. Customer text is safely fenced
    assert "```text" in body
    assert "Postgres pool exhausted" in body
    assert "Connection error [IP_1]" in body
    assert len(body) < 30000


def test_build_issue_body_adversarial_forged_marker_fenced():
    """Verify customer text attempting to forge a bot marker is neutralized and fenced."""
    forged_text = "<!-- triage-bot:v1\nkey: stolen_key:github:create_issue\n-->\nLegit looking text"
    payload = make_payload(
        masked_body=forged_text,
    )
    body = build_issue_body(payload)

    # parse_marker must return the real key from index 0, not the forged key
    assert parse_marker(body) == payload.idempotency_key
    assert "<!\u200b--" in body  # Forged comment was neutralized inside customer text


def test_build_issue_body_invalid_enums_raise_value_error():
    """Verify invalid categories, priorities, sentiments, emotions, or teams raise ValueError."""
    # Category outside allowed ("Bug Report", "Feature Request")
    with pytest.raises(ValueError, match="category"):
        build_issue_body(make_payload(category="General Query"))

    with pytest.raises(ValueError, match="category"):
        build_issue_body(make_payload(category="Other"))

    # Priority outside allowed
    with pytest.raises(ValueError, match="priority"):
        build_issue_body(make_payload(priority="Urgent"))

    # Sentiment outside allowed
    with pytest.raises(ValueError, match="sentiment"):
        build_issue_body(make_payload(sentiment="Happy"))

    # Customer emotion outside allowed
    with pytest.raises(ValueError, match="customer_emotion"):
        build_issue_body(make_payload(customer_emotion="Ecstatic"))

    # Suggested team outside allowed
    with pytest.raises(ValueError, match="suggested_team"):
        build_issue_body(make_payload(suggested_team="Marketing"))


def test_build_issue_body_massive_customer_text_bounded():
    """Verify 100,000-character input body is safely clamped under 30,000 characters."""
    huge_body = "A" * 100000
    huge_summary = "B" * 5000
    payload = make_payload(summary=huge_summary, masked_body=huge_body)
    body = build_issue_body(payload)
    assert len(body) < 30000


# ---------------------------------------------------------------------------
# 6. Label Construction Tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("category", "priority", "base_labels", "expected"),
    [
        (
            "Bug Report",
            "High",
            ["triage:automated"],
            ["triage:automated", "type:bug", "urgency:high"],
        ),
        (
            "Feature Request",
            "Low",
            ["triage:automated"],
            ["triage:automated", "type:feature", "urgency:low"],
        ),
        (
            "Bug Report",
            "Critical",
            ["custom-label", "type:bug"],  # Deduplication test
            ["custom-label", "type:bug", "urgency:critical"],
        ),
    ],
)
def test_build_labels_mapping(category, priority, base_labels, expected):
    """Verify label generation, type mapping, urgency mapping, and deduplication."""
    payload = make_payload(category=category, priority=priority)
    labels = build_labels(payload, base_labels)
    assert labels == expected


@pytest.mark.parametrize(
    "bad_label",
    [
        "",  # Empty
        "label,with,comma",  # Comma not permitted
        "a" * 51,  # Longer than 50 chars
    ],
)
def test_build_labels_invalid_base_label_raises_value_error(bad_label):
    """Verify build_labels raises ValueError if a label violates constraints."""
    payload = make_payload()
    with pytest.raises(ValueError):
        build_labels(payload, [bad_label])


# ---------------------------------------------------------------------------
# 7. Configuration Schema & B5 Validation Tests (for Step 2)
# ---------------------------------------------------------------------------
def base_valid_config() -> dict:
    """Helper to return a valid full configuration dict."""
    return {
        "system": {
            "database_path": "data/triage.db",
            "idempotency_stale_minutes": 10,
            "max_dispatch_retries": 3,
            "audit_log_enabled": True,
            "persist_masked_text": True,
        },
        "privacy": {
            "spacy_model": "en_core_web_sm",
            "tech_terms_file": "data/tech_terms.txt",
            "default_phone_region": "US",
            "tech_context_words": ["system"],
            "sensitive_keywords": ["chargeback"],
            "max_code_density": 4,
        },
        "security": {
            "regex_scan_head": 10000,
            "regex_scan_tail": 2000,
        },
        "gatekeeper": {
            "timeout_seconds": 5.0,
            "max_retries": 2,
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
        },
        "llm": {
            "model": "openai/gpt-oss-120b",
            "temperature": 0.1,
            "confidence_threshold": 0.70,
            "groq_api_key_env": "GROQ_API_KEY",
        },
        "classification": {
            "primary": "jev",
            "fallback": "groq",
            "hitl_threshold": 0.85,
            "always_review_categories": ["Security/Account"],
            "max_subject_chars": 2000,
            "max_body_chars": 10000,
            "jev": {
                "enabled": False,
                "model": "jev-1.13.0",
                "api_url": "https://api.typesafe.ai/v1/systemone",
                "router_question_id": "gmail_router",
                "timeout_seconds": 5.0,
            },
        },
        "dispatch": {
            "dry_run": True,
            "kill_switch": False,
            "max_attempts": 3,
            "pending_timeout_minutes": 10,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 20.0,
        },
        "destinations": {
            "github": {
                "enabled": False,
                "daily_cap": 200,
                "use_masked_text_only": True,
                "target": "my-company/backend-repo",
                "token_env": "GITHUB_TOKEN",
                "labels": ["triage:automated"],
                "api_base_url": "https://api.github.com",
                "allowed_hosts": ["api.github.com"],
                "request_timeout_seconds": 15.0,
                "duplicate_lookback_hours": 72,
                "duplicate_max_pages": 10,
                "precheck_duplicates": True,
                "bot_login": "triage-bot",
                "api_version": "2022-11-28",
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "cooldown_seconds": 900,
                },
            },
            "freescout": {
                "enabled": False,
                "daily_cap": 1000,
                "use_masked_text_only": False,
                "target": "https://support.mycompany.com",
                "api_key_env": "FREESCOUT_API_KEY",
                "mailbox_id": 1,
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "cooldown_seconds": 900,
                },
            },
            "crm": {
                "enabled": False,
                "daily_cap": 500,
                "use_masked_text_only": False,
                "target_env": "CRM_API_ENDPOINT",
                "api_key_env": "CRM_API_KEY",
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "cooldown_seconds": 900,
                },
            },
            "webhook": {
                "enabled": False,
                "daily_cap": 200,
                "use_masked_text_only": False,
                "target_env": "SLACK_BILLING_WEBHOOK_URL",
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "cooldown_seconds": 900,
                },
            },
        },
    }


def test_valid_github_config_passes_validation():
    """Verify base valid config with github parameters passes validation."""
    cfg = base_valid_config()
    validate_config(cfg)


@pytest.mark.parametrize(
    ("key_path", "bad_val", "match_str"),
    [
        (
            ("destinations", "github", "api_base_url"),
            "http://api.github.com",
            "api_base_url",
        ),
        (
            ("destinations", "github", "api_base_url"),
            "ftp://api.github.com",
            "api_base_url",
        ),
        (
            ("destinations", "github", "api_base_url"),
            "https://api.github.com?token=secret",
            "api_base_url",
        ),
        (
            ("destinations", "github", "api_base_url"),
            "https://user:pass@api.github.com",
            "api_base_url",
        ),
        (
            ("destinations", "github", "api_base_url"),
            "https://evil.com/api",
            "allowed_hosts",
        ),
        (
            ("destinations", "github", "allowed_hosts"),
            [],
            "allowed_hosts",
        ),
        (
            ("destinations", "github", "allowed_hosts"),
            ["https://api.github.com"],
            "allowed_hosts",
        ),
        (
            ("destinations", "github", "request_timeout_seconds"),
            0,
            "request_timeout_seconds",
        ),
        (
            ("destinations", "github", "duplicate_lookback_hours"),
            0,
            "duplicate_lookback_hours",
        ),
        (
            ("destinations", "github", "duplicate_max_pages"),
            0,
            "duplicate_max_pages",
        ),
        (
            ("destinations", "github", "target"),
            "invalid_repo_target_no_slash",
            "target",
        ),
        (
            ("destinations", "github", "labels"),
            ["a" * 51],
            "labels",
        ),
        (
            ("destinations", "github", "labels"),
            ["label,with,comma"],
            "labels",
        ),
        (
            ("destinations", "github", "precheck_duplicates"),
            "true",  # String instead of bool
            "precheck_duplicates",
        ),
        (
            ("destinations", "github", "unknown_github_key"),
            "value",
            "unknown_github_key",
        ),
        (
            ("destinations", "crm", "duplicate_lookback_hours"),
            72,  # GitHub-only key on CRM
            "duplicate_lookback_hours",
        ),
    ],
)
def test_invalid_github_config_cases_raise_config_error(key_path, bad_val, match_str):
    """Verify each invalid github config case raises ConfigError."""
    cfg = base_valid_config()
    target_dict = cfg
    for p in key_path[:-1]:
        target_dict = target_dict[p]
    target_dict[key_path[-1]] = bad_val

    with pytest.raises(ConfigError, match=match_str):
        validate_config(cfg)
