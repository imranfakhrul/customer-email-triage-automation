"""Tests for FreeScout payload formatting, HTML sanitization, and correlation markers."""


from utils.adapters.freescout_format import (
    MARKER_PREFIX,
    build_conversation_payload,
    build_marker,
    build_thread_reply_payload,
    parse_marker,
    sanitize_html_body,
    sanitize_subject,
)


def test_build_and_parse_marker():
    """Verify system-owned correlation marker is generated and extracted when anchored."""
    key = "em_test_100:freescout:create_ticket"
    email_id = "em_test_100"
    thread_id = "th_test_100"

    marker = build_marker(key, email_id, thread_id)
    assert marker.startswith(MARKER_PREFIX)
    assert f"key: {key}" in marker
    assert f"email_id: {email_id}" in marker
    assert f"thread_id: {thread_id}" in marker

    parsed = parse_marker(marker + "<p>Some text</p>")
    assert parsed is not None
    assert parsed["key"] == key
    assert parsed["email_id"] == email_id
    assert parsed["thread_id"] == thread_id


def test_parse_marker_ignores_unanchored_or_injected_marker():
    """Security Defense: A marker appearing after any character or inside customer text

    is strictly ignored.
    """
    key = "spoofed_key:freescout:create_ticket"
    marker = build_marker(key, "spoofed_em", "spoofed_th")

    # Preceded by newline or space
    assert parse_marker("\n" + marker) is None
    assert parse_marker(" " + marker) is None
    assert parse_marker("Hello world " + marker) is None
    assert parse_marker("<p>" + marker + "</p>") is None


def test_sanitize_html_body_defangs_xss_and_preserves_newlines():
    """Security Defense: HTML entities are escaped to prevent Stored XSS in agent helpdesk."""
    dirty = "<script>alert('xss');</script><iframe src='javascript:void(0)'>\nLine 2\n& special"
    clean = sanitize_html_body(dirty)

    assert "<script>" not in clean
    assert "<iframe>" not in clean
    assert "&lt;script&gt;" in clean
    assert "&lt;iframe" in clean
    assert "&#x27;xss&#x27;" in clean or "&#39;xss&#39;" in clean or "&apos;xss&apos;" in clean
    assert "&amp; special" in clean
    assert "<br>\n" in clean


def test_sanitize_html_body_strips_bidi_and_control_chars():
    """Defense: Strips unicode bidirectional overrides and ascii control characters."""
    sneaky = "Hello\u202E\u2066World\x00\x08!"
    clean = sanitize_html_body(sneaky)
    assert clean == "<p>HelloWorld!</p>"


def test_sanitize_subject_truncates_and_strips_newlines():
    """Subject sanitization truncates to 200 chars and replaces newlines."""
    long_subj = "Subject with \n newline " + ("A" * 300)
    clean = sanitize_subject(long_subj)
    assert "\n" not in clean
    assert len(clean) <= 200
    assert clean.startswith("Subject with newline A")


def test_build_conversation_payload_conforms_to_freescout_schema():
    """Verify generated JSON payload conforms to FreeScout REST API v1 specification."""
    record = {
        "email_id": "em_conv_01",
        "message_id": "<msg01@acme.com>",
        "thread_id": "th_conv_01",
        "sender_email": "jane.doe@acme.com",
        "sender_domain": "acme.com",
        "masked_subject": "Need help with billing for [PERSON_1_1234]",
        "masked_body": "Please contact [EMAIL_1_1234] regarding invoice.",
        "token_map": {
            "[PERSON_1_1234]": "Jane Doe",
            "[EMAIL_1_1234]": "jane.doe@acme.com",
        },
    }

    idempotency_key = "em_conv_01:freescout:create_ticket"
    payload = build_conversation_payload(
        record,
        mailbox_id=1,
        idempotency_key=idempotency_key,
        unmask_pii=True,
    )

    assert payload["mailboxId"] == 1
    assert payload["type"] == "email"
    assert payload["status"] == "active"
    assert payload["subject"] == "Need help with billing for Jane Doe"
    assert payload["customer"]["email"] == "jane.doe@acme.com"

    threads = payload["threads"]
    assert len(threads) == 1
    first_thread = threads[0]
    assert first_thread["type"] == "customer"
    assert first_thread["customer"]["email"] == "jane.doe@acme.com"

    # Anchored marker present in thread text
    text = first_thread["text"]
    assert text.startswith(MARKER_PREFIX)
    assert f"key: {idempotency_key}" in text
    assert "Please contact jane.doe@acme.com regarding invoice." in text


def test_build_conversation_payload_fallback_when_unmask_pii_false():
    """When unmask_pii=False, uses synthetic sender address so real PII is not sent."""
    record = {
        "email_id": "em_conv_02",
        "message_id": "<msg02@acme.com>",
        "thread_id": "th_conv_02",
        "sender_email": "secret@acme.com",
        "sender_domain": "acme.com",
        "masked_subject": "Secret subject",
        "masked_body": "Secret body",
    }

    idempotency_key = "em_conv_02:freescout:create_ticket"
    payload = build_conversation_payload(
        record,
        mailbox_id=1,
        idempotency_key=idempotency_key,
        unmask_pii=False,
    )

    assert payload["customer"]["email"] == "triage+em_conv_02@invalid"
    assert payload["threads"][0]["customer"]["email"] == "triage+em_conv_02@invalid"


def test_build_thread_reply_payload():
    """Verify building an append thread reply payload."""
    record = {
        "email_id": "em_reply_01",
        "message_id": "<reply01@acme.com>",
        "thread_id": "th_conv_01",
        "sender_email": "jane.doe@acme.com",
        "sender_domain": "acme.com",
        "masked_subject": "Re: Help",
        "masked_body": "Here is additional context.",
        "token_map": {},
    }

    idempotency_key = "em_reply_01:freescout:create_ticket"
    thread_payload = build_thread_reply_payload(
        record,
        idempotency_key=idempotency_key,
        unmask_pii=True,
    )

    assert thread_payload["type"] == "customer"
    assert thread_payload["customer"]["email"] == "jane.doe@acme.com"
    assert thread_payload["status"] == "active"
    assert thread_payload["text"].startswith(MARKER_PREFIX)
    assert "Here is additional context." in thread_payload["text"]
