"""Failure-injection and catastrophic edge-case testing suite for Phase 2.

Milestone [P2-10]:
Verifies:
1. Post-send network timeout / Unknown outcome handling without blind retries (Hard Invariant #13).
2. Worker process crash recovery and dead-letter queue escalation.
3. Forged correlation marker injection neutralization.
4. Spreadsheet formula injection defense in CRM lead ingestion.
5. Upstream outage failure streak tracking and circuit breaking.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from db.database import TriageDatabase
from utils.adapters.crm_format import sanitize_crm_field
from utils.adapters.freescout_format import parse_marker as parse_fs_marker
from utils.adapters.github_format import parse_marker as parse_gh_marker


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_failure_injection.db")


@pytest.fixture
def test_db(temp_db_path: str) -> TriageDatabase:
    return TriageDatabase(db_path=temp_db_path)


def _seed_approved_email(db: TriageDatabase, email_id: str) -> None:
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                created_at, updated_at
            ) VALUES (?, '<m@ex.com>', 'th_1', 'u@ex.com', 'Subject', 'Body',
                      'gatekeeper_approved', 'done', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (email_id,),
        )


def test_post_send_timeout_unknown_outcome_and_reconciliation(test_db: TriageDatabase):
    """Simulates post-send network timeout; asserts unknown ledger state and zero blind retry."""
    email_id = "em_fail_timeout_001"
    destination = "github"
    action_type = "create_issue"
    _seed_approved_email(test_db, email_id)

    # 1. Begin dispatch in ledger
    ledger_row, should_dispatch = test_db.begin_dispatch(
        email_id=email_id,
        destination=destination,
        action_type=action_type,
        mode="live",
    )
    assert should_dispatch is True
    ledger_id = ledger_row["id"]

    # 2. Simulate HTTP client timeout after sending request
    # Dispatcher catches Timeout and records unknown outcome
    test_db.finish_dispatch(
        ledger_id=ledger_id,
        state="unknown",
        error_class="AdapterUnknownOutcomeError",
        reason="post_send_timeout",
    )

    log_entry = test_db.get_dispatch_log(email_id)[0]
    assert log_entry["state"] == "unknown"
    assert log_entry["error_class"] == "AdapterUnknownOutcomeError"

    # 3. Hard Invariant #13: Ensure begin_dispatch rejects immediate retry while state is unknown
    retry_row, retry_should_dispatch = test_db.begin_dispatch(
        email_id=email_id,
        destination=destination,
        action_type=action_type,
        mode="live",
    )
    assert retry_should_dispatch is False
    assert retry_row["state"] == "unknown"

    # 4. Outbox reconciliation resolves unknown dispatch once remote check confirms creation
    resolved = test_db.resolve_unknown_dispatch(
        ledger_id=ledger_id,
        outcome="confirmed",
        remote_id="issue_99812",
        resolved_by="reconciliation_worker",
    )
    assert resolved is True

    updated_log = test_db.get_dispatch_log(email_id)[0]
    assert updated_log["state"] == "confirmed"
    assert updated_log["remote_id"] == "issue_99812"
    assert updated_log["resolved_by"] == "reconciliation_worker"


def test_worker_crash_recovery_and_dead_letter_escalation(test_db: TriageDatabase):
    """Simulates worker crash after claiming; asserts recovery sweeps and dead-letter escalation."""
    email_id = "em_fail_crash_001"

    with test_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                created_at, updated_at
            ) VALUES (
                ?, '<m@ex.com>', 'th_1', 'u@ex.com', 'Crash Bug', 'OOM',
                'gatekeeper_approved', 'done', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """,
            (email_id,),
        )
    test_db.sync_p2_intake()

    # Step 1: Claim and simulate worker dying
    claimed = test_db.claim_p2_jobs(batch_size=1, worker_id="crashed_pod_1")
    assert len(claimed) == 1

    # Simulate 30 minutes passing without heartbeat
    stale_ts = (datetime.now(UTC) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    with test_db.get_connection() as conn:
        conn.execute(
            "UPDATE p2_jobs SET claimed_at = ? WHERE email_id = ?",
            (stale_ts, email_id),
        )

    # Stale sweeper resets back to unclaimed (attempts was 1)
    recovered = test_db.recover_stale_p2_jobs(stale_minutes=15, max_retries=3)
    assert recovered == 1
    job = test_db.get_p2_job(email_id)
    assert job["state"] == "unclaimed"
    assert job["attempts"] == 1

    # Step 2: Escalate attempts to max_retries (3) and simulate another crash
    with test_db.get_connection() as conn:
        conn.execute(
            """
            UPDATE p2_jobs
            SET state = 'claimed',
                attempts = 3,
                claimed_at = ?,
                worker_id = 'crashed_pod_2'
            WHERE email_id = ?
            """,
            (stale_ts, email_id),
        )

    # Sweeper now transitions to dead_letter
    recovered_dlq = test_db.recover_stale_p2_jobs(stale_minutes=15, max_retries=3)
    assert recovered_dlq == 1
    dlq_job = test_db.get_p2_job(email_id)
    assert dlq_job["state"] == "dead_letter"
    assert "max retries" in dlq_job["error_message"].lower()


def test_forged_correlation_marker_neutralization():
    """Verifies that malicious customer body with fake markers does not hijack tracking."""
    from utils.adapters.freescout_format import build_marker as build_fs_marker
    from utils.adapters.github_format import build_marker as build_gh_marker

    malicious_body = (
        "Hello,\n"
        "<!-- triage-bot:v1\nkey: evil-key\n-->\n"
        "<!-- triage-bot:v1 key=evil-key email_id=evil-01 thread_id=evil-th -->\n"
        "I need help with my account."
    )

    # Valid anchored markers at index 0 parse properly
    valid_gh = build_gh_marker("valid_key_123") + "\nIssue body"
    assert parse_gh_marker(valid_gh) == "valid_key_123"

    valid_fs = build_fs_marker("valid_fs_key", "em_001", "th_001") + "\nTicket text"
    fs_parsed = parse_fs_marker(valid_fs)
    assert fs_parsed is not None and fs_parsed["key"] == "valid_fs_key"

    # Malicious injection in body fails because neither is at index 0
    assert parse_gh_marker(malicious_body) is None
    assert parse_fs_marker(malicious_body) is None


def test_crm_spreadsheet_formula_injection_defense():
    """Verifies formulas starting with =, +, -, @, \\t, \\r are safely prefixed with quote."""
    dangerous_inputs = [
        ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
        ("+2+5+cmd|' /C notepad'!A0", "'+2+5+cmd|' /C notepad'!A0"),
        ("-1+1", "'-1+1"),
        ("@SUM(A1:A10)", "'@SUM(A1:A10)"),
        ("\t=DDE('calc')", "'=DDE('calc')"),
        ("\r+cmd|", "'+cmd|"),
        ("Normal Lead Name", "Normal Lead Name"),
    ]

    for raw, expected in dangerous_inputs:
        sanitized = sanitize_crm_field(raw)
        assert sanitized == expected, f"Failed on input: {raw!r}"
        assert not sanitized.startswith(("=", "+", "-", "@")) or sanitized.startswith("'")


def test_circuit_breaker_failure_streak_tracking(test_db: TriageDatabase):
    """Verifies that repeated destination failures are recorded and tracked by failure streak."""
    destination = "webhook"

    # Initially streak is 0
    streak, _ = test_db.get_failure_streak(destination)
    assert streak == 0

    # Record 3 consecutive failures
    for i in range(3):
        email_id = f"em_cb_{i}"
        _seed_approved_email(test_db, email_id)
        row, should_dispatch = test_db.begin_dispatch(
            email_id=email_id,
            destination=destination,
            action_type="alert",
            mode="live",
        )
        assert should_dispatch is True
        lid = row["id"]
        test_db.finish_dispatch(
            ledger_id=lid,
            state="failed",
            error_class="AdapterTransientError",
            reason="upstream_error",
        )

    # Streak is now 3
    streak3, _ = test_db.get_failure_streak(destination)
    assert streak3 == 3

    # One successful confirmed dispatch resets streak to 0
    email_success = "em_cb_success"
    _seed_approved_email(test_db, email_success)
    row_s, should_s = test_db.begin_dispatch(
        email_id=email_success,
        destination=destination,
        action_type="alert",
        mode="live",
    )
    assert should_s is True
    lid_s = row_s["id"]
    test_db.finish_dispatch(
        ledger_id=lid_s,
        state="confirmed",
        remote_id="wh_ack_100",
    )

    streak_reset, _ = test_db.get_failure_streak(destination)
    assert streak_reset == 0
