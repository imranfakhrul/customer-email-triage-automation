"""Comprehensive test suite for P2-03b: Multi-Destination Dispatcher Node."""

import logging
import sqlite3
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.database import TriageDatabase
from utils.adapters import reset_adapters
from utils.adapters.base import (
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.config import reset_config_cache

# Node under test (to be imported once implemented)
try:
    from nodes.dispatcher import (
        ROUTING_RULES,
        dispatcher_node,
        route_actions,
        should_route_after_dispatcher,
    )
except ImportError:
    dispatcher_node = None  # type: ignore
    route_actions = None  # type: ignore
    ROUTING_RULES = {}  # type: ignore
    should_route_after_dispatcher = None  # type: ignore


# ---------------------------------------------------------------------------
# Test Fixtures & Test Doubles
# ---------------------------------------------------------------------------
class FakeAdapter(BaseDestinationAdapter):
    """Configurable scriptable destination adapter for testing dispatcher logic."""

    def __init__(
        self,
        name: str = "github",
        outcomes: list[Any] | None = None,
        duplicate_id: str | None = None,
        config_valid: bool | Exception = True,
        health: bool = True,
    ) -> None:
        self.name = name
        self.outcomes = list(outcomes) if outcomes is not None else ["remote-default-id"]
        self.duplicate_id = duplicate_id
        self.config_valid = config_valid
        self.health = health
        self.calls: list[DispatchPayload] = []
        self.check_duplicate_calls: list[tuple[str, DispatchPayload]] = []

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        self.calls.append(payload)
        if not self.outcomes:
            return DispatchResult(remote_id=f"{self.name}-default")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, type) and issubclass(outcome, Exception):
            raise outcome("scripted adapter exception")
        return DispatchResult(remote_id=str(outcome))

    def check_duplicate(
        self, idempotency_key: str, payload: DispatchPayload
    ) -> str | None:
        self.check_duplicate_calls.append((idempotency_key, payload))
        return self.duplicate_id

    def validate_config(self) -> bool:
        if isinstance(self.config_valid, Exception):
            raise self.config_valid
        return bool(self.config_valid)

    def health_check(self) -> bool:
        return self.health


@pytest.fixture
def temp_db():
    """Provides a temporary, fresh TriageDatabase instance for each test."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = TriageDatabase(db_path=tmp.name)
        yield db


@pytest.fixture(autouse=True)
def clean_adapters():
    """Resets adapter registry and config cache before and after each test."""
    reset_adapters()
    reset_config_cache()
    yield
    reset_adapters()
    reset_config_cache()


def base_test_config(dry_run: bool = False, kill_switch: bool = False) -> dict[str, Any]:
    """Returns a fully populated valid configuration dictionary for testing."""
    return {
        "dispatch": {
            "dry_run": dry_run,
            "kill_switch": kill_switch,
            "max_attempts": 3,
            "pending_timeout_minutes": 10,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 20.0,
        },
        "destinations": {
            "github": {
                "enabled": True,
                "daily_cap": 200,
                "use_masked_text_only": True,
                "target": "org/repo",
                "circuit_breaker": {
                    "failure_threshold": 3,
                    "cooldown_seconds": 60,
                },
            },
            "freescout": {
                "enabled": True,
                "daily_cap": 1000,
                "use_masked_text_only": False,
                "target": "https://support.example.com",
                "circuit_breaker": {
                    "failure_threshold": 3,
                    "cooldown_seconds": 60,
                },
            },
            "crm": {
                "enabled": True,
                "daily_cap": 500,
                "use_masked_text_only": False,
                "target_env": "CRM_ENDPOINT",
                "circuit_breaker": {
                    "failure_threshold": 3,
                    "cooldown_seconds": 60,
                },
            },
            "webhook": {
                "enabled": True,
                "daily_cap": 200,
                "use_masked_text_only": False,
                "target_env": "WEBHOOK_URL",
                "circuit_breaker": {
                    "failure_threshold": 3,
                    "cooldown_seconds": 60,
                },
            },
        },
    }


def insert_email_record(
    db: TriageDatabase,
    email_id: str = "em_test_001",
    routing_status: str = "gatekeeper_approved",
    hitl_status: str = "auto_approved",
    category: str = "Bug Report",
    priority: str = "Medium",
    masked_subject: str | None = "Database pool exhausted",
    masked_body: str | None = "Hi, our backend cannot connect to [IP_1].",
    sender_email: str = "dev@example.com",
    status: str = "done",
) -> dict[str, Any]:
    """Helper to insert an email triage record into SQLite."""
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
                sender_email,
                masked_subject,
                masked_body,
                routing_status,
                status,
                category,
                priority,
                "Neutral",
                "Calm",
                "Issue summary",
                "Engineering",
                0.95,
                "groq",
                hitl_status,
                "2026-10-27T12:00:00+00:00",
                "2026-10-27T12:00:00+00:00",
            ),
        )
    return db.get_record(email_id) or {}


# ---------------------------------------------------------------------------
# 1. Routing Rules & Pure Function Unit Tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("category", "priority", "expected_actions"),
    [
        ("Bug Report", "Low", [("github", "create_issue")]),
        ("Bug Report", "Medium", [("github", "create_issue")]),
        ("Bug Report", "High", [("github", "create_issue")]),
        ("Bug Report", "Critical", [("github", "create_issue"), ("webhook", "alert")]),
        ("Feature Request", "Low", [("github", "create_issue")]),
        ("Feature Request", "Critical", [("github", "create_issue")]),
        ("Demo Request", "Medium", [("crm", "create_lead")]),
        ("Pricing Inquiry", "High", [("crm", "create_lead")]),
        ("General Query", "Low", [("freescout", "create_ticket")]),
        ("General Query", "Critical", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Complaint", "Medium", [("freescout", "create_ticket")]),
        ("Complaint", "Critical", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Billing Issue", "Low", [("freescout", "create_ticket")]),
        ("Billing Issue", "Medium", [("freescout", "create_ticket")]),
        ("Billing Issue", "High", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Billing Issue", "Critical", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Refund Request", "Low", [("freescout", "create_ticket")]),
        ("Refund Request", "High", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Refund Request", "Critical", [("freescout", "create_ticket"), ("webhook", "alert")]),
        ("Security/Account", "Low", [("webhook", "alert")]),
        ("Security/Account", "Critical", [("webhook", "alert")]),
        ("Other", "Low", []),
        ("Other", "Critical", []),
        ("UnknownCategory", "High", []),
    ],
)
def test_route_actions_taxonomy_matrix(category, priority, expected_actions):
    """Verifies deterministic pure routing matrix across all categories and priorities."""
    assert route_actions is not None, "route_actions must be implemented and exported"
    actions = route_actions(category, priority)
    assert actions == expected_actions


def test_other_unmapped_category_diverts_to_hitl(temp_db):
    """Verifies that an unmapped category or 'Other' diverts to HITL and returns hitl_pending."""
    insert_email_record(temp_db, "em_other_01", category="Other", hitl_status="auto_approved")
    cfg = base_test_config(dry_run=False)

    res = dispatcher_node({"email_id": "em_other_01"}, db=temp_db, config=cfg)
    assert res["p2_status"] == "hitl_pending"
    assert res["dispatch_results"] == []

    # Verify database was updated with divert_to_hitl
    rec = temp_db.get_record("em_other_01")
    assert rec["hitl_status"] == "pending"
    assert rec["hitl_reason"] == "unmapped_category"

    # No ledger rows created
    assert temp_db.get_dispatch_log("em_other_01") == []


# ---------------------------------------------------------------------------
# 2. Eligibility & State Gating Tests
# ---------------------------------------------------------------------------
def test_dispatcher_node_returns_persist_failed_when_db_is_none():
    """Verify missing database returns persist_failed without touching network."""
    res = dispatcher_node({"email_id": "em_test_001"}, db=None)
    assert res["p2_status"] == "persist_failed"
    assert res["dispatch_results"] == []


@pytest.mark.parametrize(
    ("routing_status", "hitl_status", "category"),
    [
        ("threat_detected", "auto_approved", "Bug Report"),
        ("spam", "auto_approved", "Bug Report"),
        ("gatekeeper_approved", "pending", "Bug Report"),
        ("gatekeeper_approved", "rejected", "Bug Report"),
        ("gatekeeper_approved", "none", "Bug Report"),
        ("gatekeeper_approved", "auto_approved", None),  # missing p2_category
    ],
)
def test_dispatcher_node_not_eligible(temp_db, routing_status, hitl_status, category):
    """Verify ineligible emails return not_eligible and do not touch ledger or adapters."""
    insert_email_record(
        temp_db,
        "em_ineligible",
        routing_status=routing_status,
        hitl_status=hitl_status,
        category=category,
    )
    fake_github = FakeAdapter("github")
    adapters = {"github": fake_github}
    cfg = base_test_config()

    res = dispatcher_node(
        {"email_id": "em_ineligible"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res["p2_status"] == "not_eligible"
    assert res["dispatch_results"] == []
    assert len(fake_github.calls) == 0
    assert temp_db.get_dispatch_log("em_ineligible") == []


def test_missing_email_record_returns_not_eligible(temp_db):
    """Verify non-existent email id returns not_eligible."""
    res = dispatcher_node({"email_id": "em_nonexistent"}, db=temp_db, config=base_test_config())
    assert res["p2_status"] == "not_eligible"
    assert res["dispatch_results"] == []


# ---------------------------------------------------------------------------
# 3. Dry Run Execution & Caplog Privacy Tests
# ---------------------------------------------------------------------------
def test_dry_run_dispatch_simulation_and_privacy_logs(temp_db, caplog):
    """Verify dry_run records simulated rows, makes 0 adapter calls, and logs payload hash."""
    insert_email_record(
        temp_db,
        "em_dry_01",
        category="Bug Report",
        priority="Medium",
        masked_subject="Secret customer masked subject 9988",
        masked_body="Private customer masked body 1122",
    )
    fake_github = FakeAdapter("github")
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=True)

    with caplog.at_level(logging.INFO):
        res = dispatcher_node(
            {"email_id": "em_dry_01"},
            db=temp_db,
            config=cfg,
            adapters=adapters,
        )

    assert res["p2_status"] == "simulated"
    assert len(res["dispatch_results"]) == 1
    item = res["dispatch_results"][0]
    assert item["destination"] == "github"
    assert item["action_type"] == "create_issue"
    assert item["mode"] == "dry_run"
    assert item["ledger_state"] == "simulated"

    # Adapter was never called
    assert len(fake_github.calls) == 0

    # Ledger check: only simulated dry_run row exists
    log_rows = temp_db.get_dispatch_log("em_dry_01")
    assert len(log_rows) == 1
    assert log_rows[0]["mode"] == "dry_run"
    assert log_rows[0]["state"] == "simulated"

    # Privacy check on caplog
    log_text = caplog.text
    assert "[DRY_RUN_DISPATCH]" in log_text
    assert f"payload_sha256={log_rows[0]['payload_sha256']}" in log_text
    assert "payload_bytes=" in log_text
    assert "Secret customer masked subject" not in log_text
    assert "Private customer masked body" not in log_text
    assert "dev@example.com" not in log_text


def test_promotion_dry_run_then_live_coexistence(temp_db):
    """Verify that a previous simulated dry-run row never blocks subsequent live dispatch."""
    insert_email_record(temp_db, "em_promo_01", category="Bug Report")
    fake_github = FakeAdapter("github", outcomes=["issue-777"])
    adapters = {"github": fake_github}

    # Step 1: Run dry run
    res_dry = dispatcher_node(
        {"email_id": "em_promo_01"},
        db=temp_db,
        config=base_test_config(dry_run=True),
        adapters=adapters,
    )
    assert res_dry["p2_status"] == "simulated"
    assert len(fake_github.calls) == 0

    # Step 2: Switch to live mode
    res_live = dispatcher_node(
        {"email_id": "em_promo_01"},
        db=temp_db,
        config=base_test_config(dry_run=False),
        adapters=adapters,
    )
    assert res_live["p2_status"] == "dispatched"
    assert len(fake_github.calls) == 1

    # Verify both rows coexist cleanly in ledger
    rows = temp_db.get_dispatch_log("em_promo_01")
    assert len(rows) == 2
    modes = {r["mode"]: r["state"] for r in rows}
    assert modes["dry_run"] == "simulated"
    assert modes["live"] == "confirmed"


# ---------------------------------------------------------------------------
# 4. Live Dispatch, Idempotency & Retry Lifecycle Tests
# ---------------------------------------------------------------------------
def test_live_dispatch_success_is_idempotent(temp_db):
    """Verify second dispatch call on confirmed record makes no adapter calls."""
    insert_email_record(temp_db, "em_idem_01", category="Demo Request")
    fake_crm = FakeAdapter("crm", outcomes=["lead-100"])
    adapters = {"crm": fake_crm}
    cfg = base_test_config(dry_run=False)

    # First dispatch
    res1 = dispatcher_node({"email_id": "em_idem_01"}, db=temp_db, config=cfg, adapters=adapters)
    assert res1["p2_status"] == "dispatched"
    assert len(fake_crm.calls) == 1
    assert res1["dispatch_results"][0]["remote_id"] == "lead-100"

    # Second dispatch: idempotent re-entry
    res2 = dispatcher_node({"email_id": "em_idem_01"}, db=temp_db, config=cfg, adapters=adapters)
    assert res2["p2_status"] == "dispatched"
    assert len(fake_crm.calls) == 1  # No second call!
    assert res2["dispatch_results"][0]["remote_id"] == "lead-100"


def test_transient_retries_with_bounded_backoff_then_success(temp_db):
    """Verify 2 transient failures followed by success records 3 attempts and calls sleep."""
    insert_email_record(temp_db, "em_trans_01", category="General Query")
    fake_fs = FakeAdapter(
        "freescout",
        outcomes=[
            AdapterTransientError("network glitch 1"),
            AdapterTransientError("network glitch 2"),
            "ticket-999",
        ],
    )
    adapters = {"freescout": fake_fs}
    cfg = base_test_config(dry_run=False)
    mock_sleep = MagicMock()

    res = dispatcher_node(
        {"email_id": "em_trans_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        sleep=mock_sleep,
    )
    assert res["p2_status"] == "dispatched"
    assert len(fake_fs.calls) == 3
    assert mock_sleep.call_count == 2

    # Verify sleep delays were bounded in [0, backoff_max_seconds]
    for call_args in mock_sleep.call_args_list:
        delay = call_args[0][0]
        assert 0.0 <= delay <= 20.0

    log = temp_db.get_dispatch_log("em_trans_01")[0]
    assert log["state"] == "confirmed"
    assert log["attempts"] == 3
    assert log["remote_id"] == "ticket-999"


def test_transient_failures_exhaust_retries_to_dead_letter(temp_db):
    """Verify permanent transient failures reach max_attempts and transition to dead_letter."""
    insert_email_record(temp_db, "em_dead_01", category="Bug Report")
    fake_github = FakeAdapter(
        "github",
        outcomes=[
            AdapterTransientError("err1"),
            AdapterTransientError("err2"),
            AdapterTransientError("err3"),
            AdapterTransientError("err4"),
        ],
    )
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)
    mock_sleep = MagicMock()

    res = dispatcher_node(
        {"email_id": "em_dead_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        sleep=mock_sleep,
    )
    assert res["p2_status"] == "dead_letter"
    assert len(fake_github.calls) == 3  # max_attempts is 3
    assert mock_sleep.call_count == 2

    log = temp_db.get_dispatch_log("em_dead_01")[0]
    assert log["state"] == "dead_letter"
    assert log["reason"] == "retries_exhausted"
    assert log["error_class"] == "AdapterTransientError"

    # Subsequent invocation never calls adapter again
    res2 = dispatcher_node(
        {"email_id": "em_dead_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        sleep=mock_sleep,
    )
    assert res2["p2_status"] == "dead_letter"
    assert len(fake_github.calls) == 3


def test_permanent_error_marks_failed_and_retries_on_later_dispatch(temp_db):
    """Verify AdapterPermanentError marks failed immediately and is retried on later dispatch."""
    insert_email_record(temp_db, "em_perm_01", category="Bug Report")
    fake_github = FakeAdapter(
        "github",
        outcomes=[
            AdapterPermanentError("401 Unauthorized"),
            "issue-recovered",
        ],
    )
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)
    mock_sleep = MagicMock()

    # First attempt: permanent error
    res1 = dispatcher_node(
        {"email_id": "em_perm_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        sleep=mock_sleep,
    )
    assert res1["p2_status"] == "failed"
    assert len(fake_github.calls) == 1
    assert mock_sleep.call_count == 0  # No loop retry on permanent error

    log1 = temp_db.get_dispatch_log("em_perm_01")[0]
    assert log1["state"] == "failed"
    assert log1["reason"] == "permanent_error"
    assert log1["error_class"] == "AdapterPermanentError"

    # Later dispatch retries the failed row and succeeds
    res2 = dispatcher_node(
        {"email_id": "em_perm_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        sleep=mock_sleep,
    )
    assert res2["p2_status"] == "dispatched"
    assert len(fake_github.calls) == 2


# ---------------------------------------------------------------------------
# 5. Unknown Outcome & Verification Sweeper Tests
# ---------------------------------------------------------------------------
def test_unknown_outcome_without_duplicate_diverts_to_hitl(temp_db):
    """Verify AdapterUnknownOutcomeError with check_duplicate=None diverts to HITL."""
    insert_email_record(temp_db, "em_unk_01", category="Bug Report")
    fake_github = FakeAdapter(
        "github",
        outcomes=[AdapterUnknownOutcomeError("Timeout waiting for response")],
        duplicate_id=None,
    )
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    res = dispatcher_node(
        {"email_id": "em_unk_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res["p2_status"] == "hitl_pending"
    assert len(fake_github.calls) == 1
    assert len(fake_github.check_duplicate_calls) == 1

    # Ledger state is unknown
    log = temp_db.get_dispatch_log("em_unk_01")[0]
    assert log["state"] == "unknown"

    # Email diverted to HITL
    rec = temp_db.get_record("em_unk_01")
    assert rec["hitl_status"] == "pending"
    assert rec["hitl_reason"] == "dispatch_outcome_unknown"

    # Subsequent call does NOT make blind dispatch calls (ineligible because hitl_status is pending)
    res2 = dispatcher_node(
        {"email_id": "em_unk_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res2["p2_status"] == "not_eligible"
    assert len(fake_github.calls) == 1


def test_unknown_outcome_with_duplicate_found_resolves_to_confirmed(temp_db):
    """Verify AdapterUnknownOutcomeError resolves to confirmed if duplicate found."""
    insert_email_record(temp_db, "em_unk_02", category="Bug Report")
    fake_github = FakeAdapter(
        "github",
        outcomes=[AdapterUnknownOutcomeError("Connection dropped")],
        duplicate_id="issue-verified-duplicate-44",
    )
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    res = dispatcher_node(
        {"email_id": "em_unk_02"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res["p2_status"] == "dispatched"
    assert len(fake_github.calls) == 1
    assert len(fake_github.check_duplicate_calls) == 1

    # Ledger row was resolved to confirmed
    log = temp_db.get_dispatch_log("em_unk_02")[0]
    assert log["state"] == "confirmed"
    assert log["remote_id"] == "issue-verified-duplicate-44"
    assert log["resolved_by"] == "auto_check"

    # No diversion to HITL
    rec = temp_db.get_record("em_unk_02")
    assert rec["hitl_status"] == "auto_approved"


def test_unexpected_adapter_exception_treated_as_unknown(temp_db):
    """Verify unexpected runtime exceptions from adapter are treated safely as unknown outcome."""
    insert_email_record(temp_db, "em_unexp_01", category="Demo Request")
    fake_crm = FakeAdapter(
        "crm",
        outcomes=[RuntimeError("unexpected socket crash")],
        duplicate_id=None,
    )
    adapters = {"crm": fake_crm}
    cfg = base_test_config(dry_run=False)

    res = dispatcher_node(
        {"email_id": "em_unexp_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res["p2_status"] == "hitl_pending"
    assert len(fake_crm.calls) == 1

    log = temp_db.get_dispatch_log("em_unexp_01")[0]
    assert log["state"] == "unknown"
    assert log["reason"] == "unexpected_error"
    assert log["error_class"] == "RuntimeError"


def test_stale_pending_row_treated_as_unknown_without_dispatch_call(temp_db):
    """Verify stale pending rows are expired to unknown and checked without calling dispatch."""
    insert_email_record(temp_db, "em_stale_01", category="Bug Report")
    row, _ = temp_db.begin_dispatch("em_stale_01", "github", "create_issue", "live")
    ledger_id = row["id"]

    # Backdate pending row by 30 minutes
    now_utc = datetime.now(UTC)
    old_time = (now_utc - timedelta(minutes=30)).isoformat()
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE p2_dispatch_log SET updated_at = ? WHERE id = ?",
            (old_time, ledger_id),
        )

    fake_github = FakeAdapter("github", duplicate_id="issue-recovered-stale")
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    res = dispatcher_node(
        {"email_id": "em_stale_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        now=lambda: now_utc,
    )
    assert res["p2_status"] == "dispatched"
    assert len(fake_github.calls) == 0  # No dispatch call
    assert len(fake_github.check_duplicate_calls) == 1

    log = temp_db.get_dispatch_log("em_stale_01")[0]
    assert log["state"] == "confirmed"
    assert log["remote_id"] == "issue-recovered-stale"


# ---------------------------------------------------------------------------
# 6. Safety Rails Tests (Kill Switch, Daily Cap, Circuit Breaker)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("rail_mod", "expected_reason"),
    [
        ({"dispatch": {"kill_switch": True}}, "kill_switch"),
        ({"destinations": {"github": {"enabled": False}}}, "destination_disabled"),
        ({"no_adapter": True}, "adapter_unavailable"),
        ({"bad_config": True}, "adapter_not_configured"),
    ],
)
def test_safety_rails_defer_action(temp_db, rail_mod, expected_reason):
    """Verify safety rails defer action before dispatch attempt with appropriate reason codes."""
    insert_email_record(temp_db, "em_rail_01", category="Bug Report")
    cfg = base_test_config(dry_run=False)

    fake_github = FakeAdapter("github")
    adapters: dict[str, Any] = {"github": fake_github}

    if "dispatch" in rail_mod:
        cfg["dispatch"]["kill_switch"] = rail_mod["dispatch"]["kill_switch"]
    if "destinations" in rail_mod:
        cfg["destinations"]["github"]["enabled"] = rail_mod["destinations"]["github"]["enabled"]
    if rail_mod.get("no_adapter"):
        adapters = {}
    if rail_mod.get("bad_config"):
        fake_github.config_valid = False

    res = dispatcher_node(
        {"email_id": "em_rail_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res["p2_status"] == "deferred"
    assert len(fake_github.calls) == 0
    assert res["dispatch_results"][0]["ledger_state"] == "deferred"
    assert res["dispatch_results"][0]["reason"] == expected_reason


def test_daily_cap_rail_defers_action(temp_db):
    """Verify daily cap counts only live confirmed rows of today and defers if cap reached."""
    insert_email_record(temp_db, "em_cap_target", category="Bug Report")
    now_utc = datetime.now(UTC)
    cfg = base_test_config(dry_run=False)
    cfg["destinations"]["github"]["daily_cap"] = 2

    # Insert 2 confirmed live rows for today
    for i in range(2):
        insert_email_record(temp_db, f"em_seed_{i}", category="Bug Report")
        r, _ = temp_db.begin_dispatch(f"em_seed_{i}", "github", "create_issue", "live")
        temp_db.record_dispatch_attempt(r["id"])
        temp_db.finish_dispatch(r["id"], "confirmed", remote_id=f"seed-{i}")

    fake_github = FakeAdapter("github")
    adapters = {"github": fake_github}

    res = dispatcher_node(
        {"email_id": "em_cap_target"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        now=lambda: now_utc,
    )
    assert res["p2_status"] == "deferred"
    assert len(fake_github.calls) == 0
    assert res["dispatch_results"][0]["reason"] == "daily_cap"


def test_circuit_breaker_rail_and_cooldown_trial(temp_db):
    """Verify circuit breaker opens after failure threshold, and allows trial after cooldown."""
    insert_email_record(temp_db, "em_cb_01", category="Bug Report")
    now_utc = datetime.now(UTC)
    cfg = base_test_config(dry_run=False)
    cfg["destinations"]["github"]["circuit_breaker"]["failure_threshold"] = 2
    cfg["destinations"]["github"]["circuit_breaker"]["cooldown_seconds"] = 100

    # Seed 2 failures in the last 10 seconds
    recent_failure_time = (now_utc - timedelta(seconds=10)).isoformat()
    for i in range(2):
        insert_email_record(temp_db, f"em_fail_{i}", category="Bug Report")
        r, _ = temp_db.begin_dispatch(f"em_fail_{i}", "github", "create_issue", "live")
        temp_db.record_dispatch_attempt(r["id"])
        temp_db.finish_dispatch(r["id"], "failed", reason="timeout")
        with temp_db.get_connection() as conn:
            conn.execute(
                "UPDATE p2_dispatch_log SET updated_at = ? WHERE id = ?",
                (recent_failure_time, r["id"]),
            )

    fake_github = FakeAdapter("github", outcomes=["issue-trial-ok"])
    adapters = {"github": fake_github}

    # Circuit is OPEN (10s < 100s cooldown)
    res_open = dispatcher_node(
        {"email_id": "em_cb_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        now=lambda: now_utc,
    )
    assert res_open["p2_status"] == "deferred"
    assert res_open["dispatch_results"][0]["reason"] == "circuit_open"
    assert len(fake_github.calls) == 0

    # Advance time past cooldown (150s later): trial attempt is permitted!
    future_time = now_utc + timedelta(seconds=150)
    res_trial = dispatcher_node(
        {"email_id": "em_cb_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
        now=lambda: future_time,
    )
    assert res_trial["p2_status"] == "dispatched"
    assert len(fake_github.calls) == 1


# ---------------------------------------------------------------------------
# 7. Multi-Action & Concurrency Tests
# ---------------------------------------------------------------------------
def test_two_action_email_with_partial_failure(temp_db):
    """Verify dual actions on partial failure: confirmed action is not re-sent on retry."""
    insert_email_record(temp_db, "em_two_01", category="Billing Issue", priority="High")
    fake_fs = FakeAdapter("freescout", outcomes=["fs-ticket-555"])
    fake_wh = FakeAdapter("webhook", outcomes=[AdapterPermanentError("403 Forbidden")])
    adapters = {"freescout": fake_fs, "webhook": fake_wh}
    cfg = base_test_config(dry_run=False)

    # First dispatch run: FreeScout confirmed, Webhook failed
    res1 = dispatcher_node(
        {"email_id": "em_two_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res1["p2_status"] == "failed"
    assert len(fake_fs.calls) == 1
    assert len(fake_wh.calls) == 1
    states1 = {r["destination"]: r["ledger_state"] for r in res1["dispatch_results"]}
    assert states1["freescout"] == "confirmed"
    assert states1["webhook"] == "failed"

    # Second dispatch run: FreeScout is NOT re-sent; Webhook retried with recovered response
    fake_wh.outcomes = ["webhook-alert-recovered-88"]
    res2 = dispatcher_node(
        {"email_id": "em_two_01"},
        db=temp_db,
        config=cfg,
        adapters=adapters,
    )
    assert res2["p2_status"] == "dispatched"
    assert len(fake_fs.calls) == 1  # Still 1, never re-sent!
    assert len(fake_wh.calls) == 2  # Webhook was retried and succeeded


def test_concurrency_multi_threads_atomic_dispatch(temp_db):
    """Verify 8 concurrent threads dispatching same email result in exactly 1 adapter call."""
    insert_email_record(temp_db, "em_concurrent_01", category="Demo Request")
    fake_crm = FakeAdapter("crm", outcomes=["lead-atomic-001"])
    adapters = {"crm": fake_crm}
    cfg = base_test_config(dry_run=False)

    exceptions: list[Exception] = []

    def worker():
        try:
            dispatcher_node(
                {"email_id": "em_concurrent_01"},
                db=temp_db,
                config=cfg,
                adapters=adapters,
            )
        except Exception as e:
            exceptions.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not exceptions, f"Concurrent dispatch raised exceptions: {exceptions}"
    assert len(fake_crm.calls) == 1
    log = temp_db.get_dispatch_log("em_concurrent_01")
    assert len(log) == 1
    assert log[0]["state"] == "confirmed"


# ---------------------------------------------------------------------------
# 8. Privacy & Phase 1 Invariant Tests
# ---------------------------------------------------------------------------
def test_dispatch_payload_strict_privacy_invariants(temp_db):
    """Verify adapter receives DispatchPayload with exact allowed fields, no PII or raw text."""
    insert_email_record(
        temp_db,
        "em_priv_01",
        category="Bug Report",
        sender_email="alice@techcorp.io",
        masked_subject="Masked Subject [PERSON_1]",
        masked_body="Masked Body [EMAIL_1]",
    )
    fake_github = FakeAdapter("github", outcomes=["issue-priv-1"])
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    dispatcher_node({"email_id": "em_priv_01"}, db=temp_db, config=cfg, adapters=adapters)

    assert len(fake_github.calls) == 1
    payload = fake_github.calls[0]

    assert isinstance(payload, DispatchPayload)
    assert payload.sender_domain == "techcorp.io"
    assert payload.masked_subject == "Masked Subject [PERSON_1]"
    assert payload.masked_body == "Masked Body [EMAIL_1]"

    # Verify no forbidden keys exist on payload dict
    payload_dict = payload.to_dict()
    forbidden = ["sender_email", "token_map", "email_body", "raw_body", "cleaned_body"]
    for k in forbidden:
        assert k not in payload_dict


def test_exception_message_with_pii_never_logged(temp_db, caplog):
    """Verify that an adapter exception whose message contains sensitive PII is never logged."""
    insert_email_record(temp_db, "em_leak_01", category="Bug Report")
    leak_secret = "sensitive_customer_email@target.org"
    fake_github = FakeAdapter(
        "github",
        outcomes=[AdapterTransientError(f"Failed to post to {leak_secret}")],
    )
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    with caplog.at_level(logging.DEBUG):
        dispatcher_node(
            {"email_id": "em_leak_01"},
            db=temp_db,
            config=cfg,
            adapters=adapters,
        )

    # Hard privacy invariant: exception messages with customer PII must never be logged
    assert leak_secret not in caplog.text


def test_phase1_routing_status_and_status_unchanged_after_dispatch(temp_db):
    """Verify Phase 1 data is untouched and get_gatekeeper_approved still returns email."""
    insert_email_record(
        temp_db,
        "em_p1_iso",
        routing_status="gatekeeper_approved",
        status="done",
        category="Bug Report",
    )
    fake_github = FakeAdapter("github", outcomes=["issue-iso-01"])
    adapters = {"github": fake_github}
    cfg = base_test_config(dry_run=False)

    dispatcher_node({"email_id": "em_p1_iso"}, db=temp_db, config=cfg, adapters=adapters)

    rec = temp_db.get_record("em_p1_iso")
    assert rec["routing_status"] == "gatekeeper_approved"
    assert rec["status"] == "done"
    assert rec["dispatch_target"] is None

    approved = temp_db.get_gatekeeper_approved(limit=10)
    assert any(r["email_id"] == "em_p1_iso" for r in approved)


def test_database_write_failure_returns_persist_failed(temp_db):
    """Verify database write failure returns persist_failed and calls zero adapters."""
    insert_email_record(temp_db, "em_db_fail", category="Bug Report")
    fake_github = FakeAdapter("github")
    adapters = {"github": fake_github}

    # Simulate database error by closing underlying connection
    temp_db.begin_dispatch = MagicMock(side_effect=sqlite3.OperationalError("disk I/O error"))

    res = dispatcher_node(
        {"email_id": "em_db_fail"},
        db=temp_db,
        config=base_test_config(),
        adapters=adapters,
    )
    assert res["p2_status"] == "persist_failed"
    assert len(fake_github.calls) == 0


def test_should_route_after_dispatcher():
    """Verify conditional edge router for terminal dispatcher node."""
    assert should_route_after_dispatcher is not None
    assert should_route_after_dispatcher({"p2_status": "dispatched"}) == "end"
    assert should_route_after_dispatcher({"p2_status": "simulated"}) == "end"
