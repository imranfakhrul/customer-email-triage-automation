"""Unit tests for P2-03a: Dispatcher Foundations, Base Adapter, and Outbox Ledger."""

import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from db.database import HitlStateError, LedgerStateError, PersistenceError, TriageDatabase
from utils.adapters import (
    get_adapter,
    register_adapter,
    reset_adapters,
)
from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.config import (
    ConfigError,
    get_config,
    reset_config_cache,
    validate_config,
)


# ---------------------------------------------------------------------------
# Dummy Concrete Adapter for Testing
# ---------------------------------------------------------------------------
class DummyTestAdapter(BaseDestinationAdapter):
    name = "github"

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        return DispatchResult(remote_id="issue-123", outcome="success")

    def check_duplicate(self, idempotency_key: str, payload: DispatchPayload) -> str | None:
        return None

    def validate_config(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# 1. Base Adapter Contract & Exception Hierarchy Tests
# ---------------------------------------------------------------------------
def test_base_adapter_cannot_be_instantiated():
    """Verify BaseDestinationAdapter is an abstract class and cannot be instantiated."""
    with pytest.raises(TypeError):
        BaseDestinationAdapter()  # type: ignore[abstract]


def test_adapter_exception_hierarchy():
    """Verify AdapterError is base and transient/permanent/unknown are subclasses."""
    assert issubclass(AdapterTransientError, AdapterError)
    assert issubclass(AdapterPermanentError, AdapterError)
    assert issubclass(AdapterUnknownOutcomeError, AdapterError)
    assert issubclass(AdapterError, Exception)

    # Verify raise/catch mechanics
    with pytest.raises(AdapterError):
        raise AdapterTransientError("Network dropped before send")

    with pytest.raises(AdapterError):
        raise AdapterPermanentError("Invalid repository target")

    with pytest.raises(AdapterError):
        raise AdapterUnknownOutcomeError("Timeout waiting for HTTP 201")


def test_dispatch_result_validation():
    """Verify DispatchResult requires non-empty remote_id of at most 128 chars."""
    res = DispatchResult(remote_id="remote-42")
    assert res.remote_id == "remote-42"
    assert res.outcome == "success"

    # Empty remote_id
    with pytest.raises(ValueError):
        DispatchResult(remote_id="")

    with pytest.raises(ValueError):
        DispatchResult(remote_id="   ")

    # > 128 chars
    with pytest.raises(ValueError):
        DispatchResult(remote_id="a" * 129)


# ---------------------------------------------------------------------------
# 2. DispatchPayload Contract, Clamping & Privacy Invariants
# ---------------------------------------------------------------------------
def test_dispatch_payload_exact_fields_and_privacy():
    """Verify DispatchPayload contains exactly the 16 approved fields and no PII."""
    expected_fields = {
        "email_id",
        "message_id",
        "thread_id",
        "category",
        "priority",
        "sentiment",
        "customer_emotion",
        "summary",
        "suggested_team",
        "confidence",
        "masked_subject",
        "masked_body",
        "sender_domain",
        "p2_classifier_used",
        "action_type",
        "idempotency_key",
    }
    actual_fields = set(DispatchPayload.__dataclass_fields__.keys())  # type: ignore[attr-defined]
    diff_extra = actual_fields - expected_fields
    diff_missing = expected_fields - actual_fields
    assert actual_fields == expected_fields, (
        f"Fields mismatch: extra={diff_extra}, missing={diff_missing}"
    )

    # Hard invariant: no sender_email, no token_map, no raw text fields
    assert "sender_email" not in actual_fields
    assert "token_map" not in actual_fields
    assert "email_body" not in actual_fields
    assert "raw_body" not in actual_fields
    assert "cleaned_body" not in actual_fields


def test_dispatch_payload_from_record_and_clamping():
    """Verify from_record extracts domain, clamps lengths, and hashes stably."""
    record = {
        "email_id": "em_test_001",
        "message_id": "<msg001@acme.com>",
        "thread_id": "th_test_001",
        "sender_email": "John.Doe@Acme-Corp.COM",
        "p2_category": "Bug Report",
        "p2_priority": "High",
        "p2_sentiment": "Negative",
        "p2_customer_emotion": "Frustrated",
        "p2_summary": "Database pool exhaustion",
        "p2_suggested_team": "Engineering",
        "p2_confidence": 0.95,
        "p2_classifier_used": "groq",
        "masked_subject": "Issue with [ORG_1_abcd] " + ("x" * 2500),
        "masked_body": "Hello, our database connection broke. " + ("y" * 12000),
    }

    payload = DispatchPayload.from_record(
        record=record,
        action_type="create_issue",
        idempotency_key="em_test_001:github:create_issue",
    )

    assert payload.email_id == "em_test_001"
    assert payload.sender_domain == "acme-corp.com"
    assert payload.category == "Bug Report"
    assert payload.priority == "High"
    assert len(payload.masked_subject) == 2000
    assert len(payload.masked_body) == 10000

    # Stable SHA-256 hash
    hash1 = payload.sha256()
    hash2 = payload.sha256()
    assert hash1 == hash2
    assert len(hash1) == 64

    # Dict conversion
    d = payload.to_dict()
    assert isinstance(d, dict)
    assert d["email_id"] == "em_test_001"
    assert "sender_email" not in d


def test_dispatch_payload_missing_masked_text_raises_value_error():
    """Verify missing or None masked text fails closed with ValueError."""
    bad_record = {
        "email_id": "em_bad_001",
        "masked_subject": None,
        "masked_body": "Valid body",
    }
    with pytest.raises(ValueError, match="masked_subject"):
        DispatchPayload.from_record(bad_record, "alert", "key-1")

    bad_record2 = {
        "email_id": "em_bad_002",
        "masked_subject": "Valid subject",
        "masked_body": None,
    }
    with pytest.raises(ValueError, match="masked_body"):
        DispatchPayload.from_record(bad_record2, "alert", "key-2")


# ---------------------------------------------------------------------------
# 3. Adapter Registry Tests
# ---------------------------------------------------------------------------
def test_adapter_registry_lifecycle():
    """Verify thread-safe adapter registration, retrieval, and reset."""
    reset_adapters()
    adapter = DummyTestAdapter()

    register_adapter("github", adapter)
    retrieved = get_adapter("github")
    assert retrieved is adapter

    # Valid adapter names only
    with pytest.raises(ValueError, match="Invalid adapter name"):
        register_adapter("invalid_service", adapter)

    with pytest.raises(ValueError, match="Invalid adapter name"):
        get_adapter("invalid_service")

    reset_adapters()
    assert get_adapter("github") is None


# ---------------------------------------------------------------------------
# 4. Outbox Ledger (`p2_dispatch_log`) Database Tests
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_db():
    """Creates a temporary TriageDatabase initialized with gatekeeper_approved sample email."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = TriageDatabase(db_path=tmp.name)
        now = datetime.now(UTC).isoformat()
        with db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO email_triage (
                    email_id, message_id, thread_id, sender_email, status,
                    routing_status, dispatch_target, created_at, updated_at,
                    masked_subject, masked_body, gatekeeper_decision, gatekeeper_confidence,
                    p2_category, p2_priority, p2_sentiment, p2_customer_emotion,
                    p2_summary, p2_suggested_team, p2_confidence, p2_classifier_used,
                    hitl_status
                ) VALUES (
                    'em_ledger_001', '<msg001@example.com>', 'th_001', 'user@example.com',
                    'done', 'gatekeeper_approved', 'github', ?, ?,
                    'Masked Subj', 'Masked Body', 'legitimate', 0.95,
                    'Bug Report', 'High', 'Negative', 'Frustrated',
                    'DB bug', 'Engineering', 0.95, 'groq', 'auto_approved'
                )
                """,
                (now, now),
            )
        yield db


def test_idempotency_key_builder(temp_db):
    """Verify build_idempotency_key formats deterministically."""
    key = temp_db.build_idempotency_key("em_123", "github", "create_issue")
    assert key == "em_123:github:create_issue"


def test_begin_dispatch_lifecycle_and_coexistence(temp_db):
    """Verify begin_dispatch acquisition, dry_run vs live coexistence, and duplicate lock."""
    # 1. First dry_run acquisition succeeds
    row_dry, acquired = temp_db.begin_dispatch(
        email_id="em_ledger_001",
        destination="github",
        action_type="create_issue",
        mode="dry_run",
    )
    assert acquired is True
    assert row_dry["state"] == "pending"
    assert row_dry["mode"] == "dry_run"
    assert row_dry["attempts"] == 0

    # 2. Second dry_run acquisition with same key while pending returns acquired=False
    row_dry_dup, acquired_dup = temp_db.begin_dispatch(
        email_id="em_ledger_001",
        destination="github",
        action_type="create_issue",
        mode="dry_run",
    )
    assert acquired_dup is False
    assert row_dry_dup["id"] == row_dry["id"]

    # 3. Live row with the exact same idempotency_key coexists independently (D1)
    row_live, acquired_live = temp_db.begin_dispatch(
        email_id="em_ledger_001",
        destination="github",
        action_type="create_issue",
        mode="live",
    )
    assert acquired_live is True
    assert row_live["mode"] == "live"
    assert row_live["id"] != row_dry["id"]


def test_begin_dispatch_fails_if_email_missing_or_not_approved(temp_db):
    """Verify begin_dispatch raises PersistenceError if email not gatekeeper_approved."""
    # Non-existent email
    with pytest.raises(PersistenceError):
        temp_db.begin_dispatch("em_nonexistent", "github", "create_issue", "live")

    # Email exists but routing_status is 'quarantined'
    now = datetime.now(UTC).isoformat()
    with temp_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, status, routing_status, created_at, updated_at
            ) VALUES ('em_quarantined', 'done', 'sensitive_quarantine', ?, ?)
            """,
            (now, now),
        )

    with pytest.raises(PersistenceError):
        temp_db.begin_dispatch("em_quarantined", "github", "create_issue", "live")


def test_record_attempt_and_finish_dispatch_transitions(temp_db):
    """Verify attempt increment and state finish transitions."""
    row, acquired = temp_db.begin_dispatch(
        "em_ledger_001", "github", "create_issue", "live"
    )
    assert acquired is True
    ledger_id = row["id"]

    # Record attempt: 0 -> 1
    attempts = temp_db.record_dispatch_attempt(ledger_id)
    assert attempts == 1

    # Cannot finish with invalid target state
    with pytest.raises(ValueError):
        temp_db.finish_dispatch(ledger_id, state="invalid_state")

    # Finish to confirmed
    res = temp_db.finish_dispatch(ledger_id, state="confirmed", remote_id="issue-999")
    assert res is True

    # Cannot record attempt or finish an already confirmed dispatch
    with pytest.raises(LedgerStateError):
        temp_db.record_dispatch_attempt(ledger_id)

    with pytest.raises(LedgerStateError):
        temp_db.finish_dispatch(ledger_id, state="confirmed")


def test_finish_dispatch_validation_rules(temp_db):
    """Verify remote_id, reason, and error_class validations on finish_dispatch."""
    row, _ = temp_db.begin_dispatch("em_ledger_001", "github", "create_issue", "live")
    ledger_id = row["id"]

    # Invalid remote_id characters
    with pytest.raises(ValueError, match="remote_id"):
        temp_db.finish_dispatch(ledger_id, "confirmed", remote_id="bad remote id with spaces!")

    # Invalid reason code (not ^[a-z_]{1,40}$)
    with pytest.raises(ValueError, match="reason"):
        temp_db.finish_dispatch(ledger_id, "failed", reason="Invalid Reason With Spaces")

    # Invalid error_class (not ^[A-Za-z0-9_]+$)
    with pytest.raises(ValueError, match="error_class"):
        temp_db.finish_dispatch(ledger_id, "failed", error_class="Error-Class With Dashes")


def test_retry_until_max_attempts_then_dead_letter(temp_db):
    """Verify failed row can be re-acquired up to max_attempts, then transitions to dead_letter."""
    row, acquired = temp_db.begin_dispatch(
        "em_ledger_001", "github", "create_issue", "live", max_attempts=2
    )
    assert acquired is True
    ledger_id = row["id"]
    temp_db.record_dispatch_attempt(ledger_id)  # attempts = 1
    temp_db.finish_dispatch(ledger_id, "failed", reason="network_timeout")

    # Retry attempt 2: acquired = True
    row_retry, acquired_retry = temp_db.begin_dispatch(
        "em_ledger_001", "github", "create_issue", "live", max_attempts=2
    )
    assert row_retry is not None
    assert acquired_retry is True
    temp_db.record_dispatch_attempt(ledger_id)  # attempts = 2
    temp_db.finish_dispatch(ledger_id, "failed", reason="network_timeout")

    # Retry attempt 3 (exceeds max_attempts=2): moves to dead_letter, acquired = False
    row_dead, acquired_dead = temp_db.begin_dispatch(
        "em_ledger_001", "github", "create_issue", "live", max_attempts=2
    )
    assert acquired_dead is False
    assert row_dead["state"] == "dead_letter"
    assert row_dead["reason"] == "retries_exhausted"


def test_resolve_unknown_dispatch_lifecycle(temp_db):
    """Verify unknown outcome resolution rules."""
    row, _ = temp_db.begin_dispatch("em_ledger_001", "webhook", "alert", "live")
    ledger_id = row["id"]
    temp_db.record_dispatch_attempt(ledger_id)
    temp_db.finish_dispatch(ledger_id, "unknown", reason="socket_hangup")

    # Resolve confirmed requires remote_id
    with pytest.raises(ValueError, match="requires non-empty remote_id"):
        temp_db.resolve_unknown_dispatch(ledger_id, outcome="confirmed", resolved_by="admin")

    # Invalid resolved_by
    with pytest.raises(ValueError, match="resolved_by"):
        temp_db.resolve_unknown_dispatch(
            ledger_id, outcome="confirmed", resolved_by="", remote_id="hook-1"
        )

    # Resolve not_sent transitions to failed with operator_not_sent
    res = temp_db.resolve_unknown_dispatch(
        ledger_id, outcome="not_sent", resolved_by="operator_alice"
    )
    assert res is True

    log = temp_db.get_dispatch_log("em_ledger_001")
    assert log[0]["state"] == "failed"
    assert log[0]["reason"] == "operator_not_sent"
    assert log[0]["resolved_by"] == "operator_alice"

    # Resolving a row that is no longer unknown raises LedgerStateError
    with pytest.raises(LedgerStateError):
        temp_db.resolve_unknown_dispatch(
            ledger_id, outcome="confirmed", resolved_by="admin", remote_id="ok"
        )


def test_expire_stale_pending(temp_db):
    """Verify pending records older than cutoff are marked unknown."""
    row, _ = temp_db.begin_dispatch("em_ledger_001", "crm", "create_lead", "live")
    ledger_id = row["id"]

    # Backdate updated_at by 20 minutes
    stale_time = (datetime.now(UTC) - timedelta(minutes=20)).isoformat()
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE p2_dispatch_log SET updated_at = ? WHERE id = ?",
            (stale_time, ledger_id),
        )

    expired_count = temp_db.expire_stale_pending(older_than_minutes=10)
    assert expired_count == 1

    log = temp_db.get_dispatch_log("em_ledger_001")
    assert log[0]["state"] == "unknown"
    assert log[0]["reason"] == "stale_pending"


def test_count_confirmed_today_and_failure_streak(temp_db):
    """Verify daily confirmed count and failure streak calculations."""
    now = datetime.now(UTC)

    # Insert confirmed live row for today
    r1, _ = temp_db.begin_dispatch("em_ledger_001", "github", "create_issue", "live")
    temp_db.record_dispatch_attempt(r1["id"])
    temp_db.finish_dispatch(r1["id"], "confirmed", remote_id="gh-1")

    # Insert simulated dry_run row for today (must be ignored by count_confirmed_today)
    r_sim, _ = temp_db.begin_dispatch("em_ledger_001", "github", "create_issue", "dry_run")
    temp_db.finish_dispatch(r_sim["id"], "simulated")

    assert temp_db.count_confirmed_today("github", now=now) == 1

    # Insert a confirmed row backdated to yesterday (must be ignored)
    yesterday = (now - timedelta(days=1)).isoformat()
    with temp_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO p2_dispatch_log (
                email_id, destination, action_type, idempotency_key, mode,
                state, attempts, remote_id, created_at, updated_at
            ) VALUES (
                'em_ledger_001', 'github', 'alert', 'old_key', 'live',
                'confirmed', 1, 'gh-old', ?, ?
            )
            """,
            (yesterday, yesterday),
        )
    assert temp_db.count_confirmed_today("github", now=now) == 1

    # Failure streak: confirmed row resets streak
    streak, newest_failure = temp_db.get_failure_streak("github", now=now)
    assert streak == 0
    assert newest_failure is None

    # Add two failures
    with temp_db.get_connection() as conn:
        t1 = (now + timedelta(seconds=1)).isoformat()
        t2 = (now + timedelta(seconds=2)).isoformat()
        conn.execute(
            """
            INSERT INTO p2_dispatch_log (
                email_id, destination, action_type, idempotency_key, mode,
                state, attempts, created_at, updated_at
            ) VALUES
            ('em_ledger_001', 'github', 'alert', 'fail_1', 'live', 'failed', 1, ?, ?),
            ('em_ledger_001', 'github', 'alert', 'fail_2', 'live', 'unknown', 1, ?, ?)
            """,
            (t1, t1, t2, t2),
        )

    streak, newest_failure = temp_db.get_failure_streak("github", now=now)
    assert streak == 2
    assert newest_failure == t2


def test_divert_to_hitl_and_phase1_isolation(temp_db):
    """Verify divert_to_hitl updates hitl status without touching Phase 1 columns."""
    # 1. Valid divert from auto_approved -> pending
    res = temp_db.divert_to_hitl("em_ledger_001", reason="circuit_breaker_open")
    assert res is True

    record = temp_db.get_record("em_ledger_001")
    assert record is not None
    assert record["hitl_status"] == "pending"
    assert record["hitl_reason"] == "circuit_breaker_open"

    # Invariant 10: Phase 1 columns are UNTOUCHED
    assert record["routing_status"] == "gatekeeper_approved"
    assert record["status"] == "done"
    assert record["dispatch_target"] == "github"

    # 2. Second divert raises HitlStateError because already pending
    with pytest.raises(HitlStateError):
        temp_db.divert_to_hitl("em_ledger_001", reason="cap_exceeded")

    # 3. Non-existent email raises PersistenceError
    with pytest.raises(PersistenceError):
        temp_db.divert_to_hitl("em_nonexistent", reason="cap_exceeded")

    # 4. Reason validation
    with pytest.raises(ValueError):
        temp_db.divert_to_hitl("em_ledger_001", reason="Invalid Reason With Spaces!")


def test_migration_and_idempotent_db_init():
    """Verify TriageDatabase creates p2_dispatch_log cleanly and opening twice is safe."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        # Create an old-style DB with only email_triage
        with sqlite3.connect(tmp.name) as conn:
            conn.execute(
                """
                CREATE TABLE email_triage (
                    email_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

        # Open with TriageDatabase -> runs migration
        db1 = TriageDatabase(db_path=tmp.name)
        with db1.get_connection() as conn:
            query = "SELECT name FROM sqlite_master WHERE type='table'"
            tables = [r[0] for r in conn.execute(query).fetchall()]
            assert "p2_dispatch_log" in tables

        # Open again -> idempotent, no errors
        db2 = TriageDatabase(db_path=tmp.name)
        assert db2.db_path == tmp.name


# ---------------------------------------------------------------------------
# 5. Configuration & B5 Schema Validation Tests
# ---------------------------------------------------------------------------
def test_config_shipped_values_pass_validation():
    """Verify live config.yaml passes all validation checks."""
    reset_config_cache()
    cfg = get_config()
    assert "dispatch" in cfg
    assert "destinations" in cfg
    assert cfg["dispatch"]["dry_run"] is True
    assert cfg["dispatch"]["kill_switch"] is False
    assert set(cfg["destinations"].keys()) == {"github", "freescout", "crm", "webhook"}


@pytest.mark.parametrize(
    "mod_key,mod_val,err_pattern",
    [
        ("destinations.github.daily_cap", 0, "daily_cap"),
        ("dispatch.dry_run", "true", "dry_run"),
        ("dispatch.unknown_key", "test", "Unknown key 'unknown_key' in section 'dispatch'"),
        ("destinations.unknown_dest", {}, "Unknown key 'unknown_dest' in section 'destinations'"),
        ("destinations.github.circuit_breaker.failure_threshold", 0, "failure_threshold"),
        ("dispatch.backoff_max_seconds", 0.5, "backoff_max_seconds"),
        ("dispatch.max_attempts", 0, "max_attempts"),
        ("destinations.github.enabled", 1, "enabled"),
    ],
)
def test_config_invalid_cases_raise_config_error(mod_key: str, mod_val: Any, err_pattern: str):
    """Verify table-driven configuration validation rules raise ConfigError."""
    cfg = get_config()
    import copy
    test_cfg = copy.deepcopy(cfg)

    keys = mod_key.split(".")
    target = test_cfg
    for k in keys[:-1]:
        target = target[k]
    target[keys[-1]] = mod_val

    with pytest.raises(ConfigError, match=err_pattern):
        validate_config(test_cfg)


def test_config_missing_destination_raises_config_error():
    """Verify missing any of the 4 destinations raises ConfigError."""
    cfg = get_config()
    import copy
    test_cfg = copy.deepcopy(cfg)
    del test_cfg["destinations"]["webhook"]

    with pytest.raises(ConfigError, match="destinations"):
        validate_config(test_cfg)
