"""Tests for PRR-12: Operational guards, config isolation, CAS, and fail-closed."""

import copy
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from db.database import PersistenceError, TriageDatabase
from nodes.classifier import classifier_node
from nodes.dispatcher import dispatcher_node
from scripts.phase2_worker import run_worker_once
from state import TriageState
from utils.adapters.base import BaseDestinationAdapter, DispatchResult
from utils.config import get_config, reset_config_cache


class FakeAdapter(BaseDestinationAdapter):
    """Minimal fake adapter for dispatcher circuit breaker testing."""

    name: str = "github"

    def __init__(self, name: str = "github"):
        super().__init__()
        self.name = name
        self.calls: list[dict] = []

    def validate_config(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True

    def check_duplicate(self, idempotency_key, payload):
        return None

    def dispatch(self, payload):
        self.calls.append({"payload": payload})
        return DispatchResult(remote_id="fake/issue#123")


class TestWorkerConfigIsolation:
    """Verifies phase2_worker does not mutate global cached configuration."""

    def test_worker_does_not_mutate_cached_config(self, tmp_path):
        reset_config_cache()
        initial_cfg = get_config()
        initial_dry_run = initial_cfg.get("dispatch", {}).get("dry_run", True)
        initial_primary = initial_cfg.get("classification", {}).get("primary", "jev")

        db_file = tmp_path / "worker_test.db"
        db = TriageDatabase(db_path=str(db_file))

        # Run worker with overrides: dry_run=not initial_dry_run, offline=True
        run_worker_once(
            db=db,
            worker_id="test_worker_iso",
            dry_run=not initial_dry_run,
            offline=True,
        )

        # Global cached configuration must remain strictly unchanged
        cached_cfg = get_config()
        assert cached_cfg["dispatch"]["dry_run"] == initial_dry_run
        assert cached_cfg["classification"]["primary"] == initial_primary


class TestDatabaseJobCasGuard:
    """Verifies finish_p2_job compare-and-swap (CAS) worker_id protection."""

    def test_finish_p2_job_cas_prevents_stale_worker_overwrite(self, tmp_path):
        db_file = tmp_path / "cas_test.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_cas_01"
        db.check_and_acquire(email_id, "th-cas", "<msg-cas@test.com>", "u@test.com")
        db.mark_done(email_id, "gatekeeper_approved", "Sub", "Body")
        db.sync_p2_intake()

        # Worker A claims job
        claimed = db.claim_p2_jobs(worker_id="worker_a", batch_size=1)
        assert len(claimed) == 1
        assert claimed[0]["email_id"] == email_id

        # Job timed out and crash reaper reset or Worker B reclaimed it
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE p2_jobs SET worker_id = 'worker_b' WHERE email_id = ?",
                (email_id,),
            )

        # Worker A attempts to finalize job with worker_id="worker_a"
        with pytest.raises(PersistenceError) as exc_info:
            db.finish_p2_job(
                email_id=email_id,
                state="done",
                worker_id="worker_a",
            )
        assert "worker" in str(exc_info.value).lower() or "conflict" in str(exc_info.value).lower()

        # Job in database must still be owned by worker_b and not marked done
        job = db.get_p2_job(email_id)
        assert job["worker_id"] == "worker_b"
        assert job["state"] == "claimed"

    def test_finish_p2_job_cas_succeeds_with_matching_worker(self, tmp_path):
        db_file = tmp_path / "cas_test_ok.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_cas_02"
        db.check_and_acquire(email_id, "th-cas-2", "<msg-cas2@test.com>", "u@test.com")
        db.mark_done(email_id, "gatekeeper_approved", "Sub", "Body")
        db.sync_p2_intake()

        claimed = db.claim_p2_jobs(worker_id="worker_correct", batch_size=1)
        assert len(claimed) == 1

        db.finish_p2_job(
            email_id=email_id,
            state="done",
            worker_id="worker_correct",
        )
        job = db.get_p2_job(email_id)
        assert job["state"] == "done"


class TestClassifierEmptyTextFailClosed:
    """Verifies classifier_node fails closed when masked text is empty or whitespace."""

    def test_empty_masked_subject_fails_closed(self):
        mock_client = MagicMock()
        state: TriageState = {
            "email_id": "em_empty_sub",
            "masked_subject": "",
            "masked_body": "Normal body with content",
            "routing_status": "gatekeeper_approved",
        }
        res = classifier_node(state, client=mock_client)
        assert res["classification"].confidence == 0.0
        assert res["classification"].category == "Other"
        assert res["p2_classifier_used"] == "offline_heuristic"
        assert mock_client.classify.call_count == 0

    def test_whitespace_masked_subject_fails_closed(self):
        mock_client = MagicMock()
        state: TriageState = {
            "email_id": "em_ws_sub",
            "masked_subject": "    \t\n  ",
            "masked_body": "Normal body with content",
            "routing_status": "gatekeeper_approved",
        }
        res = classifier_node(state, client=mock_client)
        assert res["classification"].confidence == 0.0
        assert res["classification"].category == "Other"
        assert mock_client.classify.call_count == 0

    def test_empty_masked_body_fails_closed(self):
        mock_client = MagicMock()
        state: TriageState = {
            "email_id": "em_empty_body",
            "masked_subject": "Valid Subject",
            "masked_body": "",
            "routing_status": "gatekeeper_approved",
        }
        res = classifier_node(state, client=mock_client)
        assert res["classification"].confidence == 0.0
        assert res["classification"].category == "Other"
        assert mock_client.classify.call_count == 0

    def test_whitespace_masked_body_fails_closed(self):
        mock_client = MagicMock()
        state: TriageState = {
            "email_id": "em_ws_body",
            "masked_subject": "Valid Subject",
            "masked_body": " \n\r\t ",
            "routing_status": "gatekeeper_approved",
        }
        res = classifier_node(state, client=mock_client)
        assert res["classification"].confidence == 0.0
        assert res["classification"].category == "Other"
        assert mock_client.classify.call_count == 0


def insert_test_email(
    db: TriageDatabase,
    email_id: str,
    category: str = "Bug Report",
    priority: str = "Medium",
    hitl_status: str = "approved",
) -> None:
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
                "dev@example.com",
                "Database pool exhausted",
                "Backend cannot connect to db",
                "gatekeeper_approved",
                "done",
                category,
                priority,
                "Neutral",
                "Calm",
                "Summary",
                "Engineering",
                0.95,
                "jev",
                hitl_status,
                "2026-10-28 10:00:00",
                "2026-10-28 10:00:00",
            ),
        )


class TestCircuitBreakerSingleProbe:
    """Verifies that in half-open state after cooldown, exactly one trial probe is allowed."""

    def test_circuit_breaker_permits_only_single_probe_during_cooldown(self, tmp_path):
        db_file = tmp_path / "cb_probe.db"
        db = TriageDatabase(db_path=str(db_file))

        now_utc = datetime.now(UTC)
        cfg = copy.deepcopy(get_config())
        cfg["dispatch"]["dry_run"] = False
        cfg["destinations"]["github"]["enabled"] = True
        cfg["destinations"]["github"]["circuit_breaker"]["failure_threshold"] = 2
        cfg["destinations"]["github"]["circuit_breaker"]["cooldown_seconds"] = 100

        # Seed 2 failures in the last 10 seconds
        recent_failure_time = (now_utc - timedelta(seconds=10)).isoformat()
        for i in range(2):
            eid = f"em_cb_fail_{i}"
            insert_test_email(db, eid)
            r, _ = db.begin_dispatch(eid, "github", "create_issue", "live")
            db.record_dispatch_attempt(r["id"])
            db.finish_dispatch(r["id"], "failed", reason="timeout")
            with db.get_connection() as conn:
                conn.execute(
                    "UPDATE p2_dispatch_log SET updated_at = ? WHERE id = ?",
                    (recent_failure_time, r["id"]),
                )

        fake_adapter = FakeAdapter("github")
        adapters = {"github": fake_adapter}

        # Advance past cooldown window (150s later)
        future_time = now_utc + timedelta(seconds=150)

        # Job 1 is an active in-flight trial probe (state='pending')
        insert_test_email(db, "em_probe_1")
        r1, _ = db.begin_dispatch("em_probe_1", "github", "create_issue", "live")
        db.record_dispatch_attempt(r1["id"])

        # While Job 1 is probing, Job 2 arrives past cooldown.
        # It must NOT also probe; it must be deferred as circuit_open.
        insert_test_email(db, "em_probe_2")
        res2 = dispatcher_node(
            {"email_id": "em_probe_2"},
            db=db,
            config=cfg,
            adapters=adapters,
            now=lambda: future_time,
        )
        assert res2["p2_status"] == "deferred"
        assert res2["dispatch_results"][0]["reason"] == "circuit_open"
        assert len(fake_adapter.calls) == 0  # No live call was made for Job 2!

    def test_circuit_breaker_recovers_after_cooldown_and_deferral(self, tmp_path):
        """Verifies that rows deferred during cooldown do not prevent trial probe after cooldown."""
        db_file = tmp_path / "cb_recovery.db"
        db = TriageDatabase(db_path=str(db_file))

        now_utc = datetime.now(UTC)
        cfg = copy.deepcopy(get_config())
        cfg["dispatch"]["dry_run"] = False
        cfg["destinations"]["github"]["enabled"] = True
        cfg["destinations"]["github"]["circuit_breaker"]["failure_threshold"] = 2
        cfg["destinations"]["github"]["circuit_breaker"]["cooldown_seconds"] = 100

        # Seed 2 failures at T=0
        recent_failure_time = now_utc.isoformat()
        for i in range(2):
            eid = f"em_fail_{i}"
            insert_test_email(db, eid)
            r, _ = db.begin_dispatch(eid, "github", "create_issue", "live")
            db.record_dispatch_attempt(r["id"])
            db.finish_dispatch(r["id"], "failed", reason="timeout")
            with db.get_connection() as conn:
                conn.execute(
                    "UPDATE p2_dispatch_log SET updated_at = ? WHERE id = ?",
                    (recent_failure_time, r["id"]),
                )

        # At T=50s (during cooldown), Email A arrives and is deferred
        time_50s = now_utc + timedelta(seconds=50)
        insert_test_email(db, "em_deferred_a")
        res_a = dispatcher_node(
            {"email_id": "em_deferred_a"},
            db=db,
            config=cfg,
            adapters={"github": FakeAdapter("github")},
            now=lambda: time_50s,
        )
        assert res_a["p2_status"] == "deferred"

        # At T=150s (PAST cooldown 100s), Email B arrives.
        # It must NOT be deferred by Email A's row; it must be permitted to probe!
        time_150s = now_utc + timedelta(seconds=150)
        fake_adapter = FakeAdapter("github")
        insert_test_email(db, "em_probe_b")
        res_b = dispatcher_node(
            {"email_id": "em_probe_b"},
            db=db,
            config=cfg,
            adapters={"github": fake_adapter},
            now=lambda: time_150s,
        )
        assert res_b["p2_status"] == "dispatched"
        assert len(fake_adapter.calls) == 1
        assert res_b["dispatch_results"][0]["ledger_state"] == "confirmed"
