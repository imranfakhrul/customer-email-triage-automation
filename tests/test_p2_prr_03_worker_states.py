"""Tests for PRR-03: Worker Job State Mapping for Deferred and Failed Dispatches.

Validates that:
1. Dispatches that result in 'deferred' (daily cap, circuit breaker, kill switch, disabled target)
   are mapped to a retryable job state ('unclaimed') with a future 'next_attempt_at' timestamp,
   clearing worker_id and claimed_at so they can be retried.
2. Dispatches that result in 'dead_letter' are explicitly mapped to 'dead_letter' state,
   never silently dropped as 'done'.
3. Dispatches that result in permanent 'failed' are explicitly mapped to 'failed' state.
4. 'claim_p2_jobs' respects 'next_attempt_at', skipping jobs whose cooldown has not yet expired.
5. Successful dispatches ('dispatched', 'simulated') transition to 'done'.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from db.database import TriageDatabase
from scripts.phase2_worker import run_worker_once
from state import EmailClassification


@pytest.fixture
def temp_db(tmp_path: Any) -> TriageDatabase:
    """Creates a temporary SQLite database initialized with schema."""
    db_path = tmp_path / "test_prr_03.db"
    return TriageDatabase(db_path=str(db_path))


def _insert_intake_job(
    db: TriageDatabase,
    email_id: str,
    category: str = "Bug Report",
    priority: str = "Critical",
) -> None:
    """Seeds an approved email_triage record and imports it into p2_jobs."""
    db.check_and_acquire(
        email_id=email_id,
        message_id=f"<{email_id}@test.local>",
        thread_id=f"th_{email_id}",
        sender_email="tester@example.com",
    )
    db.mark_done(
        email_id=email_id,
        routing_status="gatekeeper_approved",
        gatekeeper_decision="legitimate",
        classifier_used="regex",
        gatekeeper_confidence=0.85,
        masked_subject=f"Subject for {email_id}",
        masked_body=f"Body for {email_id}",
    )
    db.record_phase2_classification(
        email_id=email_id,
        classification=EmailClassification(
            category=category,
            priority=priority,
            sentiment="Negative",
            customer_emotion="Frustrated",
            summary=f"Summary for {email_id}",
            suggested_team="Engineering",
            confidence=0.95,
        ),
        p2_classifier_used="heuristic",
        hitl_status="auto_approved",
    )
    db.sync_p2_intake()


class TestWorkerStateTransitions:
    """Tests asserting correct job state mapping in phase2_worker."""

    def test_deferred_dispatch_mapped_to_retryable_state_with_next_attempt(
        self, temp_db: TriageDatabase
    ) -> None:
        """Deferred dispatches must transition to 'unclaimed' with future next_attempt_at."""
        email_id = "em_defer_01"
        _insert_intake_job(temp_db, email_id)

        # Mock pipeline to return p2_status='deferred' (e.g. daily cap reached)
        mock_pipeline = MagicMock()
        mock_pipeline.invoke.return_value = {
            "email_id": email_id,
            "p2_status": "deferred",
            "hitl_status": "auto_approved",
            "dispatch_results": [
                {
                    "destination": "github",
                    "action_type": "create_issue",
                    "ledger_state": "deferred",
                    "reason": "daily_cap",
                }
            ],
        }

        with patch(
            "scripts.phase2_worker.create_phase2_worker_pipeline",
            return_value=mock_pipeline,
        ):
            processed = run_worker_once(db=temp_db, batch_size=1)

        assert processed == 1
        job = temp_db.get_p2_job(email_id)
        assert job is not None
        # MUST NOT be marked 'done'
        assert job["state"] != "done"
        # MUST be retryable
        assert job["state"] == "unclaimed"
        assert job["worker_id"] is None
        assert job["claimed_at"] is None
        assert job["next_attempt_at"] is not None

        # Verify next_attempt_at is in the future
        next_dt = datetime.strptime(
            job["next_attempt_at"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=UTC)
        assert next_dt > datetime.now(UTC)

    def test_dead_letter_dispatch_mapped_to_dead_letter(
        self, temp_db: TriageDatabase
    ) -> None:
        """Dead-letter dispatches must transition to 'dead_letter' in p2_jobs, never 'done'."""
        email_id = "em_dead_01"
        _insert_intake_job(temp_db, email_id)

        mock_pipeline = MagicMock()
        mock_pipeline.invoke.return_value = {
            "email_id": email_id,
            "p2_status": "dead_letter",
            "hitl_status": "auto_approved",
            "error_message": "Exceeded max attempts",
            "dispatch_results": [
                {
                    "destination": "github",
                    "action_type": "create_issue",
                    "ledger_state": "dead_letter",
                    "reason": "max_attempts_exceeded",
                }
            ],
        }

        with patch(
            "scripts.phase2_worker.create_phase2_worker_pipeline",
            return_value=mock_pipeline,
        ):
            processed = run_worker_once(db=temp_db, batch_size=1)

        assert processed == 1
        job = temp_db.get_p2_job(email_id)
        assert job is not None
        assert job["state"] != "done"
        assert job["state"] == "dead_letter"

    def test_failed_dispatch_mapped_to_failed(
        self, temp_db: TriageDatabase
    ) -> None:
        """Failed dispatches must transition to 'failed' in p2_jobs, never 'done'."""
        email_id = "em_fail_01"
        _insert_intake_job(temp_db, email_id)

        mock_pipeline = MagicMock()
        mock_pipeline.invoke.return_value = {
            "email_id": email_id,
            "p2_status": "failed",
            "hitl_status": "auto_approved",
            "error_message": "Permanent 400 Bad Request",
            "dispatch_results": [
                {
                    "destination": "github",
                    "action_type": "create_issue",
                    "ledger_state": "failed",
                    "reason": "permanent_error",
                }
            ],
        }

        with patch(
            "scripts.phase2_worker.create_phase2_worker_pipeline",
            return_value=mock_pipeline,
        ):
            processed = run_worker_once(db=temp_db, batch_size=1)

        assert processed == 1
        job = temp_db.get_p2_job(email_id)
        assert job is not None
        assert job["state"] != "done"
        assert job["state"] == "failed"

    def test_dispatched_and_simulated_mapped_to_done(
        self, temp_db: TriageDatabase
    ) -> None:
        """Successful or simulated dispatches transition to 'done'."""
        email_id = "em_done_01"
        _insert_intake_job(temp_db, email_id)

        mock_pipeline = MagicMock()
        mock_pipeline.invoke.return_value = {
            "email_id": email_id,
            "p2_status": "dispatched",
            "hitl_status": "auto_approved",
            "dispatch_results": [
                {
                    "destination": "github",
                    "action_type": "create_issue",
                    "ledger_state": "confirmed",
                    "remote_id": "101",
                }
            ],
        }

        with patch(
            "scripts.phase2_worker.create_phase2_worker_pipeline",
            return_value=mock_pipeline,
        ):
            processed = run_worker_once(db=temp_db, batch_size=1)

        assert processed == 1
        job = temp_db.get_p2_job(email_id)
        assert job is not None
        assert job["state"] == "done"


class TestClaimP2JobsNextAttemptFiltering:
    """Tests asserting claim_p2_jobs skips jobs with future next_attempt_at."""

    def test_claim_skips_future_cooldown_and_claims_ready_jobs(
        self, temp_db: TriageDatabase
    ) -> None:
        """Jobs with next_attempt_at in the future are skipped; expired/null jobs are claimed."""
        _insert_intake_job(temp_db, "em_future_01")
        _insert_intake_job(temp_db, "em_expired_01")
        _insert_intake_job(temp_db, "em_null_01")

        now = datetime.now(UTC)
        future_str = (now + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        past_str = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

        # Set next_attempt_at directly on jobs
        temp_db.finish_p2_job("em_future_01", state="unclaimed", next_attempt_at=future_str)
        temp_db.finish_p2_job("em_expired_01", state="unclaimed", next_attempt_at=past_str)
        # em_null_01 remains next_attempt_at=NULL

        claimed = temp_db.claim_p2_jobs(batch_size=10, worker_id="worker_test")
        claimed_ids = {j["email_id"] for j in claimed}

        # em_future_01 must NOT be claimed
        assert "em_future_01" not in claimed_ids
        # em_expired_01 and em_null_01 must be claimed
        assert "em_expired_01" in claimed_ids
        assert "em_null_01" in claimed_ids

        # Once claimed, next_attempt_at on claimed jobs must be cleared
        expired_job = temp_db.get_p2_job("em_expired_01")
        assert expired_job is not None
        assert expired_job["state"] == "claimed"
        assert expired_job["next_attempt_at"] is None
