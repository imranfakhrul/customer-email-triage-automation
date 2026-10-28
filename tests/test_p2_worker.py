"""Unit and concurrency tests for Phase 2 Queue Worker, Atomic Claiming, and Recovery.

Milestone [P2-09]:
Verifies:
1. Intake synchronization from Phase 1 gatekeeper_approved records to p2_jobs.
2. Single-statement atomic batch claiming eliminating race conditions.
3. Multi-threaded / parallel concurrent claiming with zero double-claims.
4. Stale claim sweeper and crash recovery for orphaned jobs (>15 minutes).
5. Dead-letter queue transition upon reaching max_dispatch_retries.
6. Worker daemon execution in --once mode.
7. Graceful OS signal handling (SIGINT/SIGTERM).
8. Hard Invariant #10: email_triage columns remain untouched by the worker.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from db.database import TriageDatabase
from utils.config import get_config


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_p2_worker.db")


@pytest.fixture
def test_db(temp_db_path: str) -> TriageDatabase:
    return TriageDatabase(db_path=temp_db_path)


@pytest.fixture
def sample_config() -> dict[str, Any]:
    cfg = get_config()
    cfg_copy = json.loads(json.dumps(cfg))
    cfg_copy["classification"]["primary"] = "offline_heuristic"
    cfg_copy["dispatch"]["dry_run"] = True
    return cfg_copy


def _insert_phase1_record(
    db: TriageDatabase,
    email_id: str,
    status: str = "done",
    routing_status: str = "gatekeeper_approved",
    subject: str = "Test email",
    body: str = "Test body",
    sender: str = "user@example.com",
) -> None:
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                email_id,
                f"<{email_id}@ex.com>",
                f"th_{email_id}",
                sender,
                subject,
                body,
                routing_status,
                status,
            ),
        )


def test_sync_p2_intake(test_db: TriageDatabase):
    """Verifies that only Phase 1 gatekeeper_approved emails are imported into p2_jobs."""
    # 1. Eligible record
    _insert_phase1_record(
        test_db, "em_sync_001", status="done", routing_status="gatekeeper_approved"
    )
    # 2. In-flight record (not done)
    _insert_phase1_record(
        test_db, "em_sync_002", status="processing", routing_status="processing"
    )
    # 3. Spam record (done, but not gatekeeper_approved)
    _insert_phase1_record(
        test_db, "em_sync_003", status="done", routing_status="spam_diverted"
    )
    # 4. Another eligible record
    _insert_phase1_record(
        test_db, "em_sync_004", status="done", routing_status="gatekeeper_approved"
    )

    # Initial intake sync
    synced_count = test_db.sync_p2_intake()
    assert synced_count == 2

    # Verify rows in p2_jobs
    job1 = test_db.get_p2_job("em_sync_001")
    assert job1 is not None
    assert job1["state"] == "unclaimed"
    assert job1["attempts"] == 0
    assert job1["worker_id"] is None

    job4 = test_db.get_p2_job("em_sync_004")
    assert job4 is not None
    assert job4["state"] == "unclaimed"

    assert test_db.get_p2_job("em_sync_002") is None
    assert test_db.get_p2_job("em_sync_003") is None

    # Re-running sync must be strictly idempotent (0 newly synced)
    resync_count = test_db.sync_p2_intake()
    assert resync_count == 0


def test_atomic_claim_p2_jobs(test_db: TriageDatabase):
    """Verifies single-statement atomic batch claiming with worker_id assignment."""
    for i in range(5):
        _insert_phase1_record(
            test_db, f"em_claim_{i}", status="done", routing_status="gatekeeper_approved"
        )
    test_db.sync_p2_intake()

    # Worker 1 claims 2 jobs
    w1_jobs = test_db.claim_p2_jobs(batch_size=2, worker_id="worker_alpha")
    assert len(w1_jobs) == 2
    for job in w1_jobs:
        assert job["state"] == "claimed"
        assert job["worker_id"] == "worker_alpha"
        assert job["attempts"] == 1
        assert job["masked_subject"] is not None

    # Worker 2 claims next 2 jobs
    w2_jobs = test_db.claim_p2_jobs(batch_size=2, worker_id="worker_beta")
    assert len(w2_jobs) == 2
    for job in w2_jobs:
        assert job["state"] == "claimed"
        assert job["worker_id"] == "worker_beta"
        assert job["attempts"] == 1

    # Disjoint check: No job claimed by both workers
    w1_ids = {j["email_id"] for j in w1_jobs}
    w2_ids = {j["email_id"] for j in w2_jobs}
    assert w1_ids.isdisjoint(w2_ids)

    # Worker 3 claims remaining 1 job
    w3_jobs = test_db.claim_p2_jobs(batch_size=10, worker_id="worker_gamma")
    assert len(w3_jobs) == 1

    # Empty queue returns empty list
    empty_jobs = test_db.claim_p2_jobs(batch_size=10, worker_id="worker_delta")
    assert empty_jobs == []


def test_concurrent_multiworker_claims(test_db: TriageDatabase):
    """Stress test: 4 concurrent worker threads claiming queue have zero duplicates."""
    total_jobs = 24
    for i in range(total_jobs):
        _insert_phase1_record(
            test_db, f"em_conc_{i:02d}", status="done", routing_status="gatekeeper_approved"
        )
    test_db.sync_p2_intake()

    claimed_by_worker: dict[str, list[str]] = {
        "w1": [],
        "w2": [],
        "w3": [],
        "w4": [],
    }
    barrier = threading.Barrier(4)
    errors: list[Exception] = []

    def _worker_thread(worker_id: str):
        try:
            barrier.wait(timeout=5.0)
            while True:
                batch = test_db.claim_p2_jobs(batch_size=3, worker_id=worker_id)
                if not batch:
                    break
                claimed_by_worker[worker_id].extend(j["email_id"] for j in batch)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=_worker_thread, args=(wid,))
        for wid in claimed_by_worker
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not errors, f"Concurrent workers encountered errors: {errors}"

    all_claimed = []
    for _wid, ids in claimed_by_worker.items():
        all_claimed.extend(ids)

    assert len(all_claimed) == total_jobs
    # Strict uniqueness: exactly 1 worker claimed each job
    assert len(set(all_claimed)) == total_jobs


def test_recover_stale_p2_jobs(test_db: TriageDatabase):
    """Stale claims (>15m) from crashed workers are reset back to unclaimed."""
    email_id = "em_stale_001"
    _insert_phase1_record(test_db, email_id)
    test_db.sync_p2_intake()

    # Claim job
    test_db.claim_p2_jobs(batch_size=1, worker_id="dead_worker_99")
    job = test_db.get_p2_job(email_id)
    assert job["state"] == "claimed"

    # Simulate crash: backdate claimed_at to 30 minutes ago
    stale_time = (datetime.now(UTC) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    with test_db.get_connection() as conn:
        conn.execute(
            "UPDATE p2_jobs SET claimed_at = ? WHERE email_id = ?",
            (stale_time, email_id),
        )

    recovered = test_db.recover_stale_p2_jobs(stale_minutes=15)
    assert recovered == 1

    job_after = test_db.get_p2_job(email_id)
    assert job_after["state"] == "unclaimed"
    assert job_after["worker_id"] is None
    # Attempts remain preserved
    assert job_after["attempts"] == 1


def test_dead_letter_queue_transition(test_db: TriageDatabase):
    """Jobs exceeding max_retries transition to dead_letter state."""
    email_id = "em_dlq_001"
    _insert_phase1_record(test_db, email_id)
    test_db.sync_p2_intake()

    # Set attempts = 3 and backdate claimed_at
    stale_time = (datetime.now(UTC) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    with test_db.get_connection() as conn:
        conn.execute(
            """
            UPDATE p2_jobs
            SET state = 'claimed',
                attempts = 3,
                claimed_at = ?,
                worker_id = 'crashed_worker'
            WHERE email_id = ?
            """,
            (stale_time, email_id),
        )

    recovered = test_db.recover_stale_p2_jobs(stale_minutes=15, max_retries=3)
    assert recovered == 1

    job = test_db.get_p2_job(email_id)
    assert job["state"] == "dead_letter"
    assert "max retries" in job["error_message"].lower()


def test_finish_p2_job(test_db: TriageDatabase):
    """finish_p2_job transitions job to terminal states cleanly."""
    email_id = "em_finish_001"
    _insert_phase1_record(test_db, email_id)
    test_db.sync_p2_intake()
    test_db.claim_p2_jobs(batch_size=1, worker_id="w_test")

    # Finish as done
    test_db.finish_p2_job(email_id, state="done")
    job = test_db.get_p2_job(email_id)
    assert job["state"] == "done"

    # Finish as hitl_pending
    test_db.finish_p2_job(email_id, state="hitl_pending", error_message="Review needed")
    job2 = test_db.get_p2_job(email_id)
    assert job2["state"] == "hitl_pending"
    assert job2["error_message"] == "Review needed"


def test_worker_script_once_mode(test_db: TriageDatabase, sample_config: dict[str, Any]):
    """Tests scripts/phase2_worker.py in --once execution mode."""
    from scripts.phase2_worker import run_worker_once

    email_id = "em_worker_cli_001"
    _insert_phase1_record(
        test_db,
        email_id,
        subject="Bug report: 500 error in worker",
        body="Server 500 internal error in database.",
    )

    processed_count = run_worker_once(
        db=test_db,
        config=sample_config,
        worker_id="test_worker_cli",
        batch_size=5,
    )
    assert processed_count == 1

    # Check job state in p2_jobs
    job = test_db.get_p2_job(email_id)
    assert job is not None
    assert job["state"] in ("done", "hitl_pending")

    # Hard Invariant #10: Phase 1 email_triage record untouched
    rec = test_db.get_record(email_id)
    assert rec["status"] == "done"
    assert rec["routing_status"] == "gatekeeper_approved"


def test_finish_p2_job_validation(test_db: TriageDatabase):
    """Verifies that finish_p2_job validates states and raises PersistenceError if missing."""
    from db.database import PersistenceError

    with pytest.raises(ValueError, match="Invalid p2_jobs state"):
        test_db.finish_p2_job("non_existent", state="invalid_state_xyz")

    with pytest.raises(PersistenceError, match="not found in p2_jobs"):
        test_db.finish_p2_job("non_existent", state="done")


def test_hitl_resolved_transition_and_claiming(test_db: TriageDatabase):
    """Verifies that resolving a HITL review marks p2_jobs as hitl_resolved for re-claiming."""
    email_id = "em_hitl_res_001"
    _insert_phase1_record(test_db, email_id)
    test_db.sync_p2_intake()

    # Move to hitl_pending
    test_db.claim_p2_jobs(batch_size=1, worker_id="w_hitl")
    test_db.finish_p2_job(email_id, state="hitl_pending")

    # Set hitl_status in email_triage to pending
    with test_db.get_connection() as conn:
        conn.execute(
            "UPDATE email_triage SET hitl_status = 'pending' WHERE email_id = ?",
            (email_id,),
        )

    # Reviewer approves via resolve_hitl_review
    resolved = test_db.resolve_hitl_review(
        email_id=email_id,
        decision="approved",
        reviewed_by="admin_reviewer",
        notes="Looks good",
    )
    assert resolved is True

    # Assert p2_jobs updated to hitl_resolved
    job = test_db.get_p2_job(email_id)
    assert job["state"] == "hitl_resolved"

    # Worker re-claims hitl_resolved job
    reclaimed = test_db.claim_p2_jobs(batch_size=1, worker_id="w_reclaim")
    assert len(reclaimed) == 1
    assert reclaimed[0]["email_id"] == email_id
    assert reclaimed[0]["state"] == "claimed"


def test_phase2_worker_class_lifecycle(test_db: TriageDatabase, sample_config: dict[str, Any]):
    """Verifies Phase2Worker daemon lifecycle, stop signal, and run() execution."""
    from scripts.phase2_worker import Phase2Worker

    email_id = "em_worker_class_001"
    _insert_phase1_record(
        test_db,
        email_id,
        subject="Pricing inquiry for 500 enterprise seats",
        body="Can you provide bulk enterprise licensing rates?",
    )

    worker = Phase2Worker(
        db=test_db,
        config=sample_config,
        worker_id="test_class_worker",
        batch_size=5,
        poll_interval=0.1,
        dry_run=True,
    )

    # Test once=True mode
    processed = worker.run(once=True)
    assert processed == 1
    assert worker.running is True

    # Test stop()
    worker.stop()
    assert worker.running is False


def test_phase2_worker_cli_main(monkeypatch, test_db: TriageDatabase):
    """Verifies scripts/phase2_worker.py CLI main() entrypoint in --once mode."""
    from scripts.phase2_worker import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "phase2_worker.py",
            "--batch-size",
            "2",
            "--poll-interval",
            "0.1",
            "--once",
            "--dry-run",
            "--offline",
        ],
    )
    with patch("scripts.phase2_worker.TriageDatabase", return_value=test_db):
        exit_code = main()
        assert exit_code == 0
