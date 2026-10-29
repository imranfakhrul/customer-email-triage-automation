"""Tests for PRR-10: Operator CLI reconciliation for unknown-outcome outbox rows."""

import os
import subprocess
import sys
from pathlib import Path

from db.database import TriageDatabase

CLI_PATH = str(Path(__file__).resolve().parent.parent / "scripts" / "hitl_cli.py")


def _run_cli(args: list[str], db_path: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["DATABASE_PATH"] = str(db_path)
    return subprocess.run(  # noqa: S603
        [sys.executable, CLI_PATH, *args],
        capture_output=True,
        text=True,
        env=env,
    )


class TestHitlCliReconcile:
    """Verifies hitl_cli.py reconcile command transitions unknown ledger rows."""

    def test_reconcile_confirmed_success(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_rec_01"
        db.check_and_acquire(email_id, "th-rec", "<msg@test.com>", "user@test.com")
        db.mark_done(email_id, "gatekeeper_approved", "Masked Sub", "Masked Body")

        # Create outbox row in 'unknown' state
        row, acquired = db.begin_dispatch(
            email_id=email_id,
            destination="github",
            action_type="create_issue",
            mode="live",
            payload_sha256="abc123sha",
        )
        assert acquired is True
        db.finish_dispatch(row["id"], state="unknown", reason="timeout_waiting_headers")

        res = _run_cli(
            [
                "reconcile",
                email_id,
                "--destination",
                "github",
                "--status",
                "confirmed",
                "--by",
                "operator_alice",
                "--remote-id",
                "acme/repo#99",
            ],
            db_file,
        )
        assert res.returncode == 0, f"CLI stderr: {res.stderr}\nstdout: {res.stdout}"
        assert "Successfully reconciled" in res.stdout
        assert "confirmed" in res.stdout

        # Verify database state
        logs = db.get_dispatch_log(email_id)
        assert len(logs) == 1
        assert logs[0]["state"] == "confirmed"
        assert logs[0]["remote_id"] == "acme/repo#99"
        assert logs[0]["resolved_by"] == "operator_alice"

    def test_reconcile_failed_success(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_rec_02"
        db.check_and_acquire(email_id, "th-rec-02", "<msg02@test.com>", "user@test.com")
        db.mark_done(email_id, "gatekeeper_approved", "Masked Sub", "Masked Body")

        row, acquired = db.begin_dispatch(
            email_id=email_id,
            destination="freescout",
            action_type="create_ticket",
            mode="live",
            payload_sha256="abc456sha",
        )
        assert acquired is True
        db.finish_dispatch(row["id"], state="unknown", reason="connection_reset")

        res = _run_cli(
            [
                "reconcile",
                email_id,
                "--destination",
                "freescout",
                "--status",
                "failed",
                "--by",
                "operator_bob",
            ],
            db_file,
        )
        assert res.returncode == 0, f"CLI stderr: {res.stderr}\nstdout: {res.stdout}"
        assert "Successfully reconciled" in res.stdout
        assert "failed" in res.stdout

        # Verify database state
        logs = db.get_dispatch_log(email_id)
        assert len(logs) == 1
        assert logs[0]["state"] == "failed"
        assert logs[0]["resolved_by"] == "operator_bob"

    def test_reconcile_confirmed_missing_remote_id_exits_2(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        res = _run_cli(
            [
                "reconcile",
                "em_missing_id",
                "--destination",
                "github",
                "--status",
                "confirmed",
                "--by",
                "operator_alice",
            ],
            db_file,
        )
        assert res.returncode == 2
        assert "--remote-id" in res.stderr

    def test_reconcile_missing_by_exits_2(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        res = _run_cli(
            [
                "reconcile",
                "em_missing_by",
                "--destination",
                "github",
                "--status",
                "failed",
            ],
            db_file,
        )
        assert res.returncode == 2

    def test_reconcile_row_not_found_exits_3(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        TriageDatabase(db_path=str(db_file))

        res = _run_cli(
            [
                "reconcile",
                "em_nonexistent",
                "--destination",
                "github",
                "--status",
                "failed",
                "--by",
                "operator_alice",
            ],
            db_file,
        )
        assert res.returncode == 3
        assert "not found" in res.stderr.lower()

    def test_reconcile_row_already_confirmed_exits_3(self, tmp_path):
        db_file = tmp_path / "test_reconcile.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_already_conf"
        db.check_and_acquire(email_id, "th-conf", "<msg@test.com>", "user@test.com")
        db.mark_done(email_id, "gatekeeper_approved", "Masked Sub", "Masked Body")

        row, _ = db.begin_dispatch(
            email_id=email_id,
            destination="github",
            action_type="create_issue",
            mode="live",
            payload_sha256="abc789sha",
        )
        db.finish_dispatch(row["id"], state="confirmed", remote_id="owner/repo#100")

        res = _run_cli(
            [
                "reconcile",
                email_id,
                "--destination",
                "github",
                "--status",
                "confirmed",
                "--by",
                "operator_alice",
                "--remote-id",
                "owner/repo#101",
            ],
            db_file,
        )
        assert res.returncode == 3
        assert "not found" in res.stderr.lower() or "state" in res.stderr.lower()

    def test_reconcile_unblocks_hitl_and_allows_pipeline_to_finish(self, tmp_path):
        """Verifies that reconciling an unknown dispatch unblocks the HITL review loop."""
        db_file = tmp_path / "test_reconcile.db"
        db = TriageDatabase(db_path=str(db_file))

        email_id = "em_loop_test"
        db.check_and_acquire(email_id, "th-loop", "<msg@loop.com>", "customer@acme.com")
        db.mark_done(email_id, "gatekeeper_approved", "Timeout issue", "Body text")
        db.record_phase2_classification(
            email_id=email_id,
            classification={
                "category": "Bug Report",
                "priority": "High",
                "sentiment": "Neutral",
                "customer_emotion": "Calm",
                "summary": "Timeout issue",
                "suggested_team": "Engineering",
                "confidence": 0.95,
            },
            hitl_status="approved",
            hitl_reason="Normal bug report",
        )

        # Dispatcher created an unknown outbox row and diverted email to HITL
        row, _ = db.begin_dispatch(
            email_id=email_id,
            destination="github",
            action_type="create_issue",
            mode="live",
            payload_sha256="sha_loop",
        )
        db.finish_dispatch(row["id"], state="unknown", reason="outcome_unknown")
        db.divert_to_hitl(email_id, "dispatch_outcome_unknown")

        # Verify diverted to pending
        rec = db.get_record(email_id)
        assert rec["hitl_status"] == "pending"
        assert rec["hitl_reason"] == "dispatch_outcome_unknown"

        # Operator reconciles via CLI
        res = _run_cli(
            [
                "reconcile",
                email_id,
                "--destination",
                "github",
                "--status",
                "confirmed",
                "--by",
                "lead_dev",
                "--remote-id",
                "github:acme/bugs#555",
            ],
            db_file,
        )
        assert res.returncode == 0

        # Ledger row is confirmed and HITL is unblocked (approved)
        logs = db.get_dispatch_log(email_id)
        assert logs[0]["state"] == "confirmed"
        assert logs[0]["remote_id"] == "github:acme/bugs#555"

        updated_rec = db.get_record(email_id)
        assert updated_rec["hitl_status"] == "approved"
