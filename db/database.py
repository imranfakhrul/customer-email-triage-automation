"""SQLite idempotency store and triage database management.

Maintains a three-state (`processing`, `done`, `failed`) lifecycle for
each email, handles stale lock recovery (>10 minutes by default), and
tracks active email threads to allow thread-level continuity.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple
from utils.config import load_config


class TriageDatabase:
    """Manages the SQLite database for idempotency, retry tracking, and state persistence."""

    def __init__(self, db_path: Optional[str] = None):
        """Initializes database path and creates schema if not present.

        Args:
            db_path: Path to the SQLite database file. If None, loaded from config.yaml.
        """
        if db_path is None:
            try:
                config = load_config()
                db_path = config.get("system", {}).get("database_path", "triage.db")
            except Exception:
                db_path = "triage.db"

        self.db_path = db_path
        parent = Path(self.db_path).parent
        if str(parent) != "." and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a managed sqlite3 connection with WAL mode and row factory."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes the email_triage table and indices."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS email_triage (
                    email_id TEXT PRIMARY KEY,
                    message_id TEXT,
                    thread_id TEXT,
                    sender_email TEXT,
                    status TEXT NOT NULL CHECK(status IN ('processing', 'done', 'failed')),
                    retry_count INTEGER DEFAULT 0,
                    routing_status TEXT,
                    dispatch_target TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_thread_id ON email_triage(thread_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON email_triage(status);"
            )

    def get_record(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a triage record by email_id.

        Args:
            email_id: Unique identifier of the incoming email.

        Returns:
            Dict representing the record, or None if not found.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_active_thread_records(
        self, thread_id: str, exclude_email_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves completed records belonging to a thread.

        Args:
            thread_id: Thread conversation ID.
            exclude_email_id: Optional email_id to exclude (e.g., current message).

        Returns:
            List of completed records for this thread.
        """
        if not thread_id:
            return []

        with self.get_connection() as conn:
            if exclude_email_id:
                cursor = conn.execute(
                    """
                    SELECT * FROM email_triage
                    WHERE thread_id = ? AND email_id != ? AND status = 'done'
                    ORDER BY updated_at DESC
                    """,
                    (thread_id, exclude_email_id),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM email_triage
                    WHERE thread_id = ? AND status = 'done'
                    ORDER BY updated_at DESC
                    """,
                    (thread_id,),
                )
            return [dict(r) for r in cursor.fetchall()]

    def is_active_thread(
        self, thread_id: str, exclude_email_id: Optional[str] = None
    ) -> bool:
        """Checks if a thread already has successfully completed triage records.

        Args:
            thread_id: Thread conversation ID.
            exclude_email_id: Optional email_id to exclude.

        Returns:
            True if previous completed emails exist in this thread, False otherwise.
        """
        records = self.get_active_thread_records(thread_id, exclude_email_id)
        return len(records) > 0

    def check_and_acquire(
        self,
        email_id: str,
        thread_id: str = "",
        message_id: str = "",
        sender_email: str = "",
        stale_minutes: int = 10,
        max_retries: int = 3,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Performs idempotency check and attempts to acquire a processing lock.

        Handles new emails, duplicate/completed messages, stale locks (> stale_minutes),
        and retry attempts for failed emails.

        Args:
            email_id: Unique message/email identifier.
            thread_id: Thread conversation ID.
            message_id: Original message ID from headers.
            sender_email: Sender's email address.
            stale_minutes: Number of minutes before an in-progress record is considered stale.
            max_retries: Maximum allowable retry attempts before permanent failure.

        Returns:
            Tuple of:
            - allowed (bool): True if processing should proceed; False if it should be skipped.
            - outcome (str): Outcome description:
                * 'acquired_new': Fresh email successfully locked.
                * 'recovered_stale': Stale processing lock recovered.
                * 'retry_failed': Retry attempt granted for a previously failed email.
                * 'already_completed': Email already completed ('done').
                * 'in_flight': Currently locked and active under another worker.
                * 'max_retries_exceeded': Retry limit reached for stale/failed email.
            - record (Dict[str, Any]): Record snapshot.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
            )
            row = cursor.fetchone()

            # Case 1: Brand new email
            if row is None:
                conn.execute(
                    """
                    INSERT INTO email_triage (
                        email_id, message_id, thread_id, sender_email,
                        status, retry_count, routing_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'processing', 0, 'processing', ?, ?)
                    """,
                    (email_id, message_id, thread_id, sender_email, now_iso, now_iso),
                )
                record = {
                    "email_id": email_id,
                    "message_id": message_id,
                    "thread_id": thread_id,
                    "sender_email": sender_email,
                    "status": "processing",
                    "retry_count": 0,
                    "routing_status": "processing",
                    "dispatch_target": None,
                    "error_message": None,
                    "created_at": now_iso,
                    "updated_at": now_iso,
                }
                return True, "acquired_new", record

            record = dict(row)
            current_status = record["status"]
            retry_count = record.get("retry_count", 0)

            # Case 2: Already completed
            if current_status == "done":
                return False, "already_completed", record

            # Parse updated_at timestamp to evaluate staleness
            updated_str = record["updated_at"]
            try:
                updated_at = datetime.fromisoformat(updated_str)
                if updated_at.tzinfo is None:
                    updated_at = updated_at.replace(tzinfo=timezone.utc)
            except Exception:
                updated_at = now

            elapsed_minutes = (now - updated_at).total_seconds() / 60.0

            # Case 3: In-flight processing
            if current_status == "processing":
                if elapsed_minutes > stale_minutes:
                    # Stale lock: attempt recovery
                    if retry_count < max_retries:
                        new_retries = retry_count + 1
                        conn.execute(
                            """
                            UPDATE email_triage
                            SET retry_count = ?, updated_at = ?, routing_status = 'stale_recovery'
                            WHERE email_id = ?
                            """,
                            (new_retries, now_iso, email_id),
                        )
                        record["retry_count"] = new_retries
                        record["routing_status"] = "stale_recovery"
                        record["updated_at"] = now_iso
                        return True, "recovered_stale", record
                    else:
                        conn.execute(
                            """
                            UPDATE email_triage
                            SET status = 'failed', error_message = 'Max retries exceeded on stale lock recovery', updated_at = ?
                            WHERE email_id = ?
                            """,
                            (now_iso, email_id),
                        )
                        record["status"] = "failed"
                        record["error_message"] = (
                            "Max retries exceeded on stale lock recovery"
                        )
                        record["updated_at"] = now_iso
                        return False, "max_retries_exceeded", record
                else:
                    # In-flight and active
                    return False, "in_flight", record

            # Case 4: Previously failed
            if current_status == "failed":
                if retry_count < max_retries:
                    new_retries = retry_count + 1
                    conn.execute(
                        """
                        UPDATE email_triage
                        SET status = 'processing', retry_count = ?, updated_at = ?, routing_status = 'retry'
                        WHERE email_id = ?
                        """,
                        (new_retries, now_iso, email_id),
                    )
                    record["status"] = "processing"
                    record["retry_count"] = new_retries
                    record["routing_status"] = "retry"
                    record["updated_at"] = now_iso
                    return True, "retry_failed", record
                else:
                    return False, "max_retries_exceeded", record

            return False, "unknown_status", record

    def mark_processing(self, email_id: str, retry_count: Optional[int] = None) -> None:
        """Sets status to processing and refreshes updated_at."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            if retry_count is not None:
                conn.execute(
                    """
                    UPDATE email_triage
                    SET status = 'processing', retry_count = ?, updated_at = ?
                    WHERE email_id = ?
                    """,
                    (retry_count, now_iso, email_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE email_triage
                    SET status = 'processing', updated_at = ?
                    WHERE email_id = ?
                    """,
                    (now_iso, email_id),
                )

    def mark_done(
        self,
        email_id: str,
        routing_status: str = "routed",
        dispatch_target: Optional[str] = None,
    ) -> None:
        """Sets status to done and updates routing status/target."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE email_triage
                SET status = 'done', routing_status = ?, dispatch_target = ?, updated_at = ?
                WHERE email_id = ?
                """,
                (routing_status, dispatch_target, now_iso, email_id),
            )

    def mark_failed(
        self,
        email_id: str,
        error_message: str = "",
        routing_status: str = "failed",
    ) -> None:
        """Sets status to failed and logs error message."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE email_triage
                SET status = 'failed', error_message = ?, routing_status = ?, updated_at = ?
                WHERE email_id = ?
                """,
                (error_message, routing_status, now_iso, email_id),
            )

    def clear_all(self) -> None:
        """Clears all records in the email_triage table (used for testing)."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM email_triage;")
