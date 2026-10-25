"""SQLite idempotency store and triage database management.

Maintains a three-state (`processing`, `done`, `failed`) lifecycle for
each email, handles stale lock recovery (>10 minutes by default), and
tracks active email threads to allow thread-level continuity.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple
from utils.config import load_config


class PersistenceError(Exception):
    """Raised when an attempt to persist a triage record fails (e.g. 0 rows updated)."""
    pass


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
        """Initializes the email_triage table and indices, and migrates schema if needed."""
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
                    updated_at TEXT NOT NULL,
                    masked_subject TEXT,
                    masked_body TEXT,
                    is_active_thread INTEGER,
                    gatekeeper_decision TEXT,
                    gatekeeper_confidence REAL,
                    classifier_used TEXT
                );
                """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_thread_id ON email_triage(thread_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON email_triage(status);"
            )

            # Migration for existing databases: add missing columns safely via ALTER TABLE
            cursor = conn.execute("PRAGMA table_info(email_triage);")
            existing_columns = {row["name"] for row in cursor.fetchall()}
            new_columns = [
                ("masked_subject", "TEXT"),
                ("masked_body", "TEXT"),
                ("is_active_thread", "INTEGER"),
                ("gatekeeper_decision", "TEXT"),
                ("gatekeeper_confidence", "REAL"),
                ("classifier_used", "TEXT"),
            ]
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    conn.execute(f"ALTER TABLE email_triage ADD COLUMN {col_name} {col_type};")

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
                    WHERE thread_id = ? AND email_id != ? AND routing_status = 'gatekeeper_approved'
                    ORDER BY updated_at DESC
                    """,
                    (thread_id, exclude_email_id),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM email_triage
                    WHERE thread_id = ? AND routing_status = 'gatekeeper_approved'
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

    def is_thread_participant(
        self, thread_id: str, sender_email: str, exclude_email_id: Optional[str] = None
    ) -> bool:
        """Checks if sender_email participated in previous completed records of this thread.

        Prevents thread spoofing / blind trust of thread headers from unknown parties.

        Args:
            thread_id: Thread conversation ID.
            sender_email: Email address of the inbound sender.
            exclude_email_id: Optional email_id to exclude.

        Returns:
            True if sender_email participated in prior completed messages of this thread.
        """
        records = self.get_active_thread_records(thread_id, exclude_email_id)
        sender_clean = (sender_email or "").strip().lower()
        if not sender_clean:
            return False
        for r in records:
            prev_sender = (r.get("sender_email") or "").strip().lower()
            if prev_sender and prev_sender == sender_clean:
                return True
        return False

    def get_gatekeeper_approved(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves emails completed with routing_status='gatekeeper_approved'.

        Phase 2 Note: Downstream dispatchers must pick up verified legitimate emails
        using this query or routing_status='gatekeeper_approved'. The idempotency check
        records these as finished (status='done') so retries do not re-trigger gatekeeping.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of database records ready for downstream ticket dispatching.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM email_triage
                WHERE status = 'done' AND routing_status = 'gatekeeper_approved'
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]

    def check_and_acquire(
        self,
        email_id: str,
        thread_id: str = "",
        message_id: str = "",
        sender_email: str = "",
        stale_minutes: int = 10,
        max_retries: int = 3,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Performs idempotency check and attempts to acquire an atomic processing lock.

        Follows atomic database invariants:
        1. Brand new emails are acquired atomically via single-statement
           `INSERT ... ON CONFLICT(email_id) DO NOTHING` checking cursor.rowcount == 1.
        2. Stale locks are recovered atomically via conditional
           `UPDATE ... SET status='processing' WHERE email_id=? AND status='processing' AND updated_at < ? AND retry_count < ?`
           checking cursor.rowcount == 1 so exactly one concurrent worker wins.
        3. Retry-eligible failed emails are claimed atomically via conditional
           `UPDATE ... WHERE email_id=? AND status='failed' AND retry_count < ?`.
        4. Catches lock contention and integrity collisions cleanly, treating lost races as in-flight / duplicate.

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
        stale_cutoff = now - timedelta(minutes=stale_minutes)
        stale_cutoff_iso = stale_cutoff.isoformat()

        try:
            with self.get_connection() as conn:
                # 1. Atomic insertion for new email: single statement with ON CONFLICT DO NOTHING
                cursor = conn.execute(
                    """
                    INSERT INTO email_triage (
                        email_id, message_id, thread_id, sender_email,
                        status, retry_count, routing_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'processing', 0, 'processing', ?, ?)
                    ON CONFLICT(email_id) DO NOTHING
                    """,
                    (email_id, message_id, thread_id, sender_email, now_iso, now_iso),
                )
                if cursor.rowcount == 1:
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

                # 2. Row already exists: inspect current record state
                cursor = conn.execute(
                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return False, "in_flight", {"email_id": email_id, "status": "processing"}

                record = dict(row)
                current_status = record.get("status")
                retry_count = int(record.get("retry_count") or 0)

                # Case 2: Already completed
                if current_status == "done":
                    return False, "already_completed", record

                # Parse updated_at timestamp to evaluate staleness
                updated_str = record.get("updated_at")
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
                        # Lock is stale: attempt recovery if under max_retries
                        if retry_count < max_retries:
                            update_cur = conn.execute(
                                """
                                UPDATE email_triage
                                SET status = 'processing', retry_count = retry_count + 1, updated_at = ?, routing_status = 'stale_recovery'
                                WHERE email_id = ? AND status = 'processing' AND updated_at < ? AND retry_count < ?
                                """,
                                (now_iso, email_id, stale_cutoff_iso, max_retries),
                            )
                            if update_cur.rowcount == 1:
                                # Won recovery race
                                cur = conn.execute(
                                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                                )
                                r = cur.fetchone()
                                if r:
                                    record = dict(r)
                                else:
                                    record["status"] = "processing"
                                    record["retry_count"] = retry_count + 1
                                    record["routing_status"] = "stale_recovery"
                                    record["updated_at"] = now_iso
                                return True, "recovered_stale", record
                            else:
                                # Lost race to another concurrent worker
                                cur = conn.execute(
                                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                                )
                                r = cur.fetchone()
                                if r:
                                    record = dict(r)
                                if record.get("status") == "done":
                                    return False, "already_completed", record
                                elif record.get("status") == "failed":
                                    return False, "max_retries_exceeded", record
                                else:
                                    return False, "in_flight", record
                        else:
                            # Max retries exceeded on stale lock
                            conn.execute(
                                """
                                UPDATE email_triage
                                SET status = 'failed', error_message = 'Max retries exceeded on stale lock recovery', updated_at = ?
                                WHERE email_id = ? AND status = 'processing'
                                """,
                                (now_iso, email_id),
                            )
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            else:
                                record["status"] = "failed"
                                record["error_message"] = "Max retries exceeded on stale lock recovery"
                                record["updated_at"] = now_iso
                            return False, "max_retries_exceeded", record
                    else:
                        # In-flight and active within stale window
                        return False, "in_flight", record

                # Case 4: Previously failed
                if current_status == "failed":
                    if retry_count < max_retries:
                        update_cur = conn.execute(
                            """
                            UPDATE email_triage
                            SET status = 'processing', retry_count = retry_count + 1, updated_at = ?, routing_status = 'retry'
                            WHERE email_id = ? AND status = 'failed' AND retry_count < ?
                            """,
                            (now_iso, email_id, max_retries),
                        )
                        if update_cur.rowcount == 1:
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            else:
                                record["status"] = "processing"
                                record["retry_count"] = retry_count + 1
                                record["routing_status"] = "retry"
                                record["updated_at"] = now_iso
                            return True, "retry_failed", record
                        else:
                            # Lost race
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            if record.get("status") == "done":
                                return False, "already_completed", record
                            elif record.get("status") == "processing":
                                return False, "in_flight", record
                            else:
                                return False, "max_retries_exceeded", record
                    else:
                        return False, "max_retries_exceeded", record

                return False, "unknown_status", record

        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            # Treat concurrency collisions or lock contention as a lost race
            try:
                record = self.get_record(email_id)
                if record:
                    if record.get("status") == "done":
                        return False, "already_completed", record
                    return False, "in_flight", record
            except Exception:
                pass
            return False, "in_flight", {"email_id": email_id, "status": "processing"}

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
        masked_subject: Optional[str] = None,
        masked_body: Optional[str] = None,
        is_active_thread: Optional[bool] = None,
        gatekeeper_decision: Optional[str] = None,
        gatekeeper_confidence: Optional[float] = None,
        classifier_used: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Sets status to done and updates routing status, target, and triage metadata in ONE statement.

        Raises:
            PersistenceError: If 0 rows are updated (e.g. email_id does not exist).
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check persist_masked_text configuration
        persist_text = True
        if config is not None:
            persist_text = config.get("system", {}).get("persist_masked_text", True)
        else:
            try:
                cfg = load_config()
                persist_text = cfg.get("system", {}).get("persist_masked_text", True)
            except Exception:
                persist_text = True

        # Rule: masked_subject and masked_body persisted ONLY for gatekeeper_approved and manual_review
        if routing_status not in ("gatekeeper_approved", "manual_review") or not persist_text:
            masked_subject = None
            masked_body = None

        active_thread_int = None
        if is_active_thread is not None:
            active_thread_int = 1 if is_active_thread else 0

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE email_triage
                SET status = 'done',
                    routing_status = ?,
                    dispatch_target = ?,
                    updated_at = ?,
                    masked_subject = ?,
                    masked_body = ?,
                    is_active_thread = ?,
                    gatekeeper_decision = ?,
                    gatekeeper_confidence = ?,
                    classifier_used = ?
                WHERE email_id = ?
                """,
                (
                    routing_status,
                    dispatch_target,
                    now_iso,
                    masked_subject,
                    masked_body,
                    active_thread_int,
                    gatekeeper_decision,
                    gatekeeper_confidence,
                    classifier_used,
                    email_id,
                ),
            )
            if cursor.rowcount == 0:
                raise PersistenceError(f"Email '{email_id}' not found to mark done")

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
