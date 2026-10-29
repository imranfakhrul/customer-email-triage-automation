"""SQLite idempotency store and triage database management.

Maintains a three-state (`processing`, `done`, `failed`) lifecycle for
each email, handles stale lock recovery (>10 minutes by default), and
tracks active email threads to allow thread-level continuity.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple
from utils.config import get_config
from state import ALLOWED_CATEGORIES, ALLOWED_TEAMS


class PersistenceError(Exception):
    """Raised when an attempt to persist a triage record fails (e.g. 0 rows updated)."""
    pass


class HitlStateError(Exception):
    """Raised when an HITL review cannot be resolved because the record is not in 'pending' status."""
    pass


class LedgerStateError(Exception):
    """Raised when an outbox ledger state transition is invalid or the record is missing."""
    pass


VALID_P2_JOB_STATES = {
    "unclaimed",
    "claimed",
    "dispatching",
    "done",
    "failed",
    "dead_letter",
    "hitl_pending",
    "hitl_resolved",
}


class TriageDatabase:
    """Manages the SQLite database for idempotency, retry tracking, and state persistence."""

    def __init__(self, db_path: Optional[str] = None):
        """Initializes database path and creates schema if not present.

        Args:
            db_path: Path to the SQLite database file. If None, loaded from config.yaml.
        """
        if db_path is None:
            config = get_config()
            db_path = config["system"]["database_path"]

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
            # Migration for existing databases: add missing columns safely via ALTER TABLE
            cursor = conn.execute("PRAGMA table_info(email_triage);")
            existing_columns = {row["name"] for row in cursor.fetchall()}
            new_columns = [
                ("message_id", "TEXT"),
                ("thread_id", "TEXT"),
                ("sender_email", "TEXT"),
                ("retry_count", "INTEGER DEFAULT 0"),
                ("routing_status", "TEXT"),
                ("dispatch_target", "TEXT"),
                ("error_message", "TEXT"),
                ("masked_subject", "TEXT"),
                ("masked_body", "TEXT"),
                ("is_active_thread", "INTEGER"),
                ("gatekeeper_decision", "TEXT"),
                ("gatekeeper_confidence", "REAL"),
                ("classifier_used", "TEXT"),
                # Phase 2 Classification & HITL columns
                ("p2_category", "TEXT"),
                ("p2_priority", "TEXT"),
                ("p2_sentiment", "TEXT"),
                ("p2_customer_emotion", "TEXT"),
                ("p2_summary", "TEXT"),
                ("p2_suggested_team", "TEXT"),
                ("p2_confidence", "REAL"),
                ("p2_classifier_used", "TEXT"),
                ("hitl_status", "TEXT"),
                ("hitl_reason", "TEXT"),
                ("hitl_notes", "TEXT"),
                ("reviewed_by", "TEXT"),
                ("reviewed_at", "TEXT"),
            ]
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    conn.execute(f"ALTER TABLE email_triage ADD COLUMN {col_name} {col_type};")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_thread_id ON email_triage(thread_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON email_triage(status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hitl_status ON email_triage(hitl_status);"
            )

            # Phase 2 Dispatch Outbox Ledger table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS p2_dispatch_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id TEXT NOT NULL,
                    destination TEXT NOT NULL CHECK(destination IN ('github', 'freescout', 'crm', 'webhook')),
                    action_type TEXT NOT NULL CHECK(action_type IN ('create_issue', 'create_ticket', 'create_lead', 'alert')),
                    idempotency_key TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('dry_run', 'live')),
                    state TEXT NOT NULL CHECK(state IN ('pending', 'confirmed', 'failed', 'unknown', 'dead_letter', 'simulated', 'deferred')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    remote_id TEXT,
                    reason TEXT,
                    error_class TEXT,
                    payload_sha256 TEXT,
                    resolved_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(idempotency_key, mode)
                );
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dispatch_email_id ON p2_dispatch_log(email_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dispatch_dest_state ON p2_dispatch_log(destination, state, updated_at);"
            )

            # Phase 2 Persistent Queue Jobs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS p2_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK(state IN ('unclaimed', 'claimed', 'dispatching', 'done', 'failed', 'dead_letter', 'hitl_pending', 'hitl_resolved')),
                    worker_id TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    claimed_at TEXT,
                    error_message TEXT,
                    next_attempt_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(email_id) REFERENCES email_triage(email_id)
                );
            """)
            # Migration for p2_jobs: add next_attempt_at if missing
            p2_cursor = conn.execute("PRAGMA table_info(p2_jobs);")
            p2_existing_columns = {row["name"] for row in p2_cursor.fetchall()}
            if "next_attempt_at" not in p2_existing_columns:
                conn.execute("ALTER TABLE p2_jobs ADD COLUMN next_attempt_at TEXT;")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_p2_jobs_state ON p2_jobs(state);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_p2_jobs_claimed ON p2_jobs(claimed_at);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_p2_jobs_next_attempt ON p2_jobs(next_attempt_at);"
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
            cfg = get_config()
            persist_text = cfg.get("system", {}).get("persist_masked_text", True)

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

    def record_phase2_classification(
        self,
        email_id: str,
        classification: Optional[Any],
        p2_classifier_used: Optional[str] = None,
        hitl_status: str = "none",
        hitl_reason: Optional[str] = None,
    ) -> bool:
        """Persists Phase 2 deep classification and HITL review gating state into SQLite.

        Args:
            email_id: Unique message identifier.
            classification: EmailClassification object or dictionary or None.
            p2_classifier_used: Engine identifier ('jev', 'groq', 'offline_heuristic', 'fail_closed').
            hitl_status: Gating status ('none', 'pending', 'auto_approved', 'approved', 'rejected').
            hitl_reason: Specific explanation if diverted to HITL review.

        Returns:
            True on successful persistence, or False if email was already resolved by a human.

        Raises:
            PersistenceError: If email_id is not found in database or Phase 1 routing_status is not 'gatekeeper_approved'.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        cat = None
        prio = None
        sent = None
        emotion = None
        summary = None
        team = None
        conf = None

        if classification is not None:
            if hasattr(classification, "category"):
                cat = classification.category
                prio = classification.priority
                sent = classification.sentiment
                emotion = getattr(classification, "customer_emotion", "Calm")
                summary = classification.summary
                team = classification.suggested_team
                conf = classification.confidence
            elif isinstance(classification, dict):
                cat = classification.get("category")
                prio = classification.get("priority")
                sent = classification.get("sentiment")
                emotion = classification.get("customer_emotion", "Calm")
                summary = classification.get("summary")
                team = classification.get("suggested_team")
                conf = classification.get("confidence")

        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT routing_status, hitl_status FROM email_triage WHERE email_id = ?",
                (email_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise PersistenceError(
                    f"Email '{email_id}' not found for Phase 2 classification update"
                )

            # Rule 5: Phase 1 routing_status must be 'gatekeeper_approved'
            if row["routing_status"] != "gatekeeper_approved":
                raise PersistenceError(
                    f"Email '{email_id}' has Phase 1 routing_status='{row['routing_status']}', "
                    f"expected 'gatekeeper_approved'"
                )

            # Rule 5: If hitl_status is already approved or rejected (a human decided), change nothing and return False
            current_hitl = row["hitl_status"]
            if current_hitl in ("approved", "rejected"):
                return False

            query = """
                UPDATE email_triage
                SET p2_category = ?,
                    p2_priority = ?,
                    p2_sentiment = ?,
                    p2_customer_emotion = ?,
                    p2_summary = ?,
                    p2_suggested_team = ?,
                    p2_confidence = ?,
                    p2_classifier_used = ?,
                    hitl_status = ?,
                    hitl_reason = ?,
                    updated_at = ?
                WHERE email_id = ?
            """
            params = (
                cat,
                prio,
                sent,
                emotion,
                summary,
                team,
                conf,
                p2_classifier_used,
                hitl_status,
                hitl_reason,
                now_iso,
                email_id,
            )
            cursor = conn.execute(query, params)
            if cursor.rowcount == 0:
                raise PersistenceError(
                    f"Email '{email_id}' not found for Phase 2 classification update"
                )
        return True

    def get_pending_hitl_reviews(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves emails currently awaiting Human-in-the-Loop review.

        WHERE hitl_status = 'pending' only, ORDER BY created_at ASC (oldest first),
        and selects explicit columns WITHOUT sender_email.

        Args:
            limit: Maximum number of pending records to return (default: 100).

        Returns:
            List of row dictionaries for pending reviews without sender_email.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    email_id,
                    message_id,
                    thread_id,
                    status,
                    retry_count,
                    routing_status,
                    dispatch_target,
                    created_at,
                    updated_at,
                    masked_subject,
                    masked_body,
                    is_active_thread,
                    gatekeeper_decision,
                    gatekeeper_confidence,
                    classifier_used,
                    p2_category,
                    p2_priority,
                    p2_sentiment,
                    p2_customer_emotion,
                    p2_summary,
                    p2_suggested_team,
                    p2_confidence,
                    p2_classifier_used,
                    hitl_status,
                    hitl_reason,
                    hitl_notes,
                    reviewed_by,
                    reviewed_at
                FROM email_triage
                WHERE hitl_status = 'pending'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def resolve_hitl_review(
        self,
        email_id: str,
        decision: str,
        reviewed_by: str,
        notes: str = "",
        override_category: Optional[str] = None,
        override_team: Optional[str] = None,
    ) -> bool:
        """Resolves a pending HITL review record (approve or reject with optional overrides).

        Args:
            email_id: Email identifier being reviewed.
            decision: 'approved' or 'rejected'.
            reviewed_by: Identifier/username of reviewer (non-empty, max 64 chars).
            notes: Operator review notes or reasoning (max 1000 chars, control chars removed).
                   Required for rejection.
            override_category: Optional category override in ALLOWED_CATEGORIES.
            override_team: Optional team override in ALLOWED_TEAMS.

        Returns:
            True if review record was successfully resolved.

        Raises:
            ValueError: If inputs fail validation.
            PersistenceError: If email_id was not found.
            HitlStateError: If email is not in 'pending' status.
        """
        clean_decision = str(decision).strip().lower()
        if clean_decision not in ("approved", "rejected"):
            raise ValueError(f"Invalid decision '{decision}'. Must be 'approved' or 'rejected'.")

        reviewed_by_clean = (reviewed_by or "").strip()
        if not reviewed_by_clean:
            raise ValueError("reviewed_by must be a non-empty string")
        if len(reviewed_by_clean) > 64:
            raise ValueError("reviewed_by must be at most 64 characters")

        if override_category is not None and override_category not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"Invalid override_category '{override_category}'. Must be one of {ALLOWED_CATEGORIES}"
            )

        if override_team is not None and override_team not in ALLOWED_TEAMS:
            raise ValueError(
                f"Invalid override_team '{override_team}'. Must be one of {ALLOWED_TEAMS}"
            )

        # Control characters removed (keep standard whitespace: \n, \t, \r)
        clean_notes = "".join(
            ch for ch in (notes or "") if (ch >= " " and ch != "\x7f") or ch in "\n\t\r"
        )
        if len(clean_notes) > 1000:
            raise ValueError("notes must be at most 1000 characters")

        if clean_decision == "rejected" and not clean_notes.strip():
            raise ValueError("Rejection requires non-empty notes")

        now_iso = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            if clean_decision == "approved":
                cursor = conn.execute(
                    """
                    UPDATE email_triage
                    SET hitl_status = 'approved',
                        hitl_notes = ?,
                        reviewed_by = ?,
                        reviewed_at = ?,
                        p2_category = COALESCE(?, p2_category),
                        p2_suggested_team = COALESCE(?, p2_suggested_team),
                        updated_at = ?
                    WHERE email_id = ? AND hitl_status = 'pending'
                    """,
                    (
                        clean_notes,
                        reviewed_by_clean,
                        now_iso,
                        override_category,
                        override_team,
                        now_iso,
                        email_id,
                    ),
                )
            else:  # rejected
                cursor = conn.execute(
                    """
                    UPDATE email_triage
                    SET hitl_status = 'rejected',
                        hitl_notes = ?,
                        reviewed_by = ?,
                        reviewed_at = ?,
                        updated_at = ?
                    WHERE email_id = ? AND hitl_status = 'pending'
                    """,
                    (
                        clean_notes,
                        reviewed_by_clean,
                        now_iso,
                        now_iso,
                        email_id,
                    ),
                )

            if cursor.rowcount == 0:
                cur = conn.execute(
                    "SELECT hitl_status FROM email_triage WHERE email_id = ?",
                    (email_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise PersistenceError(f"Email '{email_id}' not found")
                current_status = row["hitl_status"]
                raise HitlStateError(
                    f"Email '{email_id}' is not in 'pending' status (current status: '{current_status}')"
                )

            # Sync p2_jobs state if a queue job exists
            if clean_decision == "approved":
                conn.execute(
                    """
                    UPDATE p2_jobs
                    SET state = 'hitl_resolved',
                        updated_at = ?
                    WHERE email_id = ? AND state = 'hitl_pending'
                    """,
                    (now_iso, email_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE p2_jobs
                    SET state = 'done',
                        updated_at = ?
                    WHERE email_id = ? AND state = 'hitl_pending'
                    """,
                    (now_iso, email_id),
                )

        return True

    def get_hitl_status(self, email_id: str) -> Optional[str]:
        """Retrieves the current hitl_status for an email from email_triage.

        Args:
            email_id: Message identifier.

        Returns:
            The current hitl_status string or None if email_id is not found.
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT hitl_status FROM email_triage WHERE email_id = ?",
                (email_id,),
            )
            row = cur.fetchone()
            return str(row["hitl_status"]) if row and row["hitl_status"] is not None else None

    @staticmethod
    def build_idempotency_key(email_id: str, destination: str, action_type: str) -> str:
        """Constructs a deterministic composite idempotency key.

        Args:
            email_id: Unique identifier of the incoming email.
            destination: Downstream service name ('github', 'freescout', 'crm', 'webhook').
            action_type: Action type ('create_issue', 'create_ticket', 'create_lead', 'alert').

        Returns:
            Formatted string 'email_id:destination:action_type'.
        """
        return f"{email_id}:{destination}:{action_type}"

    def begin_dispatch(
        self,
        email_id: str,
        destination: str,
        action_type: str,
        mode: str,
        payload_sha256: Optional[str] = None,
        max_attempts: int = 3,
    ) -> Tuple[Dict[str, Any], bool]:
        """Atomically acquires an outbox dispatch lock or initiates a new dispatch log entry.

        Args:
            email_id: Target email id.
            destination: Service destination ('github', 'freescout', 'crm', 'webhook').
            action_type: Action ('create_issue', 'create_ticket', 'create_lead', 'alert').
            mode: Mode ('dry_run' or 'live').
            payload_sha256: Optional SHA-256 hash of the DispatchPayload.
            max_attempts: Maximum retry attempts before transitioning to dead_letter.

        Returns:
            Tuple of (row_dict, acquired_bool).

        Raises:
            ValueError: If arguments fail type or range validation.
            PersistenceError: If email does not exist with routing_status 'gatekeeper_approved'.
        """
        if not isinstance(email_id, str) or not email_id.strip():
            raise ValueError("email_id must be a non-empty string")
        if destination not in ("github", "freescout", "crm", "webhook"):
            raise ValueError(f"Invalid destination '{destination}'")
        if action_type not in ("create_issue", "create_ticket", "create_lead", "alert"):
            raise ValueError(f"Invalid action_type '{action_type}'")
        if mode not in ("dry_run", "live"):
            raise ValueError(f"Invalid mode '{mode}'. Must be 'dry_run' or 'live'")
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or max_attempts < 1
        ):
            raise ValueError("max_attempts must be an integer >= 1")

        idempotency_key = self.build_idempotency_key(email_id, destination, action_type)
        now_iso = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            # Enforce prerequisite: Email must exist with Phase 1 gatekeeper_approved
            cur = conn.execute(
                "SELECT routing_status FROM email_triage WHERE email_id = ?",
                (email_id,),
            )
            email_row = cur.fetchone()
            if email_row is None or email_row["routing_status"] != "gatekeeper_approved":
                raise PersistenceError(
                    f"Email '{email_id}' does not exist or is not in 'gatekeeper_approved' status "
                    f"(status: {email_row['routing_status'] if email_row else 'NOT_FOUND'})"
                )

            # Step 1: INSERT ... ON CONFLICT DO NOTHING
            cursor = conn.execute(
                """
                INSERT INTO p2_dispatch_log (
                    email_id, destination, action_type, idempotency_key, mode,
                    state, attempts, payload_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
                ON CONFLICT(idempotency_key, mode) DO NOTHING;
                """,
                (
                    email_id,
                    destination,
                    action_type,
                    idempotency_key,
                    mode,
                    payload_sha256,
                    now_iso,
                    now_iso,
                ),
            )
            if cursor.rowcount == 1:
                cur = conn.execute(
                    "SELECT * FROM p2_dispatch_log WHERE idempotency_key = ? AND mode = ?",
                    (idempotency_key, mode),
                )
                return dict(cur.fetchone()), True

            # Step 2: UPDATE to 'pending' if in failed/deferred and attempts < max_attempts
            cursor = conn.execute(
                """
                UPDATE p2_dispatch_log
                SET state = 'pending',
                    payload_sha256 = COALESCE(?, payload_sha256),
                    updated_at = ?
                WHERE idempotency_key = ? AND mode = ?
                  AND state IN ('failed', 'deferred')
                  AND attempts < ?;
                """,
                (payload_sha256, now_iso, idempotency_key, mode, max_attempts),
            )
            if cursor.rowcount == 1:
                cur = conn.execute(
                    "SELECT * FROM p2_dispatch_log WHERE idempotency_key = ? AND mode = ?",
                    (idempotency_key, mode),
                )
                return dict(cur.fetchone()), True

            # Step 3: Move failed row with attempts >= max_attempts to 'dead_letter'
            conn.execute(
                """
                UPDATE p2_dispatch_log
                SET state = 'dead_letter',
                    reason = 'retries_exhausted',
                    updated_at = ?
                WHERE idempotency_key = ? AND mode = ?
                  AND state = 'failed'
                  AND attempts >= ?;
                """,
                (now_iso, idempotency_key, mode, max_attempts),
            )

            # Step 4: Return current row with acquired=False
            cur = conn.execute(
                "SELECT * FROM p2_dispatch_log WHERE idempotency_key = ? AND mode = ?",
                (idempotency_key, mode),
            )
            return dict(cur.fetchone()), False

    def record_dispatch_attempt(self, ledger_id: int) -> int:
        """Increments the attempt counter for a pending dispatch log row.

        Args:
            ledger_id: Primary key id of p2_dispatch_log.

        Returns:
            New attempts count.

        Raises:
            LedgerStateError: If row does not exist or is not in 'pending' state.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE p2_dispatch_log
                SET attempts = attempts + 1,
                    updated_at = ?
                WHERE id = ? AND state = 'pending';
                """,
                (now_iso, ledger_id),
            )
            if cursor.rowcount == 0:
                raise LedgerStateError(
                    f"Cannot record attempt on dispatch log #{ledger_id}: "
                    "row not found or not in 'pending' state"
                )

            cur = conn.execute(
                "SELECT attempts FROM p2_dispatch_log WHERE id = ?",
                (ledger_id,),
            )
            return int(cur.fetchone()["attempts"])

    def finish_dispatch(
        self,
        ledger_id: int,
        state: str,
        remote_id: Optional[str] = None,
        reason: Optional[str] = None,
        error_class: Optional[str] = None,
    ) -> bool:
        """Transitions a pending dispatch log row to a terminal or deferred state.

        Args:
            ledger_id: Primary key id of p2_dispatch_log.
            state: Target state in ('confirmed', 'failed', 'unknown', 'dead_letter', 'simulated', 'deferred').
            remote_id: Optional remote identifier (<= 128 chars matching ^[A-Za-z0-9._:/#-]+$).
            reason: Optional reason code (matching ^[a-z_]{1,40}$).
            error_class: Optional exception class name (<= 64 chars matching ^[A-Za-z0-9_]+$).

        Returns:
            True on successful transition.

        Raises:
            ValueError: If arguments violate format contracts.
            LedgerStateError: If row is not found or not currently in 'pending' state.
        """
        allowed_targets = (
            "confirmed",
            "failed",
            "unknown",
            "dead_letter",
            "simulated",
            "deferred",
        )
        if state not in allowed_targets:
            raise ValueError(
                f"Invalid target state '{state}'. Must be one of {allowed_targets}"
            )

        if remote_id is not None and (
            not isinstance(remote_id, str)
            or not remote_id.strip()
            or len(remote_id) > 128
            or not re.match(r"^[A-Za-z0-9._:/#-]+$", remote_id)
        ):
            raise ValueError(
                "remote_id must be a non-empty string of at most 128 characters "
                f"matching ^[A-Za-z0-9._:/#-]+$, got {remote_id!r}"
            )

        if reason is not None and (
            not isinstance(reason, str) or not re.match(r"^[a-z_]{1,40}$", reason)
        ):
            raise ValueError(
                f"reason must match ^[a-z_]{{1,40}}$, got {reason!r}"
            )

        if error_class is not None and (
            not isinstance(error_class, str)
            or len(error_class) > 64
            or not re.match(r"^[A-Za-z0-9_]+$", error_class)
        ):
            raise ValueError(
                "error_class must be a string of at most 64 characters "
                f"matching ^[A-Za-z0-9_]+$, got {error_class!r}"
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE p2_dispatch_log
                SET state = ?,
                    remote_id = ?,
                    reason = ?,
                    error_class = ?,
                    updated_at = ?
                WHERE id = ? AND state = 'pending';
                """,
                (state, remote_id, reason, error_class, now_iso, ledger_id),
            )
            if cursor.rowcount == 0:
                raise LedgerStateError(
                    f"Cannot finish dispatch log #{ledger_id} to '{state}': "
                    "row not found or not in 'pending' state"
                )

        return True

    def resolve_unknown_dispatch(
        self,
        ledger_id: int,
        outcome: str,
        resolved_by: str,
        remote_id: Optional[str] = None,
    ) -> bool:
        """Resolves an 'unknown' outcome dispatch log row following duplicate verification.

        Args:
            ledger_id: Primary key id of p2_dispatch_log.
            outcome: Either 'confirmed' (verified delivered) or 'not_sent' (safe to retry).
            resolved_by: Identifier of the operator or automated resolver (<= 64 chars).
            remote_id: Remote identifier (required when outcome is 'confirmed').

        Returns:
            True on successful resolution.

        Raises:
            ValueError: If arguments violate format requirements.
            PersistenceError: If row does not exist.
            LedgerStateError: If row is not currently in 'unknown' state.
        """
        if outcome not in ("confirmed", "not_sent", "failed"):
            raise ValueError(
                f"Invalid outcome '{outcome}'. Must be 'confirmed', 'not_sent', or 'failed'"
            )

        if (
            not isinstance(resolved_by, str)
            or not resolved_by.strip()
            or len(resolved_by) > 64
        ):
            raise ValueError(
                "resolved_by must be a non-empty string of at most 64 characters, "
                f"got {resolved_by!r}"
            )

        if outcome == "confirmed" and (
            not remote_id
            or not isinstance(remote_id, str)
            or not remote_id.strip()
            or len(remote_id) > 128
            or not re.match(r"^[A-Za-z0-9._:/#-]+$", remote_id)
        ):
            raise ValueError(
                "outcome 'confirmed' requires non-empty remote_id (at most 128 chars "
                f"matching ^[A-Za-z0-9._:/#-]+$), got {remote_id!r}"
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            if outcome == "confirmed":
                cursor = conn.execute(
                    """
                    UPDATE p2_dispatch_log
                    SET state = 'confirmed',
                        remote_id = ?,
                        resolved_by = ?,
                        updated_at = ?
                    WHERE id = ? AND state = 'unknown';
                    """,
                    (remote_id, resolved_by, now_iso, ledger_id),
                )
            else:  # not_sent
                cursor = conn.execute(
                    """
                    UPDATE p2_dispatch_log
                    SET state = 'failed',
                        reason = 'operator_not_sent',
                        resolved_by = ?,
                        updated_at = ?
                    WHERE id = ? AND state = 'unknown';
                    """,
                    (resolved_by, now_iso, ledger_id),
                )

            if cursor.rowcount == 0:
                cur = conn.execute(
                    "SELECT state FROM p2_dispatch_log WHERE id = ?",
                    (ledger_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise PersistenceError(f"Dispatch log #{ledger_id} not found")
                raise LedgerStateError(
                    f"Dispatch log #{ledger_id} is in state '{row['state']}', expected 'unknown'"
                )

        return True

    def expire_stale_pending(
        self,
        older_than_minutes: int,
        now: Optional[datetime] = None,
    ) -> int:
        """Transitions stale pending dispatches older than cutoff to 'unknown'.

        Args:
            older_than_minutes: Stale threshold in minutes.
            now: Optional reference UTC datetime.

        Returns:
            Number of rows transitioned.
        """
        ref_now = now or datetime.now(timezone.utc)
        cutoff = (ref_now - timedelta(minutes=older_than_minutes)).isoformat()
        now_iso = ref_now.isoformat()

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE p2_dispatch_log
                SET state = 'unknown',
                    reason = 'stale_pending',
                    updated_at = ?
                WHERE state = 'pending' AND updated_at < ?;
                """,
                (now_iso, cutoff),
            )
            return cursor.rowcount

    def get_dispatch_log(self, email_id: str) -> List[Dict[str, Any]]:
        """Retrieves all dispatch log rows for a given email_id ordered by id.

        Args:
            email_id: Unique identifier of the incoming email.

        Returns:
            List of dispatch log row dictionaries.
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM p2_dispatch_log WHERE email_id = ? ORDER BY id ASC;",
                (email_id,),
            )
            return [dict(row) for row in cur.fetchall()]

    def count_confirmed_today(
        self,
        destination: str,
        now: Optional[datetime] = None,
    ) -> int:
        """Counts confirmed live dispatches for a destination on or after 00:00 UTC today.

        Simulated dry-run rows and dispatches from previous UTC days are ignored.

        Args:
            destination: Downstream service name ('github', 'freescout', 'crm', 'webhook').
            now: Optional reference UTC datetime.

        Returns:
            Integer count of confirmed dispatches today.
        """
        ref_now = now or datetime.now(timezone.utc)
        start_of_day = (
            ref_now.astimezone(timezone.utc)
            .replace(hour=0, minute=0, second=0, microsecond=0)
            .isoformat()
        )

        with self.get_connection() as conn:
            cur = conn.execute(
                """
                SELECT COUNT(*) as cnt FROM p2_dispatch_log
                WHERE destination = ?
                  AND mode = 'live'
                  AND state = 'confirmed'
                  AND updated_at >= ?;
                """,
                (destination, start_of_day),
            )
            return int(cur.fetchone()["cnt"])

    def get_failure_streak(
        self,
        destination: str,
        now: Optional[datetime] = None,
    ) -> Tuple[int, Optional[str]]:
        """Calculates consecutive failures in newest-first live rows for a destination.

        Streak resets immediately when a 'confirmed' row is encountered.
        Pending, deferred, and simulated rows are ignored.

        Args:
            destination: Downstream service name ('github', 'freescout', 'crm', 'webhook').
            now: Optional reference UTC datetime.

        Returns:
            Tuple of (consecutive_failures_count, newest_failure_updated_at or None).
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                SELECT state, updated_at FROM p2_dispatch_log
                WHERE destination = ? AND mode = 'live'
                ORDER BY updated_at DESC, id DESC;
                """,
                (destination,),
            )
            count = 0
            newest_failure_updated_at: Optional[str] = None
            for row in cur.fetchall():
                st = row["state"]
                if st in ("pending", "deferred", "simulated"):
                    continue
                if st in ("failed", "dead_letter", "unknown"):
                    if count == 0:
                        newest_failure_updated_at = row["updated_at"]
                    count += 1
                elif st == "confirmed":
                    break

            return count, newest_failure_updated_at

    def has_active_circuit_probe(
        self,
        destination: str,
        since_iso: str,
        exclude_ledger_id: Optional[int] = None,
        stale_cutoff_iso: Optional[str] = None,
    ) -> bool:
        """Checks if a trial probe is already in flight after circuit cooldown.

        Args:
            destination: Downstream service name.
            since_iso: Timestamp of the newest failure that opened the circuit.
            exclude_ledger_id: Optional outbox ledger id to exclude (e.g. current row).
            stale_cutoff_iso: Optional cutoff timestamp before which pending probes are ignored.

        Returns:
            True if an active in-flight probe exists, False otherwise.
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                SELECT 1 FROM p2_dispatch_log
                WHERE destination = ?
                  AND mode = 'live'
                  AND state = 'pending'
                  AND (? IS NULL OR id != ?)
                  AND updated_at > ?
                  AND (? IS NULL OR updated_at >= ?)
                LIMIT 1;
                """,
                (
                    destination,
                    exclude_ledger_id,
                    exclude_ledger_id,
                    since_iso,
                    stale_cutoff_iso,
                    stale_cutoff_iso,
                ),
            )
            return cur.fetchone() is not None

    def divert_to_hitl(self, email_id: str, reason: str) -> bool:
        """Diverts an auto_approved or approved email back to pending HITL review.

        Strictly preserves Phase 1 columns and does not alter reviewed_by/reviewed_at.

        Args:
            email_id: Unique identifier of the email.
            reason: Reason code matching ^[a-z_]{1,40}$.

        Returns:
            True on successful update.

        Raises:
            ValueError: If reason code format is invalid.
            PersistenceError: If email does not exist.
            HitlStateError: If email is not currently in ('auto_approved', 'approved').
        """
        if not isinstance(reason, str) or not re.match(r"^[a-z_]{1,40}$", reason):
            raise ValueError(f"reason must match ^[a-z_]{{1,40}}$, got {reason!r}")

        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE email_triage
                SET hitl_status = 'pending',
                    hitl_reason = ?,
                    updated_at = ?
                WHERE email_id = ? AND hitl_status IN ('auto_approved', 'approved');
                """,
                (reason, now_iso, email_id),
            )
            if cursor.rowcount == 0:
                cur = conn.execute(
                    "SELECT hitl_status FROM email_triage WHERE email_id = ?",
                    (email_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise PersistenceError(f"Email '{email_id}' not found")
                current_status = row["hitl_status"]
                raise HitlStateError(
                    f"Email '{email_id}' has hitl_status '{current_status}', "
                    "expected 'auto_approved' or 'approved'"
                )

        return True

    def sync_p2_intake(self) -> int:
        """Imports eligible gatekeeper_approved Phase 1 records into p2_jobs as unclaimed.

        Returns:
            Number of new jobs inserted.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO p2_jobs (email_id, state, attempts, created_at, updated_at)
                SELECT email_id, 'unclaimed', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                FROM email_triage
                WHERE status = 'done' AND routing_status = 'gatekeeper_approved'
                  AND email_id NOT IN (SELECT email_id FROM p2_jobs);
                """
            )
            return cursor.rowcount

    def claim_p2_jobs(
        self,
        batch_size: int = 10,
        worker_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Atomically claims a batch of unclaimed or hitl_resolved jobs for a worker.

        Executes a single atomic UPDATE statement with a subquery LIMIT to eliminate
        SELECT-then-UPDATE race conditions across concurrent workers. Respects next_attempt_at
        filtering to skip jobs in cooldown.

        Args:
            batch_size: Maximum number of jobs to claim (must be > 0).
            worker_id: Optional worker identifier.
            now: Optional current datetime (defaults to UTC now).

        Returns:
            List of dicts representing the claimed jobs joined with email_triage fields.
        """
        if batch_size <= 0:
            return []
        if worker_id is None:
            import uuid
            worker_id = f"worker_{uuid.uuid4().hex[:8]}"

        if now is None:
            now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")
        now_query_str = now.strftime("%Y-%m-%d %H:%M:%S")

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE p2_jobs
                SET state = 'claimed',
                    worker_id = ?,
                    claimed_at = ?,
                    attempts = attempts + 1,
                    next_attempt_at = NULL,
                    updated_at = ?
                WHERE email_id IN (
                    SELECT email_id FROM p2_jobs
                    WHERE state IN ('unclaimed', 'hitl_resolved')
                      AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime(?))
                    ORDER BY created_at ASC
                    LIMIT ?
                );
                """,
                (worker_id, now_str, now_str, now_query_str, batch_size),
            )
            if cursor.rowcount == 0:
                return []

            fetch_cursor = conn.execute(
                """
                SELECT j.id, j.email_id, j.state, j.worker_id, j.attempts,
                       j.claimed_at, j.error_message, j.created_at, j.updated_at,
                       t.masked_subject, t.masked_body, t.sender_email,
                       t.message_id, t.thread_id, t.is_active_thread,
                       t.gatekeeper_confidence, t.classifier_used,
                       t.hitl_status, t.p2_category, t.p2_priority,
                       t.p2_sentiment, t.p2_customer_emotion, t.p2_summary,
                       t.p2_suggested_team, t.p2_confidence, t.p2_classifier_used
                FROM p2_jobs j
                JOIN email_triage t ON j.email_id = t.email_id
                WHERE j.worker_id = ? AND j.state = 'claimed' AND j.claimed_at = ?
                ORDER BY j.created_at ASC;
                """,
                (worker_id, now_str),
            )
            return [dict(row) for row in fetch_cursor.fetchall()]

    def recover_stale_p2_jobs(
        self, stale_minutes: int = 15, max_retries: int = 3, now: Optional[datetime] = None
    ) -> int:
        """Recovers abandoned or crashed worker claims older than stale_minutes.

        Jobs exceeding max_retries transition to 'dead_letter'.
        Other stale jobs reset to 'unclaimed' with worker_id and claimed_at cleared.

        Args:
            stale_minutes: Inactivity threshold in minutes (default 15).
            max_retries: Max attempt count before moving to dead_letter (default 3).
            now: Optional current datetime (defaults to UTC now).

        Returns:
            Total number of stale jobs recovered.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=stale_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        with self.get_connection() as conn:
            dlq_cur = conn.execute(
                """
                UPDATE p2_jobs
                SET state = 'dead_letter',
                    error_message = 'Exceeded max retries after worker crash recovery',
                    updated_at = ?
                WHERE state IN ('claimed', 'dispatching')
                  AND datetime(claimed_at) <= datetime(?)
                  AND attempts >= ?;
                """,
                (now_str, cutoff, max_retries),
            )
            dlq_count = dlq_cur.rowcount

            reset_cur = conn.execute(
                """
                UPDATE p2_jobs
                SET state = 'unclaimed',
                    worker_id = NULL,
                    claimed_at = NULL,
                    updated_at = ?
                WHERE state IN ('claimed', 'dispatching')
                  AND datetime(claimed_at) <= datetime(?)
                  AND attempts < ?;
                """,
                (now_str, cutoff, max_retries),
            )
            reset_count = reset_cur.rowcount

            return dlq_count + reset_count

    def finish_p2_job(
        self,
        email_id: str,
        state: str,
        error_message: Optional[str] = None,
        next_attempt_at: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> None:
        """Transitions a p2_jobs record to its terminal or intermediate state.

        Args:
            email_id: Email identifier.
            state: New state (e.g. 'done', 'failed', 'hitl_pending', 'unclaimed').
            error_message: Optional error or diagnostic message.
            next_attempt_at: Optional ISO timestamp string for scheduled re-attempt.
            worker_id: Optional worker identifier enforcing compare-and-swap (CAS) ownership.

        Raises:
            ValueError: If state is not in VALID_P2_JOB_STATES.
            PersistenceError: If email_id is not found in p2_jobs or worker ownership conflict.
        """
        if state not in VALID_P2_JOB_STATES:
            raise ValueError(
                f"Invalid p2_jobs state: '{state}'. Must be one of {sorted(VALID_P2_JOB_STATES)}"
            )

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            if state == "unclaimed":
                # Clear active worker ownership to allow clean reclaiming after cooldown
                cursor = conn.execute(
                    """
                    UPDATE p2_jobs
                    SET state = ?,
                        worker_id = NULL,
                        claimed_at = NULL,
                        next_attempt_at = ?,
                        error_message = ?,
                        updated_at = ?
                    WHERE email_id = ?
                      AND (? IS NULL OR worker_id = ? OR worker_id IS NULL);
                    """,
                    (state, next_attempt_at, error_message, now_str, email_id, worker_id, worker_id),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE p2_jobs
                    SET state = ?,
                        next_attempt_at = ?,
                        error_message = ?,
                        updated_at = ?
                    WHERE email_id = ?
                      AND (? IS NULL OR worker_id = ? OR worker_id IS NULL);
                    """,
                    (state, next_attempt_at, error_message, now_str, email_id, worker_id, worker_id),
                )
            if cursor.rowcount == 0:
                raise PersistenceError(
                    f"Job for email_id '{email_id}' not found in p2_jobs or worker ownership conflict"
                )

    def get_p2_job(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a p2_jobs record by email_id.

        Args:
            email_id: Email identifier.

        Returns:
            Dict representing the p2_jobs record, or None if not found.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM p2_jobs WHERE email_id = ?;", (email_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def clear_all(self) -> None:
        """Clears all records in triage tables (used for testing)."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM p2_dispatch_log;")
            conn.execute("DELETE FROM p2_jobs;")
            conn.execute("DELETE FROM email_triage;")
