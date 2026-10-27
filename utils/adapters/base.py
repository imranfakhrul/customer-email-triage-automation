"""Abstract base contract, payload models, and error hierarchy for downstream adapters."""

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any


# ---------------------------------------------------------------------------
# 1. Dispatch Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DispatchPayload:
    """Privacy-hardened data payload for downstream destination adapters.

    Guarantees that zero unmasked customer PII (sender_email, token_map, raw text)
    can ever reach external destination adapters.
    """

    email_id: str
    message_id: str
    thread_id: str
    category: str
    priority: str
    sentiment: str
    customer_emotion: str
    summary: str
    suggested_team: str
    confidence: float
    masked_subject: str
    masked_body: str
    sender_domain: str
    p2_classifier_used: str
    action_type: str
    idempotency_key: str

    @classmethod
    def from_record(
        cls,
        record: dict[str, Any],
        action_type: str,
        idempotency_key: str,
    ) -> "DispatchPayload":
        """Constructs a hardened DispatchPayload from a database triage record or state.

        Args:
            record: Mapping containing email metadata, classification fields, and masked text.
            action_type: Canonical destination action (e.g. 'create_issue', 'create_ticket').
            idempotency_key: Unique composite idempotency key for outbox tracking.

        Returns:
            Immutable DispatchPayload with clamped text and sender domain.

        Raises:
            ValueError: If masked_subject or masked_body is None or missing.
        """
        masked_subject = record.get("masked_subject")
        masked_body = record.get("masked_body")
        if masked_subject is None or masked_body is None:
            raise ValueError(
                f"Cannot create DispatchPayload: masked_subject and masked_body are required (got "
                f"masked_subject={masked_subject!r}, masked_body={masked_body!r})"
            )

        # Clamping to bounded lengths (A6 security defense)
        clamped_subject = str(masked_subject)[:2000]
        clamped_body = str(masked_body)[:10000]

        # Sender domain extraction: lowercased part after '@' of record['sender_email']
        sender_email = record.get("sender_email") or ""
        if "@" in sender_email:
            sender_domain = sender_email.split("@", 1)[1].lower()
        else:
            sender_domain = (record.get("sender_domain") or "").lower()

        # Map Phase 2 fields (p2_* to clean names with fallback to clean names)
        category = record.get("p2_category") or record.get("category") or "Other"
        priority = record.get("p2_priority") or record.get("priority") or "Medium"
        sentiment = record.get("p2_sentiment") or record.get("sentiment") or "Neutral"
        customer_emotion = (
            record.get("p2_customer_emotion") or record.get("customer_emotion") or "Calm"
        )
        summary = record.get("p2_summary") or record.get("summary") or ""
        suggested_team = (
            record.get("p2_suggested_team") or record.get("suggested_team") or "Support"
        )

        conf_val = record.get("p2_confidence")
        if conf_val is None:
            conf_val = record.get("confidence", 0.0)
        try:
            confidence = float(conf_val)
        except (ValueError, TypeError):
            confidence = 0.0

        p2_classifier_used = (
            record.get("p2_classifier_used") or record.get("classifier_used") or ""
        )

        return cls(
            email_id=str(record.get("email_id") or ""),
            message_id=str(record.get("message_id") or ""),
            thread_id=str(record.get("thread_id") or ""),
            category=str(category),
            priority=str(priority),
            sentiment=str(sentiment),
            customer_emotion=str(customer_emotion),
            summary=str(summary),
            suggested_team=str(suggested_team),
            confidence=confidence,
            masked_subject=clamped_subject,
            masked_body=clamped_body,
            sender_domain=sender_domain,
            p2_classifier_used=str(p2_classifier_used),
            action_type=str(action_type),
            idempotency_key=str(idempotency_key),
        )

    def to_dict(self) -> dict[str, Any]:
        """Converts payload to a standard dictionary representation."""
        return asdict(self)

    def sha256(self) -> str:
        """Returns stable SHA-256 hexadecimal digest of canonical UTF-8 JSON representation."""
        payload_json = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DispatchResult:
    """Immutable result of a dispatch operation."""

    remote_id: str
    outcome: str = "success"

    def __post_init__(self) -> None:
        """Validates that remote_id is non-empty and at most 128 characters."""
        if (
            not isinstance(self.remote_id, str)
            or not self.remote_id.strip()
            or len(self.remote_id) > 128
        ):
            raise ValueError(
                "remote_id must be a non-empty string of at most 128 characters, "
                f"got {self.remote_id!r}"
            )


# ---------------------------------------------------------------------------
# 2. Adapter Error Hierarchy
# ---------------------------------------------------------------------------
class AdapterError(Exception):
    """Base exception for all downstream adapter failures."""

    pass


class AdapterTransientError(AdapterError):
    """Raised when the request was certainly NOT delivered to the remote service.

    Safe for automated immediate retry with backoff (e.g. DNS failure before connection,
    immediate local network error, connection refused).
    """

    pass


class AdapterPermanentError(AdapterError):
    """Raised when the destination rejected the request and retrying will not help.

    Terminal failure (e.g. 400 Bad Request, 401 Unauthorized, 404 Repository Not Found).
    """

    pass


class AdapterUnknownOutcomeError(AdapterError):
    """Raised when the request may or may not have been delivered or processed.

    Blind retries are strictly forbidden. The system must verify remote state via
    adapter.check_duplicate() or defer to operator inspection (e.g. connection reset
    after request write, HTTP timeout waiting for response headers, ambiguous 502/503/504).
    """

    pass


# ---------------------------------------------------------------------------
# 3. Base Destination Adapter Abstract Contract
# ---------------------------------------------------------------------------
class BaseDestinationAdapter(ABC):
    """Abstract contract for all downstream destination service adapters.

    Operational Guardrail Rules:
    - Zero customer PII or raw text fields may be logged.
    - Remote response bodies and headers must NEVER be logged.
    - Outbound connections must be HTTPS-only and restricted to allowlisted hostnames.
    """

    name: str

    @abstractmethod
    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        """Transmits the hardened payload to the external destination service.

        Args:
            payload: Privacy-sanitized, length-clamped DispatchPayload.

        Returns:
            DispatchResult confirming successful transmission and remote record id.

        Raises:
            AdapterTransientError: Network error before request transmission.
            AdapterPermanentError: Remote destination permanent rejection.
            AdapterUnknownOutcomeError: Timeout or disconnection after request write.
        """
        pass

    @abstractmethod
    def check_duplicate(
        self,
        idempotency_key: str,
        payload: DispatchPayload,
    ) -> str | None:
        """Queries the destination service to determine if an action was already delivered.

        Args:
            idempotency_key: Unique composite idempotency key.
            payload: DispatchPayload for context-specific correlation matching.

        Returns:
            The existing remote_id if already confirmed on remote system, or None.
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validates that necessary configuration keys and environment secrets exist."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Executes a non-mutating ping or auth-check against the destination service."""
        pass
