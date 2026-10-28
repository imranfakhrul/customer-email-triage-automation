"""Abstract base interface for mailbox connectors.

Defines a provider-agnostic protocol for importing live email events,
extracting SPF/DKIM/DMARC authentication results, and authorized original-text re-fetch.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseMailboxConnector(ABC):
    """Abstract base class for all enterprise mailbox connectors."""

    @abstractmethod
    def fetch_new_messages(
        self, start_history_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Fetches newly received messages incrementally.

        Args:
            start_history_id: Optional synchronization token or history marker.

        Returns:
            List of normalized email metadata and message dictionaries.
        """

    @abstractmethod
    def refetch_original_email(self, message_id: str) -> dict[str, Any] | None:
        """Authorized re-fetch of unmasked original email text by message identifier.

        Args:
            message_id: Remote message identifier.

        Returns:
            Dictionary containing original email text and metadata, or None if not found.
        """

    @abstractmethod
    def setup_watch(
        self, topic_name: str, label_ids: list[str] | None = None
    ) -> dict[str, Any]:
        """Sets up mailbox push notification subscription.

        Args:
            topic_name: Cloud Pub/Sub topic or webhook recipient name.
            label_ids: Optional list of mailbox labels to filter (e.g. ['INBOX']).

        Returns:
            Response containing subscription metadata and expiration timestamp.
        """
