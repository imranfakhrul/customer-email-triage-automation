"""Gmail Mailbox Connector using Gmail REST API v1.

Handles:
1. Least-privilege OAuth 2.0 lifecycle & token refresh
2. Base64url MIME decoding and multipart navigation
3. Cryptographic SPF / DKIM / DMARC authentication header evaluation (closing A5)
4. Incremental history sync via users.history.list
5. Authorized original-text re-fetch by message ID
"""

import base64
import html
import logging
import os
import re
from typing import Any

import requests

from utils.config import get_config
from utils.mailbox.base import BaseMailboxConnector

logger = logging.getLogger(__name__)


def decode_base64url(data: str) -> str:
    """Decodes a base64url-encoded string with automatic padding handling.

    Args:
        data: Base64url encoded string (padded or unpadded).

    Returns:
        Decoded UTF-8 string with errors replaced safely.
    """
    if not data:
        return ""
    clean_data = data.strip().replace("-", "+").replace("_", "/")
    missing_padding = len(clean_data) % 4
    if missing_padding:
        clean_data += "=" * (4 - missing_padding)
    decoded_bytes = base64.b64decode(clean_data.encode("utf-8"), validate=False)
    return decoded_bytes.decode("utf-8", errors="replace")


def _clean_html_text(html_text: str) -> str:
    """Strips HTML tags and unescapes HTML entities for plain-text fallback."""
    if not html_text:
        return ""
    # Strip script and style tags
    clean = re.sub(
        r"<(script|style)[^>]*>.*?</\1>", " ", html_text, flags=re.DOTALL | re.IGNORECASE
    )
    # Strip remaining HTML tags
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    # Collapse multiple whitespaces
    return " ".join(clean.split())


def _is_trusted_gmail_auth_header(value: str) -> bool:
    """Verifies that the Authentication-Results header originates from Google (mx.google.com).

    In RFC 8601, the header begins with authserv-id. Gmail's inbound MTA writes 'mx.google.com'.
    Ensures that domain suffixes like 'mx.google.com.attacker.com' or other MTAs are rejected.
    """
    val = value.strip().lower()
    if not val.startswith("mx.google.com"):
        return False
    if len(val) == len("mx.google.com"):
        return True
    return val[len("mx.google.com")] in (";", " ", "\t", "\r", "\n")


def extract_email_auth_results(
    headers: list[dict[str, Any]] | dict[str, Any],
) -> dict[str, str]:
    """Evaluates cryptographic SPF, DKIM, and DMARC authentication headers.

    Extracts Authentication-Results (RFC 8601) and Received-SPF (RFC 7208).
    Enforces that only the topmost (first) Authentication-Results header with
    authserv-id 'mx.google.com' is trusted, and parses exact method=result tokens.

    Args:
        headers: List of header dicts (`[{'name': ..., 'value': ...}]`) or dict.

    Returns:
        Dictionary with keys 'auth_status', 'spf', 'dkim', 'dmarc'.
    """
    auth_results = ""
    received_spf = ""

    if isinstance(headers, list):
        for h in headers:
            if not isinstance(h, dict):
                continue
            name = str(h.get("name", "")).strip().lower()
            val = str(h.get("value", "")).strip()
            # PRR-06: Use ONLY the topmost (first) Authentication-Results header
            # whose authserv-id is mx.google.com. Never allow lower headers to overwrite it.
            if name == "authentication-results" and not auth_results:
                if _is_trusted_gmail_auth_header(val):
                    auth_results = val.lower()
            elif name == "received-spf" and not received_spf:
                received_spf = val.lower()
    elif isinstance(headers, dict):
        for k, v in headers.items():
            name = str(k).strip().lower()
            val = str(v).strip()
            if name == "authentication-results" and not auth_results:
                if _is_trusted_gmail_auth_header(val):
                    auth_results = val.lower()
            elif name == "received-spf" and not received_spf:
                received_spf = val.lower()

    # Default to none
    spf_val = "none"
    dkim_val = "none"
    dmarc_val = "none"

    # PRR-06: Parse RFC 8601 method=result tokens using bounded token boundaries
    # rather than naive substring matching.
    if auth_results:
        # DKIM token evaluation
        dkim_tokens = re.findall(r"(?:^|[\s;])dkim=([a-z0-9_-]+)", auth_results)
        if "fail" in dkim_tokens:
            dkim_val = "fail"
        elif "pass" in dkim_tokens:
            dkim_val = "pass"
        elif dkim_tokens:
            dkim_val = dkim_tokens[0]

        # DMARC token evaluation
        dmarc_tokens = re.findall(r"(?:^|[\s;])dmarc=([a-z0-9_-]+)", auth_results)
        if "fail" in dmarc_tokens:
            dmarc_val = "fail"
        elif "pass" in dmarc_tokens:
            dmarc_val = "pass"
        elif dmarc_tokens:
            dmarc_val = dmarc_tokens[0]

        # SPF token evaluation from Authentication-Results
        spf_tokens = re.findall(r"(?:^|[\s;])spf=([a-z0-9_-]+)", auth_results)
        if "fail" in spf_tokens:
            spf_val = "fail"
        elif "pass" in spf_tokens:
            spf_val = "pass"
        elif "softfail" in spf_tokens:
            spf_val = "softfail"
        elif "neutral" in spf_tokens:
            spf_val = "neutral"
        elif spf_tokens:
            spf_val = spf_tokens[0]

    # Evaluate Received-SPF fallback if SPF was not resolved via Authentication-Results
    if spf_val == "none" and received_spf:
        if received_spf.startswith("pass"):
            spf_val = "pass"
        elif received_spf.startswith("fail"):
            spf_val = "fail"
        elif received_spf.startswith("softfail"):
            spf_val = "softfail"
        elif received_spf.startswith("neutral"):
            spf_val = "neutral"

    # Compute aggregate auth_status
    if dkim_val == "fail" or spf_val == "fail" or dmarc_val == "fail":
        auth_status = "fail"
    elif (dkim_val == "pass" and spf_val == "pass") or dmarc_val == "pass":
        auth_status = "pass"
    elif spf_val in ("softfail", "neutral"):
        auth_status = "neutral"
    else:
        auth_status = "none"

    return {
        "auth_status": auth_status,
        "spf": spf_val,
        "dkim": dkim_val,
        "dmarc": dmarc_val,
    }


def parse_gmail_message_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Parses a full Gmail message resource into normalized intake state.

    Args:
        payload: Full Gmail message JSON object from users.messages.get.

    Returns:
        Normalized email intake dictionary.
    """
    msg_id = str(payload.get("id") or "")
    thread_id = str(payload.get("threadId") or msg_id)
    inner_payload = payload.get("payload", {})
    headers = inner_payload.get("headers", [])

    header_dict: dict[str, str] = {}
    for h in headers:
        header_dict[str(h.get("name", "")).lower()] = str(h.get("value", ""))

    email_subject = header_dict.get("subject", "").strip()
    from_raw = header_dict.get("from", "").strip()
    message_id = header_dict.get("message-id", f"<{msg_id}@mail.gmail.com>")

    # Extract sender email and domain
    sender_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", from_raw)
    sender_email = sender_match.group(0).lower() if sender_match else from_raw.lower()
    sender_domain = sender_email.split("@", 1)[1].lower() if "@" in sender_email else ""

    # Extract body content
    plain_body = ""
    html_body = ""

    def _walk_parts(part: dict[str, Any]) -> None:
        nonlocal plain_body, html_body
        mime_type = str(part.get("mimeType", "")).lower()
        body_data = part.get("body", {}).get("data", "")

        if mime_type == "text/plain" and body_data and not plain_body:
            plain_body = decode_base64url(body_data)
        elif mime_type == "text/html" and body_data and not html_body:
            html_body = decode_base64url(body_data)

        for subpart in part.get("parts", []):
            _walk_parts(subpart)

    # If single-part root body
    root_mime = str(inner_payload.get("mimeType", "")).lower()
    root_data = inner_payload.get("body", {}).get("data", "")
    if root_mime == "text/plain" and root_data:
        plain_body = decode_base64url(root_data)
    elif root_mime == "text/html" and root_data:
        html_body = decode_base64url(root_data)

    for p in inner_payload.get("parts", []):
        _walk_parts(p)

    resolved_body = plain_body if plain_body else _clean_html_text(html_body)
    if not resolved_body:
        resolved_body = str(payload.get("snippet") or "")

    auth_info = extract_email_auth_results(headers)

    return {
        "email_id": msg_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "email_subject": email_subject,
        "email_body": resolved_body,
        "raw_body": resolved_body,
        "has_attachments": bool(inner_payload.get("parts") and len(inner_payload["parts"]) > 2),
        "auth_status": auth_info["auth_status"],
        "auth_details": auth_info,
    }


class GmailConnector(BaseMailboxConnector):
    """Production Gmail connector implementing OAuth 2.0 and Pub/Sub notifications."""

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        refresh_token: str | None = None,
        access_token: str | None = None,
        user_id: str = "me",
        config: dict[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        """Initializes Gmail connector.

        Credentials default to config or environment variables:
        - GMAIL_CLIENT_ID
        - GMAIL_CLIENT_SECRET
        - GMAIL_REFRESH_TOKEN
        - GMAIL_ACCESS_TOKEN
        """
        cfg = config or get_config()
        mb_cfg = cfg.get("mailbox", {}).get("gmail", {})

        self._client_id = client_id or os.environ.get("GMAIL_CLIENT_ID", "")
        self._client_secret = client_secret or os.environ.get("GMAIL_CLIENT_SECRET", "")
        self._refresh_token = refresh_token or os.environ.get("GMAIL_REFRESH_TOKEN", "")
        self._access_token = access_token or os.environ.get("GMAIL_ACCESS_TOKEN", "")
        self._user_id = user_id or mb_cfg.get("user_id", "me")
        self._base_url = mb_cfg.get("api_base_url", "https://gmail.googleapis.com")
        self._session = session or requests.Session()

    def get_valid_access_token(self) -> str:
        """Returns active access token, refreshing via OAuth token endpoint if needed."""
        if self._access_token:
            return self._access_token

        if not (self._refresh_token and self._client_id and self._client_secret):
            return ""

        oauth_endpoint = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": self._refresh_token,
            "grant_type": "refresh_token",
        }
        resp = self._session.post(oauth_endpoint, data=data, timeout=10.0)
        if resp.status_code == 200:
            token_json = resp.json()
            self._access_token = token_json.get("access_token", "")
            return self._access_token
        logger.error(f"[GmailConnector] Failed to refresh token: HTTP {resp.status_code}")
        return ""

    def _get_headers(self) -> dict[str, str]:
        token = self.get_valid_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def fetch_new_messages(
        self,
        start_history_id: str | None = None,
        max_pages: int = 5,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetches newly added messages via incremental history sync.

        Args:
            start_history_id: Optional historyId to sync incrementally from.
            max_pages: Maximum number of pagination pages to retrieve (default: 5).

        Returns:
            List of newly added Gmail message dicts.
        """
        seen_ids: set[str] = set()
        new_messages: list[dict[str, Any]] = []

        if start_history_id:
            url = f"{self._base_url}/gmail/v1/users/{self._user_id}/history"
            page_token: str | None = None
            page_count = 0

            while page_count < max_pages:
                params: dict[str, Any] = {
                    "startHistoryId": start_history_id,
                    "historyTypes": "messageAdded",
                }
                if page_token:
                    params["pageToken"] = page_token

                headers = self._get_headers()
                resp = self._session.get(url, headers=headers, params=params, timeout=15.0)

                if resp.status_code == 401:
                    # Token expired mid-session; refresh once
                    self._access_token = ""  # nosec B105
                    headers = self._get_headers()
                    resp = self._session.get(url, headers=headers, params=params, timeout=15.0)

                if resp.status_code != 200:
                    logger.error(f"[GmailConnector] History sync failed: HTTP {resp.status_code}")
                    break

                data = resp.json()
                for record in data.get("history", []):
                    for item in record.get("messagesAdded", []):
                        msg = item.get("message", {})
                        mid = msg.get("id")
                        if mid and mid not in seen_ids:
                            seen_ids.add(mid)
                            new_messages.append(msg)

                page_token = data.get("nextPageToken")
                if not page_token:
                    break
                page_count += 1

            return new_messages

        # Initial bulk fetch
        url = f"{self._base_url}/gmail/v1/users/{self._user_id}/messages"
        page_token = None
        page_count = 0

        while page_count < max_pages:
            params = {"maxResults": 20}
            if query:
                params["q"] = query
            if page_token:
                params["pageToken"] = page_token

            headers = self._get_headers()
            resp = self._session.get(url, headers=headers, params=params, timeout=15.0)

            if resp.status_code == 401:
                # Token expired mid-session; refresh once
                self._access_token = ""  # nosec B105
                headers = self._get_headers()
                resp = self._session.get(url, headers=headers, params=params, timeout=15.0)

            if resp.status_code != 200:
                logger.error(f"[GmailConnector] Message fetch failed: HTTP {resp.status_code}")
                break

            data = resp.json()
            messages_list = data.get("messages", [])
            for m in messages_list:
                if isinstance(m, dict):
                    mid = m.get("id")
                    if mid and mid not in seen_ids:
                        seen_ids.add(mid)
                        new_messages.append(dict(m))

            page_token = data.get("nextPageToken")
            if not page_token:
                break
            page_count += 1

        return new_messages

    def refetch_original_email(self, message_id: str) -> dict[str, Any] | None:
        """Authorized re-fetch of unmasked original email by message ID."""
        headers = self._get_headers()
        url = f"{self._base_url}/gmail/v1/users/{self._user_id}/messages/{message_id}"
        resp = self._session.get(url, headers=headers, params={"format": "full"}, timeout=15.0)

        if resp.status_code == 401:
            # Token expired mid-session; refresh once
            self._access_token = ""  # nosec B105
            headers = self._get_headers()
            resp = self._session.get(url, headers=headers, params={"format": "full"}, timeout=15.0)

        if resp.status_code != 200:
            logger.warning(
                f"[GmailConnector] refetch_original_email failed: {resp.status_code}"
            )
            return None

        payload = resp.json()
        return parse_gmail_message_payload(payload)

    def setup_watch(
        self, topic_name: str, label_ids: list[str] | None = None
    ) -> dict[str, Any]:
        """Sets up or renews Cloud Pub/Sub watch subscription."""
        headers = self._get_headers()
        url = f"{self._base_url}/gmail/v1/users/{self._user_id}/watch"
        body = {
            "topicName": topic_name,
            "labelIds": label_ids or ["INBOX"],
        }
        resp = self._session.post(url, headers=headers, json=body, timeout=15.0)

        if resp.status_code == 401:
            # Token expired; refresh once
            self._access_token = ""  # nosec B105
            headers = self._get_headers()
            resp = self._session.post(url, headers=headers, json=body, timeout=15.0)

        if resp.status_code != 200:
            logger.error(f"[GmailConnector] setup_watch failed: HTTP {resp.status_code}")
            return {"error": f"HTTP {resp.status_code}"}
        result = resp.json()
        return dict(result) if isinstance(result, dict) else {}
