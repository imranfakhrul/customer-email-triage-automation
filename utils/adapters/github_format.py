"""Pure formatting and sanitization functions for GitHub issue integration.

Guarantees:
1. System-owned correlation marker is strictly anchored at index 0 of issue body.
2. Output hardening: neutralizes user @mentions, #issue cross-links, HTML comments/tags,
   CRLF control characters, and bidi override spoofing.
3. Strict code block fencing ensures untrusted customer text is safely fenced.
4. Strict enum validation enforces project taxonomies.
"""

import re
from collections.abc import Sequence

from utils.adapters.base import DispatchPayload

MARKER_PREFIX = "<!-- triage-bot:v1"

ALLOWED_CATEGORIES: tuple[str, ...] = ("Bug Report", "Feature Request")
ALLOWED_PRIORITIES: tuple[str, ...] = ("Low", "Medium", "High", "Critical")
ALLOWED_SENTIMENTS: tuple[str, ...] = ("Positive", "Neutral", "Negative")
ALLOWED_EMOTIONS: tuple[str, ...] = ("Calm", "Frustrated", "Angry")
ALLOWED_TEAMS: tuple[str, ...] = (
    "Engineering",
    "Sales",
    "Billing",
    "Support",
    "Security",
)


def build_marker(idempotency_key: str) -> str:
    """Builds a system-owned correlation marker anchored to the top of an issue.

    Args:
        idempotency_key: Composite idempotency key matching ^[A-Za-z0-9._:-]{1,200}$.

    Returns:
        Structured marker string.

    Raises:
        ValueError: If idempotency_key is empty or violates format constraints.
    """
    if (
        not isinstance(idempotency_key, str)
        or not re.match(r"^[A-Za-z0-9._:-]{1,200}$", idempotency_key)
    ):
        raise ValueError(
            f"idempotency_key must match ^[A-Za-z0-9._:-]{{1,200}}$, got {idempotency_key!r}"
        )
    return f"{MARKER_PREFIX}\nkey: {idempotency_key}\n-->\n"


def parse_marker(body: str | None) -> str | None:
    """Extracts the idempotency key from an anchored marker at index 0 of body.

    A marker appearing later in the body (e.g. injected inside customer text)
    or preceded by any character (including whitespace or newline) is strictly ignored.

    Args:
        body: The issue body string or None.

    Returns:
        The extracted idempotency key string, or None if marker is absent/invalid.
    """
    if not body or not isinstance(body, str):
        return None
    if not body.startswith(MARKER_PREFIX):
        return None

    pattern = r"^<!-- triage-bot:v1\s*\nkey:\s*([A-Za-z0-9._:-]{1,200})\s*\n-->"
    match = re.match(pattern, body)
    if not match:
        return None
    return match.group(1)


def neutralize_text(text: str) -> str:
    """Sanitizes customer-controlled text against markdown injection and ping spam.

    Applied in strict sequential order:
    1. Normalise CRLF and CR to \n.
    2. Remove control characters except \n and \t.
    3. Remove bidi controls U+202A-U+202E and U+2066-U+2069.
    4. Insert U+200B zero-width space after '@' when followed by [A-Za-z0-9_-].
    5. Insert U+200B zero-width space after '#' when followed by [0-9].
    6. Replace '<!--' with '<!\u200b--' and '-->' with '--\u200b>'.

    Idempotent: neutralize_text(neutralize_text(x)) == neutralize_text(x).

    Args:
        text: Raw text to sanitize.

    Returns:
        Sanitized, injection-neutralized string.
    """
    if not text:
        return ""

    # 1. Normalise CRLF and CR to \n
    s = text.replace("\r\n", "\n").replace("\r", "\n")

    # 2. Remove control characters except \n and \t
    s = "".join(
        c for c in s if c in ("\n", "\t") or (ord(c) >= 32 and ord(c) != 127)
    )

    # 3. Remove bidi controls U+202A to U+202E and U+2066 to U+2069
    s = re.sub(r"[\u202A-\u202E\u2066-\u2069]", "", s)

    # 4. Insert zero-width space after @ when followed by alphanumeric/underscore/hyphen
    s = re.sub(r"@(?=[A-Za-z0-9_-])", "@\u200b", s)

    # 5. Insert zero-width space after # when followed by digit
    s = re.sub(r"#(?=[0-9])", "#\u200b", s)

    # 6. Neutralize HTML comments
    s = s.replace("<!--", "<!\u200b--").replace("-->", "--\u200b>")

    return s


def sanitize_title(subject: str, category: str) -> str:
    """Produces a clean issue title with category prefix and length bounds.

    Format: "[{category}] {text}"
    Where text is the neutralized subject with whitespace collapsed, or '(no subject)'.
    The total length is clamped to at most 120 characters.

    Args:
        subject: Incoming email subject line.
        category: Classified category (e.g. 'Bug Report', 'Feature Request').

    Returns:
        Clamped, sanitized title string <= 120 characters.
    """
    neutralized = neutralize_text(subject)
    collapsed = re.sub(r"\s+", " ", neutralized).strip()
    text = collapsed if collapsed else "(no subject)"
    full_title = f"[{category}] {text}"
    return full_title[:120]


def fence_block(text: str) -> str:
    """Wraps text inside a fenced code block with an adaptive backtick fence.

    The fence length is 1 longer than the longest backtick run inside text (minimum 3).

    Args:
        text: Text content to fence.

    Returns:
        Formatted code block: "{fence}text\n{content}\n{fence}\n".
    """
    backtick_runs = re.findall(r"`+", text)
    max_run = max((len(r) for r in backtick_runs), default=0)
    fence_len = max(3, max_run + 1)
    fence = "`" * fence_len

    content = text.rstrip("\n")
    return f"{fence}text\n{content}\n{fence}\n"


def build_issue_body(payload: DispatchPayload) -> str:
    """Constructs a complete, hardened GitHub issue Markdown body.

    Args:
        payload: Sanitized DispatchPayload.

    Returns:
        Hardened Markdown body string guaranteed under 30,000 characters.

    Raises:
        ValueError: If any taxonomy value is outside allowed sets.
    """
    if payload.category not in ALLOWED_CATEGORIES:
        raise ValueError(
            f"Invalid category '{payload.category}' for GitHub issue. "
            f"Allowed: {ALLOWED_CATEGORIES}"
        )
    if payload.priority not in ALLOWED_PRIORITIES:
        raise ValueError(
            f"Invalid priority '{payload.priority}'. Allowed: {ALLOWED_PRIORITIES}"
        )
    if payload.sentiment not in ALLOWED_SENTIMENTS:
        raise ValueError(
            f"Invalid sentiment '{payload.sentiment}'. Allowed: {ALLOWED_SENTIMENTS}"
        )
    if payload.customer_emotion not in ALLOWED_EMOTIONS:
        raise ValueError(
            f"Invalid customer_emotion '{payload.customer_emotion}'. "
            f"Allowed: {ALLOWED_EMOTIONS}"
        )
    if payload.suggested_team not in ALLOWED_TEAMS:
        raise ValueError(
            f"Invalid suggested_team '{payload.suggested_team}'. "
            f"Allowed: {ALLOWED_TEAMS}"
        )

    marker = build_marker(payload.idempotency_key)

    metadata_table = (
        "| Attribute | Value |\n"
        "|---|---|\n"
        f"| Category | {payload.category} |\n"
        f"| Priority | {payload.priority} |\n"
        f"| Sentiment | {payload.sentiment} |\n"
        f"| Customer Emotion | {payload.customer_emotion} |\n"
        f"| Confidence | {payload.confidence:.2f} |\n"
        f"| Suggested Team | {payload.suggested_team} |\n"
        f"| Classifier Used | {payload.p2_classifier_used} |\n"
        f"| Email ID | {payload.email_id} |\n"
    )

    # Clamping and fencing summary (max 1000 chars)
    clamped_summary = payload.summary[:1000]
    neutralized_summary = neutralize_text(clamped_summary)
    summary_block = fence_block(neutralized_summary)

    # Clamping and fencing customer message (max 8000 chars)
    customer_raw = f"Subject: {payload.masked_subject}\n\n{payload.masked_body}"[:8000]
    neutralized_customer = neutralize_text(customer_raw)
    customer_block = fence_block(neutralized_customer)

    body = (
        f"{marker}\n"
        "### Metadata\n"
        f"{metadata_table}\n"
        "## Summary (auto-generated, untrusted)\n"
        f"{summary_block}\n"
        "## Customer message (masked, untrusted)\n"
        f"{customer_block}"
    )

    return body[:30000]


def build_labels(
    payload: DispatchPayload,
    base_labels: Sequence[str],
) -> list[str]:
    """Builds deduplicated, validated GitHub labels for an issue.

    Order:
    1. Base labels from repository config.
    2. 'type:bug' or 'type:feature'.
    3. 'urgency:low|medium|high|critical'.

    Args:
        payload: Sanitized DispatchPayload.
        base_labels: Configured baseline labels for GitHub issues.

    Returns:
        List of unique, validated label strings.

    Raises:
        ValueError: If any label exceeds 50 characters, is empty, or contains a comma.
    """
    labels: list[str] = list(base_labels)

    type_label = (
        "type:bug" if payload.category == "Bug Report" else "type:feature"
    )
    urgency_label = f"urgency:{payload.priority.lower()}"

    labels.append(type_label)
    labels.append(urgency_label)

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for lbl in labels:
        if lbl not in seen:
            seen.add(lbl)
            deduped.append(lbl)

    # Validation
    for lbl in deduped:
        if (
            not isinstance(lbl, str)
            or not lbl.strip()
            or len(lbl) > 50
            or "," in lbl
        ):
            raise ValueError(
                f"Invalid label {lbl!r}: must be non-empty string <= 50 chars without commas"
            )

    return deduped
