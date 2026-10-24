"""Node 02: Signature and Quoted Reply Stripper.

This node performs privacy cleaning and token reduction by removing:
1. Quoted reply history (e.g., 'On <date> ... wrote:', '-----Original Message-----', Outlook headers).
2. Trailing quote lines (e.g., RFC 2822 lines starting with '>').
3. RFC 3676 signature delimiters ('-- ') and common sign-off blocks (e.g., 'Best regards', 'Thanks').
4. Mobile device signatures (e.g., 'Sent from my iPhone', 'Get Outlook for iOS').
5. Corporate confidentiality disclaimers and legal notices.

Preserves the customer's actual message while ensuring downstream LLMs and classifiers
receive clean, relevant input without wasting token context or leaking prior thread PII.
"""

import re
from typing import Any, Dict

from state import TriageState
from utils.text_tools import bounded_scan_text

# Regular expressions for reply thread boundaries
QUOTE_HEADERS = [
    # On <date> ... wrote / writes: (handles single-line and multi-line headers up to 500 chars)
    re.compile(
        r"(?mi)^\s*On\s+(?:(?!(?:\r?\n){2,})[\s\S]){1,500}?\s+(?:wrote|writes|schrieb|a écrit|escribió):\s*$"
    ),
    # -----Original Message----- or -----Forwarded Message-----
    re.compile(
        r"(?mi)^\s*-{3,}\s*(?:Original\s+Message|Forwarded\s+Message)\s*-{3,}\s*$"
    ),
    # 5+ underscores/hyphens used as divider
    re.compile(r"(?mi)^\s*_{5,}\s*$"),
    # Outlook header block: From: ... \n Sent/Date: ... \n To/Subject: ... (bounded to 200 chars per line)
    re.compile(
        r"(?mi)^\s*From:\s+.{0,200}?\r?\n\s*(?:Sent|Date):\s+.{0,200}?\r?\n\s*(?:To|Subject):\s+.{0,200}$"
    ),
]

# Indicators that subsequent lines contain code or technical configuration rather than a signature
CODE_INDICATORS = re.compile(
    r"(?:"
    r"^\s*//|"
    r"(?<!:)\s//\s|"
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|FROM|WHERE|DROP|ALTER|TABLE)\b|"
    r";\s*$|"
    r"[{}]|"
    r"=>"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# Mobile device signatures (bounded to 200 chars to prevent ReDoS)
MOBILE_SIGS = re.compile(
    r"(?mi)^\s*(?:Sent\s+from\s+my\s+(?:iPhone|iPad|Galaxy|Android|phone|mobile|smartphone|BlackBerry)|"
    r"Sent\s+from\s+Mail\s+for\s+\w+|"
    r"Get\s+Outlook\s+for\s+(?:iOS|Android)|"
    r"Sent\s+via\s+Superhuman)[^\r\n]{0,200}$"
)

# Patterns verifying legal disclaimer boilerplate
DISCLAIMER_PATTERNS = [
    re.compile(
        r"(?i)\b(?:confidential(?:ity)?\s+notice|privileged|intended\s+recipient|delete\s+immediately|transmission\s+in\s+error)\b"
    ),
    re.compile(
        r"(?i)\b(?:this\s+(?:email|e-mail|message)\s+(?:and\s+any\s+attachments\s+)?(?:is|are)\s+confidential)\b"
    ),
]

GREETING_REGEX = re.compile(
    r"(?i)^\s*(?:hi\b|hello\b|hey\b|dear\b|good\s+(?:morning|afternoon|evening))\s*.{0,200}[,\.!?-]?\s*$"
)


def is_legal_disclaimer(text: str) -> bool:
    """Checks whether the text block contains actual legal boilerplate terms."""
    scan = bounded_scan_text(text)
    return any(p.search(scan) for p in DISCLAIMER_PATTERNS)


def has_substantive_body(preceding_lines: list) -> bool:
    """Verifies that preceding lines contain substantive body text rather than only greetings."""
    substantive = [l for l in preceding_lines if l.strip() and not GREETING_REGEX.match(l)]
    return len(substantive) > 0


def looks_like_message_body(lines: list) -> bool:
    """Detects whether subsequent lines look like customer problem text rather than signature."""
    filtered = [l for l in lines if not is_legal_disclaimer(l)]
    for l in filtered:
        s = l.strip()
        if re.match(r"^\d+[\.\)]\s", s) or re.match(r"^[-\*]\s", s):
            return True
        if any(
            w in s.lower()
            for w in (
                "crashes",
                "error",
                "bug",
                "steps to reproduce",
                "reproduce",
                "failing",
                "problem",
                "broken",
            )
        ):
            return True
        if len(s) > 120:
            return True
    return False


# Common standalone sign-off closings
SIGN_OFF_REGEX = re.compile(
    r"(?i)^\s*(?:Best\s+regards|Warm\s+regards|Kind\s+regards|Regards|With\s+regards|"
    r"Thanks\s+and\s+regards|Thanks\s+&\s+regards|Many\s+thanks|Thanks|Thank\s+you|"
    r"Sincerely|Yours\s+sincerely|Yours\s+faithfully|Cheers|Best|Respectfully)"
    r"[,\.!?-]?\s*$"
)


def strip_signatures_and_quotes(text: str) -> str:
    """Strips quoted email replies, sign-offs, mobile signatures, and disclaimers.

    Rules:
    - Quoted headers and '>' blocks are stripped.
    - '-- ' (RFC 3676 with space) alone on a line in the last 10 lines is a signature boundary.
    - '--' (bare dashes) in the last 10 lines is cut only if followed by <= 6 short lines
      and no lines look like code (SELECT, ;, {}, =>, //).
    - Sign-offs are searched bottom-up in the last 10 non-empty lines with a >50% safety check.
    - Disclaimers ('Disclaimer', 'Important notice') are only cut in the bottom block if they
      contain true legal boilerplate. At the top of a message, they are preserved as customer text.
    - Empty fallback safety prevents accidental data loss.

    Args:
        text: The raw email body text to clean.

    Returns:
        Cleaned email body string.
    """
    if not text:
        return ""

    original = text.strip()
    if not original:
        return ""

    working = original

    # 1. Truncate at quoted reply headers (earliest match wins)
    earliest_quote_idx = None
    for pattern in QUOTE_HEADERS:
        match = pattern.search(working)
        if match:
            idx = match.start()
            if earliest_quote_idx is None or idx < earliest_quote_idx:
                earliest_quote_idx = idx

    if earliest_quote_idx is not None:
        working = working[:earliest_quote_idx].rstrip()

    # 2. Strip trailing quote lines (lines starting with '>')
    lines = working.splitlines()
    while lines and (lines[-1].strip().startswith(">") or not lines[-1].strip()):
        lines.pop()
    working = "\n".join(lines).rstrip()

    # 3. Strip mobile signatures if in the bottom 10 lines
    lines = working.splitlines()
    non_empty_indices = [i for i, l in enumerate(lines) if l.strip()]
    if not non_empty_indices:
        return original

    last_10_threshold = non_empty_indices[-10] if len(non_empty_indices) >= 10 else 0
    mobile_cut_idx = None
    for i in range(len(lines) - 1, max(-1, last_10_threshold - 1), -1):
        if MOBILE_SIGS.match(lines[i]):
            mobile_cut_idx = i
            break
    if mobile_cut_idx is not None:
        lines = lines[:mobile_cut_idx]
        working = "\n".join(lines).rstrip()

    # 4. Search bottom-up within the last 10 non-empty lines for delimiters, sign-offs, disclaimers
    lines = working.splitlines()
    non_empty_indices = [i for i, l in enumerate(lines) if l.strip()]
    if not non_empty_indices:
        return original

    last_10_start = non_empty_indices[-10] if len(non_empty_indices) >= 10 else 0
    candidate_cut = None

    for i in range(len(lines) - 1, max(-1, last_10_start - 1), -1):
        line = lines[i]
        line_stripped = line.strip()

        # Rule A: '-- ' (RFC 3676 with space) alone on a line
        if line == "-- ":
            candidate_cut = i
            break

        # Rule B: '--' alone on a line (no trailing space)
        if line_stripped == "--":
            subsequent = [l for l in lines[i + 1 :] if l.strip()]
            subsequent_text = "\n".join(subsequent)
            if (
                len(subsequent) <= 6
                and all(len(l) < 120 for l in subsequent)
                and not CODE_INDICATORS.search(subsequent_text)
            ):
                candidate_cut = i
                break

        # Rule C: Sign-off regex ('Thanks', 'Regards', etc.)
        if SIGN_OFF_REGEX.match(line):
            preceding = [l for l in lines[:i] if l.strip()]
            subsequent = [l for l in lines[i + 1 :] if l.strip()]
            if (
                has_substantive_body(preceding)
                and len(subsequent) <= 6
                and all(len(l) < 120 for l in subsequent)
            ):
                subsequent_text = "\n".join(subsequent)
                if not CODE_INDICATORS.search(subsequent_text) and not looks_like_message_body(
                    subsequent
                ):
                    candidate_cut = i
                    break

        # Rule D: Legal disclaimer in bottom block
        if any(
            re.match(
                r"(?i)^\s*(?:CONFIDENTIALITY\s+NOTICE|IMPORTANT\s+NOTICE|DISCLAIMER)\b",
                line,
            )
            for _ in [1]
        ):
            preceding = [l for l in lines[:i] if l.strip()]
            tail_text = "\n".join(lines[i:])
            if has_substantive_body(preceding) and is_legal_disclaimer(tail_text):
                candidate_cut = i
                break

    if candidate_cut is not None:
        proposed = "\n".join(lines[:candidate_cut]).rstrip()
        subsequent = [l for l in lines[candidate_cut:] if l.strip()]
        if has_substantive_body(proposed.splitlines()):
            if len(proposed.strip()) < 0.5 * len(working.strip()) and looks_like_message_body(
                subsequent
            ):
                pass
            else:
                working = proposed

    # 5. Clean up excessive consecutive blank lines (normalize to max 2 newlines)
    working = re.sub(r"\n{3,}", "\n\n", working).strip()

    # 6. Fallback safety: do not return empty if original had content
    return working if working else original


def signature_stripper_node(state: TriageState) -> Dict[str, Any]:
    """LangGraph node execution function for signature and quote stripping.

    Args:
        state: The current pipeline state containing 'raw_body' or 'email_body'.

    Returns:
        Dictionary update with 'cleaned_body' and synchronized 'email_body'.
    """
    raw_body = state.get("raw_body")
    if raw_body is None:
        raw_body = state.get("email_body", "")

    cleaned = strip_signatures_and_quotes(raw_body)

    return {
        "cleaned_body": cleaned,
        "email_body": cleaned,
    }
