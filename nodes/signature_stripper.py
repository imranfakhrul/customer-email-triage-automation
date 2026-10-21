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

# Regular expressions for reply thread boundaries
QUOTE_HEADERS = [
    # On <date> ... wrote / writes: (handles single-line and multi-line headers)
    re.compile(
        r"(?mi)^\s*On\s+(?:(?!(?:\r?\n){2,})[\s\S])+?\s+(?:wrote|writes|schrieb|a écrit|escribió):\s*$"
    ),
    # -----Original Message----- or -----Forwarded Message-----
    re.compile(
        r"(?mi)^\s*-{3,}\s*(?:Original\s+Message|Forwarded\s+Message)\s*-{3,}\s*$"
    ),
    # 5+ underscores/hyphens used as divider
    re.compile(r"(?mi)^\s*_{5,}\s*$"),
    # Outlook header block: From: ... \n Sent/Date: ... \n To/Subject: ...
    re.compile(
        r"(?mi)^\s*From:\s+.*?\r?\n\s*(?:Sent|Date):\s+.*?\r?\n\s*(?:To|Subject):\s+.*$"
    ),
]

# Standard signature delimiters and mobile signatures
DELIMITERS = [
    # RFC 3676 standard signature delimiter: dash-dash-space on its own line
    re.compile(r"(?m)^--\s*$"),
    # Mobile device signatures
    re.compile(
        r"(?mi)^\s*(?:Sent\s+from\s+my\s+(?:iPhone|iPad|Galaxy|Android|phone|mobile|smartphone|BlackBerry)|"
        r"Sent\s+from\s+Mail\s+for\s+\w+|"
        r"Get\s+Outlook\s+for\s+(?:iOS|Android)|"
        r"Sent\s+via\s+Superhuman).*$"
    ),
    # Legal and confidentiality disclaimers
    re.compile(
        r"(?mi)^\s*(?:CONFIDENTIALITY\s+NOTICE|IMPORTANT\s+NOTICE|DISCLAIMER|"
        r"This\s+(?:email|e-mail|message)\s+(?:and\s+any\s+attachments\s+)?(?:is|are)\s+confidential|"
        r"The\s+contents\s+of\s+this\s+(?:email|e-mail|message)\s+are\s+confidential|"
        r"If\s+you\s+(?:have\s+received|are\s+not)\s+this\s+(?:email|e-mail|transmission)\s+in\s+error).*$"
    ),
]

# Common standalone sign-off closings
SIGN_OFF_REGEX = re.compile(
    r"(?i)^\s*(?:Best\s+regards|Warm\s+regards|Kind\s+regards|Regards|With\s+regards|"
    r"Thanks\s+and\s+regards|Thanks\s+&\s+regards|Many\s+thanks|Thanks|Thank\s+you|"
    r"Sincerely|Yours\s+sincerely|Yours\s+faithfully|Cheers|Best|Respectfully)"
    r"[,\.!?-]?\s*$"
)


def strip_signatures_and_quotes(text: str) -> str:
    """Strips quoted email replies, sign-offs, mobile signatures, and disclaimers.

    Args:
        text: The raw email body text to clean.

    Returns:
        Cleaned email body string. If stripping would result in an empty string,
        the trimmed original text is returned as a fallback to avoid data loss.
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

    # 3. Strip signature delimiters, mobile signatures, and corporate disclaimers
    earliest_delim_idx = None
    for pattern in DELIMITERS:
        match = pattern.search(working)
        if match:
            idx = match.start()
            if earliest_delim_idx is None or idx < earliest_delim_idx:
                earliest_delim_idx = idx

    if earliest_delim_idx is not None:
        working = working[:earliest_delim_idx].rstrip()

    # 4. Check for standalone sign-off near the end of the text
    lines = working.splitlines()
    sign_off_idx = None
    for idx, line in enumerate(lines):
        if SIGN_OFF_REGEX.match(line):
            # Verify that following lines look like a signature block:
            # - At most 8 subsequent non-empty lines
            # - No long narrative paragraphs (each line < 120 chars)
            subsequent = [l.strip() for l in lines[idx + 1 :] if l.strip()]
            if len(subsequent) <= 8 and all(len(l) < 120 for l in subsequent):
                sign_off_idx = idx
                break

    if sign_off_idx is not None:
        lines = lines[:sign_off_idx]
        working = "\n".join(lines).rstrip()

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
