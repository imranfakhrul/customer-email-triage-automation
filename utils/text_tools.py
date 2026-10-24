"""Text scanning and processing utilities for security guardrails."""

from typing import Any, Dict, Optional


def bounded_scan_text(
    text: str,
    head: int = 10000,
    tail: int = 2000,
    config: Optional[Dict[str, Any]] = None,
) -> str:
    """Returns a bounded text slice (head + tail) for safe heuristic regex scanning.

    If len(text) > head + tail, extracts the first `head` characters and the last
    `tail` characters separated by a newline, preventing ReDoS on long inputs while
    ensuring padding attacks cannot hide payloads at the end of the input.

    Args:
        text: Input customer text to be scanned.
        head: Number of characters to scan from the beginning (default 10,000).
        tail: Number of characters to scan from the end (default 2,000).
        config: Optional configuration dictionary containing security.regex_scan_head
                and security.regex_scan_tail.

    Returns:
        The full text if len(text) <= head + tail, or `text[:head] + "\n" + text[-tail:]`.
    """
    if not text:
        return ""

    if config and isinstance(config, dict):
        sec = config.get("security", {})
        if isinstance(sec, dict):
            if "regex_scan_head" in sec:
                try:
                    head = int(sec["regex_scan_head"])
                except (ValueError, TypeError):
                    pass
            if "regex_scan_tail" in sec:
                try:
                    tail = int(sec["regex_scan_tail"])
                except (ValueError, TypeError):
                    pass

    total_len = len(text)

    if head <= 0 and tail <= 0:
        return ""
    if head <= 0:
        return text[-tail:] if (tail > 0 and tail < total_len) else text
    if tail <= 0:
        return text[:head]

    if total_len <= head + tail:
        return text

    return text[:head] + "\n" + text[-tail:]
