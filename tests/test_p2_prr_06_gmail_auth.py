"""Tests for PRR-06: Gmail SPF/DKIM/DMARC Header Spoof Defense & Token Parsing.

Guarantees:
1. Topmost Header Evaluation: Only the topmost (first) Authentication-Results header
   whose authserv-id is 'mx.google.com' is evaluated.
2. Injected Header Isolation: Attacker-controlled Authentication-Results headers appended
   lower down or preceding untrusted relays (e.g. attacker.com) are strictly rejected.
3. Subdomain / Partial Authserv Defense: Headers from 'mx.google.com.attacker.com' or
   'fake-mx.google.com' are not accepted as trusted Google authserv headers.
4. Token Boundary Parsing: Authentication status (pass, fail, softfail, neutral) is parsed
   by exact RFC 8601 method=result token boundaries rather than substring matches.
"""

from typing import Any

from utils.mailbox.gmail_connector import (
    extract_email_auth_results,
    parse_gmail_message_payload,
)


class TestGmailAuthResultsSpoofDefense:
    """Tests verifying spoof defenses and token parsing in extract_email_auth_results."""

    def test_topmost_mx_google_evaluated_ignoring_injected_lower_header(self) -> None:
        """Topmost Google header with 'fail' must win over injected 'pass' lower in the list."""
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "dkim=fail (bad signature); "
                    "spf=fail (ip 198.51.100.1 not authorized); "
                    "dmarc=fail (p=REJECT)"
                ),
            },
            {
                # Forged header injected by sender before reaching Gmail
                "name": "Authentication-Results",
                "value": "mx.google.com; dkim=pass; spf=pass; dmarc=pass",
            },
        ]

        result = extract_email_auth_results(headers)
        assert result["auth_status"] == "fail"
        assert result["dkim"] == "fail"
        assert result["spf"] == "fail"
        assert result["dmarc"] == "fail"

    def test_skips_untrusted_authserv_header_and_uses_topmost_google(self) -> None:
        """Untrusted authserv-id (e.g. attacker.com) is skipped in favor of real mx.google.com."""
        headers = [
            {
                # Intermediate relay or attacker-added header
                "name": "Authentication-Results",
                "value": "attacker.com; dkim=pass; spf=pass; dmarc=pass",
            },
            {
                # Real Google MTA header
                "name": "Authentication-Results",
                "value": "mx.google.com; dkim=fail; spf=fail; dmarc=fail",
            },
        ]

        result = extract_email_auth_results(headers)
        assert result["auth_status"] == "fail"
        assert result["dkim"] == "fail"
        assert result["spf"] == "fail"
        assert result["dmarc"] == "fail"

    def test_subdomain_spoof_authserv_rejected(self) -> None:
        """Domain like 'mx.google.com.evil.com' or 'fake-mx.google.com' is not accepted."""
        headers = [
            {
                "name": "Authentication-Results",
                "value": "mx.google.com.evil.org; dkim=pass; spf=pass; dmarc=pass",
            },
            {
                "name": "Authentication-Results",
                "value": "not-mx.google.com; dkim=pass; spf=pass; dmarc=pass",
            },
        ]

        result = extract_email_auth_results(headers)
        # Without any valid mx.google.com header, auth_status must be 'none'
        assert result["auth_status"] == "none"
        assert result["dkim"] == "none"
        assert result["spf"] == "none"
        assert result["dmarc"] == "none"

    def test_token_parsing_prevents_substring_bypass(self) -> None:
        """Exact token parsing prevents substring false-positives."""
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "test-dmarc=pass-not-real; "
                    "header.i=dmarc=pass@phishing.com; "
                    "dkim=fail; "
                    "spf=neutral; "
                    "dmarc=fail"
                ),
            }
        ]

        result = extract_email_auth_results(headers)
        assert result["auth_status"] == "fail"
        assert result["dmarc"] == "fail"
        assert result["dkim"] == "fail"
        assert result["spf"] == "neutral"

    def test_authentic_google_results_pass(self) -> None:
        """Legitimate Google Authentication-Results header correctly resolves to 'pass'."""
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "dkim=pass header.i=@legitcorp.com; "
                    "spf=pass (google.com: domain of support@legitcorp.com designates 192.0.2.1); "
                    "dmarc=pass (p=REJECT) header.from=legitcorp.com"
                ),
            }
        ]

        result = extract_email_auth_results(headers)
        assert result["auth_status"] == "pass"
        assert result["dkim"] == "pass"
        assert result["spf"] == "pass"
        assert result["dmarc"] == "pass"


class TestGmailMessagePayloadIntegration:
    """Integration test verifying parse_gmail_message_payload honors topmost Google header."""

    def test_parse_gmail_message_payload_spoof_resilience(self) -> None:
        """Full Gmail message resource with spoofed header lower down evaluates to 'fail'."""
        payload: dict[str, Any] = {
            "id": "msg_spoof_001",
            "threadId": "th_spoof_001",
            "snippet": "Urgent update requested",
            "payload": {
                "headers": [
                    {
                        "name": "Authentication-Results",
                        "value": (
                            "mx.google.com; "
                            "dkim=fail (bad signature); "
                            "spf=fail; "
                            "dmarc=fail"
                        ),
                    },
                    {
                        "name": "Authentication-Results",
                        "value": "mx.google.com; dkim=pass; spf=pass; dmarc=pass",
                    },
                    {"name": "Subject", "value": "Payment confirmation"},
                    {"name": "From", "value": "Spoofed User <vip@client.com>"},
                ],
                "mimeType": "text/plain",
                "body": {"data": "UGxlYXNlIHNlbmQgbW9uZXku"},  # "Please send money."
            },
        }

        parsed = parse_gmail_message_payload(payload)
        assert parsed["auth_status"] == "fail"
        assert parsed["email_id"] == "msg_spoof_001"
        assert parsed["sender_email"] == "vip@client.com"
