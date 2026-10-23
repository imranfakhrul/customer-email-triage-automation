"""Unit tests for Node 02 Signature and Quoted Reply Stripper."""

import unittest

from nodes.signature_stripper import (
    signature_stripper_node,
    strip_signatures_and_quotes,
)
from state import TriageState


class TestSignatureStripper(unittest.TestCase):
    def test_strip_standard_quote_and_signoff(self):
        """Verifies stripping of standard sign-off block and 'On ... wrote:' quoted reply."""
        raw_email = (
            "Hi Support,\n\n"
            "Our API integration is returning 401 Unauthorized since this morning.\n"
            "We verified our API keys are correct.\n\n"
            "Best regards,\n"
            "John Doe\n"
            "DevOps Lead, Acme Corp\n"
            "+1 555-0199\n\n"
            "On Mon, Oct 20, 2026 at 10:00 AM Support <support@example.com> wrote:\n"
            "> Hi John,\n"
            "> Did you rotate your tokens recently?\n"
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        expected = (
            "Hi Support,\n\n"
            "Our API integration is returning 401 Unauthorized since this morning.\n"
            "We verified our API keys are correct."
        )
        self.assertEqual(cleaned, expected)

    def test_strip_multiline_on_wrote_header(self):
        """Verifies stripping when 'On ... wrote:' spans across lines."""
        raw_email = (
            "Could we schedule a call tomorrow at 2 PM?\n\n"
            "On Mon, Oct 20, 2026 at 10:00 AM\n"
            "Sarah Connor <sarah@skynet.com> wrote:\n"
            "> Let me know when you are free."
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, "Could we schedule a call tomorrow at 2 PM?")

    def test_strip_outlook_original_message(self):
        """Verifies stripping of Outlook '-----Original Message-----' header block."""
        raw_email = (
            "Please see the update below. The fix resolved our issue.\n\n"
            "-----Original Message-----\n"
            "From: Jane Smith [mailto:jane@client.com]\n"
            "Sent: Friday, October 17, 2026 3:45 PM\n"
            "To: support@example.com\n"
            "Subject: RE: High Priority - System Outage\n\n"
            "System is still down."
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(
            cleaned, "Please see the update below. The fix resolved our issue."
        )

    def test_strip_outlook_from_sent_block(self):
        """Verifies stripping of Outlook reply block without separator dashes."""
        raw_email = (
            "Thanks for the quick turnaround.\n\n"
            "From: Support Team <support@saas.com>\n"
            "Sent: Tuesday, October 21, 2026 9:00 AM\n"
            "To: client@customer.com\n"
            "Subject: Your Ticket #48291\n\n"
            "We have applied the patch."
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, "Thanks for the quick turnaround.")

    def test_strip_underscore_divider(self):
        """Verifies stripping of underscore line separator preceding reply content."""
        raw_email = (
            "Here is the log file you requested.\n\n"
            "________________________________\n"
            "From: Alex\n"
            "Can you send logs?"
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, "Here is the log file you requested.")

    def test_strip_rfc3676_delimiter(self):
        """Verifies stripping at RFC 3676 signature delimiter ('-- ')."""
        raw_email = (
            "I would like to request a demo for 50 users.\n\n"
            "-- \n"
            "Dr. Robert Paulson\n"
            "Director of Analytics\n"
            "robert@university.edu"
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(
            cleaned, "I would like to request a demo for 50 users."
        )

    def test_strip_mobile_signatures(self):
        """Verifies stripping of mobile device signature lines."""
        mobile_cases = [
            ("Can you extend our trial?\n\nSent from my iPhone", "Can you extend our trial?"),
            ("Issue persists.\n\nSent from my Galaxy", "Issue persists."),
            ("Will check back later.\n\nSent from my Android phone", "Will check back later."),
            ("Approved.\n\nGet Outlook for iOS", "Approved."),
            ("Let's proceed.\n\nSent via Superhuman", "Let's proceed."),
        ]
        for raw, expected in mobile_cases:
            with self.subTest(raw=raw):
                self.assertEqual(strip_signatures_and_quotes(raw), expected)

    def test_strip_confidentiality_disclaimers(self):
        """Verifies stripping of legal disclaimers at the end of messages."""
        raw_email = (
            "Where can I find the invoices for August 2026?\n\n"
            "CONFIDENTIALITY NOTICE: This transmission may contain confidential "
            "information. If you are not the intended recipient, please delete immediately."
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(
            cleaned, "Where can I find the invoices for August 2026?"
        )

    def test_strip_trailing_quotes(self):
        """Verifies stripping of trailing '>' quotes without reply headers."""
        raw_email = (
            "Here is my response.\n\n"
            "> Previous message line 1\n"
            "> Previous message line 2\n"
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, "Here is my response.")

    def test_preserves_inline_quotes(self):
        """Verifies that blockquoted code or error messages in the body are preserved."""
        raw_email = (
            "Hi Support,\n\n"
            "I received the following error in the console:\n"
            "> Error 500: Database connection timed out\n\n"
            "Please advise how to resolve this."
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, raw_email)

    def test_preserves_thank_you_in_body(self):
        """Verifies 'Thank you' mid-body is not prematurely cut as a sign-off."""
        raw_email = (
            "Thank you for the quick response.\n"
            "However, the button is still disabled on Chrome.\n\n"
            "Kind regards,\n"
            "Sarah"
        )
        cleaned = strip_signatures_and_quotes(raw_email)
        expected = (
            "Thank you for the quick response.\n"
            "However, the button is still disabled on Chrome."
        )
        self.assertEqual(cleaned, expected)

    def test_opening_thank_you_three_line_email_preserved(self):
        """Verifies short email starting with 'Thank you.' is fully preserved."""
        raw_email = "Thank you.\nOur server is crashing.\nPlease help."
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, raw_email)

    def test_fallback_on_only_signature(self):
        """Verifies safety fallback: does not return empty string when input has only signature."""
        raw_email = "Best regards,\nJohn"
        cleaned = strip_signatures_and_quotes(raw_email)
        self.assertEqual(cleaned, "Best regards,\nJohn")

    def test_empty_and_whitespace_inputs(self):
        """Verifies handling of empty, None, or whitespace inputs."""
        self.assertEqual(strip_signatures_and_quotes(""), "")
        self.assertEqual(strip_signatures_and_quotes(None), "")
        self.assertEqual(strip_signatures_and_quotes("   \n\t  "), "")

    def test_signature_stripper_node_updates_state(self):
        """Verifies LangGraph node execution correctly updates cleaned_body and email_body."""
        raw_text = (
            "Can you refund our latest invoice?\n\n"
            "Thanks and regards,\n"
            "Michael Scott\n"
            "Regional Manager"
        )
        state: TriageState = {
            "email_id": "test_refund_1",
            "message_id": "msg_001",
            "thread_id": "th_001",
            "sender_email": "michael@dundermifflin.com",
            "sender_domain": "dundermifflin.com",
            "email_subject": "Refund Request",
            "email_body": raw_text,
            "raw_body": raw_text,
            "has_attachments": False,
            "cleaned_body": None,
            "masked_body": None,
            "token_map": {},
            "is_sensitive": False,
            "sensitive_reason": None,
            "is_spam": None,
            "gatekeeper_decision": None,
            "gatekeeper_confidence": None,
            "is_threat": None,
            "threat_details": None,
            "customer_tier": None,
            "sla_target": None,
            "classification": None,
            "labels_to_apply": [],
            "is_starred": False,
            "dispatch_target": None,
            "dispatch_status": "processing",
            "retry_count": 0,
            "error_message": None,
            "routing_status": "processing",
            "is_active_thread": False,
        }

        output = signature_stripper_node(state)

        self.assertIn("cleaned_body", output)
        self.assertIn("email_body", output)
        self.assertEqual(output["cleaned_body"], "Can you refund our latest invoice?")
        self.assertEqual(output["email_body"], "Can you refund our latest invoice?")

    def test_b1_bug_report_starting_with_thanks_preserved(self):
        """Verifies bug reports with an opening 'Thanks' are not prematurely cut."""
        raw = "Hi team,\nThanks.\nThe export button crashes when clicking on it.\nSteps to reproduce:\n1. Go to exports\n2. Click export"
        self.assertEqual(strip_signatures_and_quotes(raw), raw)

    def test_b1_important_notice_at_top_preserved(self):
        """Verifies 'Important notice' at the top of an email is treated as customer text, not a disclaimer."""
        raw = "Hello,\nImportant notice: since v2.3 the export crashes when generating CSVs."
        self.assertEqual(strip_signatures_and_quotes(raw), raw)

    def test_b1_disclaimer_at_top_preserved(self):
        """Verifies 'Disclaimer' at the top of an email is treated as customer text."""
        raw = "Disclaimer: I'm not an admin, but our dashboard shows high CPU alerts on worker 4."
        self.assertEqual(strip_signatures_and_quotes(raw), raw)

    def test_b1_sql_query_with_bare_dashes_not_cut(self):
        """Verifies a pasted SQL query with a bare '--' comment line is preserved."""
        raw = (
            "Hi team, here is the failing query:\n"
            "SELECT id, name\n"
            "FROM users\n"
            "--\n"
            "WHERE active = 1;"
        )
        self.assertEqual(strip_signatures_and_quotes(raw), raw)

    def test_b1_real_signature_bare_dashes_cut(self):
        """Verifies a real signature starting with bare '--' (no trailing space) is cleanly cut."""
        raw = "Can we meet tomorrow to review the proposal?\n\n--\nJohn Doe\n+1 555 0100"
        self.assertEqual(strip_signatures_and_quotes(raw), "Can we meet tomorrow to review the proposal?")

    def test_b1_real_signature_rfc_dashes_cut(self):
        """Verifies a real signature starting with RFC 3676 '-- ' (with space) is cleanly cut."""
        raw = "I need assistance with my account access.\n\n-- \nJohn Doe"
        self.assertEqual(strip_signatures_and_quotes(raw), "I need assistance with my account access.")

    def test_b1_three_line_email_starting_with_thank_you_preserved(self):
        """Verifies short 3-line email starting with 'Thank you.' is preserved by safety check."""
        raw = "Thank you.\nOur server is crashing.\nPlease help."
        self.assertEqual(strip_signatures_and_quotes(raw), raw)

    def test_b1_safety_check_stripping_more_than_half_aborts(self):
        """Verifies direct safety rule: if stripping would remove more than half of the message,
        do not strip and keep the original text."""
        raw = (
            "Hi Support,\n"
            "Thanks,\n"
            "The database connection fails on replica 3.\n"
            "Logs:\n"
            "Error: Connection refused at 10.0.0.5:5432\n"
            "Please investigate immediately."
        )
        self.assertEqual(strip_signatures_and_quotes(raw), raw)


if __name__ == "__main__":
    unittest.main()
