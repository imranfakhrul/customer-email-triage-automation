"""Unit tests for main.py CLI PII suppression and entity count summaries."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid


class TestMainCliPiiSuppression(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_main_input_suppresses_raw_pii_and_shows_entity_counts(self):
        """Verifies running main.py --input on email with PII outputs zero plaintext values in stdout/stderr."""
        raw_name = "Jane Doe"
        raw_email = "jane.doe@enterprise-triage.org"
        raw_card = "4111 1111 1111 1111"

        nonce = uuid.uuid4().hex[:8]
        email_payload = {
            "email_id": f"em_cli_test_{nonce}_01",
            "message_id": f"<msg-cli-{nonce}-01@enterprise.org>",
            "thread_id": f"th-cli-{nonce}-01",
            "sender_email": f"{raw_name} <{raw_email}>",
            "sender_domain": "enterprise-triage.org",
            "email_subject": f"Inquiry from {raw_name} regarding card {raw_card}",
            "email_body": (
                f"Hello support team,\n\n"
                f"My name is {raw_name} and my email address is {raw_email}.\n"
                f"Please update my billing payment card {raw_card}.\n\n"
                f"Thanks,\n{raw_name}"
            ),
        }

        test_file = os.path.join(self.temp_dir.name, "test_pii_email.json")
        with open(test_file, "w", encoding="utf-8") as f:
            json.dump(email_payload, f)

        # Run main.py --input via subprocess
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "main.py", "--input", test_file, "--offline"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 0, f"Process failed with stderr: {proc.stderr}")
        stdout = proc.stdout
        stderr = proc.stderr

        # 1. Assert raw PII never appears in stdout or stderr
        self.assertNotIn(raw_name, stdout)
        self.assertNotIn(raw_name, stderr)
        self.assertNotIn(raw_email, stdout)
        self.assertNotIn(raw_email, stderr)
        self.assertNotIn(raw_card, stdout)
        self.assertNotIn(raw_card, stderr)
        self.assertNotIn(raw_card.replace(" ", ""), stdout)
        self.assertNotIn(raw_card.replace(" ", ""), stderr)

        # 2. Assert raw token_map dictionary is NOT printed
        self.assertNotIn('"token_map":', stdout)

        # 3. Assert pii_entity_counts is present and shows expected counts
        self.assertIn('"pii_entity_counts":', stdout)
        json_marker = "--- Pipeline Triage Result ---"
        self.assertIn(json_marker, stdout)
        json_part = stdout.split(json_marker, 1)[1].strip()
        parsed = json.loads(json_part)

        counts = parsed.get("pii_entity_counts", {})
        self.assertIn("PERSON", counts)
        self.assertGreaterEqual(counts["PERSON"], 1)
        self.assertIn("EMAIL", counts)
        self.assertGreaterEqual(counts["EMAIL"], 1)
        self.assertIn("CREDIT_CARD", counts)
        self.assertGreaterEqual(counts["CREDIT_CARD"], 1)

    def test_main_input_exception_path_suppresses_raw_pii(self):
        """Verifies that when an exception occurs during email processing, no raw PII appears in stdout/stderr."""
        raw_name = "SuperSecretPerson"
        raw_email = "secret.user@classified-domain.org"
        raw_card = "4222 3333 4444 5555"

        email_payload = {
            "email_id": f"em_cli_err_{os.getpid()}_01",
            "sender_email": f"{raw_name} <{raw_email}>",
            "email_subject": f"Secret issue {raw_card}",
            "email_body": f"Sensitive data for {raw_name} {raw_email} {raw_card}",
        }

        test_file = os.path.join(self.temp_dir.name, "test_err_email.json")
        with open(test_file, "w", encoding="utf-8") as f:
            json.dump(email_payload, f)

        # Run python code via subprocess that patches run_triage_pipeline to raise an error
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        injection_code = (
            "import main, unittest.mock as mock; "
            "mock.patch('main.run_triage_pipeline', side_effect=RuntimeError('Simulated internal engine failure')).start(); "
            "main.main()"
        )
        proc = subprocess.run(
            [sys.executable, "-c", injection_code, "--input", test_file, "--offline"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(proc.returncode, 0)
        stdout = proc.stdout
        stderr = proc.stderr

        # Assert raw PII never appears in stdout or stderr on failure
        self.assertNotIn(raw_name, stdout)
        self.assertNotIn(raw_name, stderr)
        self.assertNotIn(raw_email, stdout)
        self.assertNotIn(raw_email, stderr)
        self.assertNotIn(raw_card, stdout)
        self.assertNotIn(raw_card, stderr)
        self.assertNotIn(raw_card.replace(" ", ""), stdout)
        self.assertNotIn(raw_card.replace(" ", ""), stderr)


if __name__ == "__main__":
    unittest.main()
