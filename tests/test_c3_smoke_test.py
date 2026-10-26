"""Unit tests for Fix C3: Strict Jev Smoke Test Verification.

Validates that scripts/jev_smoke_test.py:
1. Exits with code 1 when Jev returns 401 Unauthorized (invalid key) and falls back.
2. Exits with code 1 when Jev returns 500 Server Error.
3. Exits with code 1 when a network timeout occurs and falls back to offline heuristics.
4. Completes successfully with exit code 0 when Jev actively classifies the email.
5. Exits cleanly with code 0 and guidance when JEV_API_KEY is missing or placeholder.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

import scripts.jev_smoke_test as smoke_test


def test_c3_smoke_test_fails_on_http_401_invalid_key(capsys, monkeypatch):
    """Smoke test must exit with code 1 when Jev returns 401 Unauthorized and falls back."""
    monkeypatch.setenv("JEV_API_KEY", "invalid_revoked_key_12345")

    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(SystemExit) as exc_info:
            smoke_test.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Smoke test FAILED" in combined
    assert "TypeSafe System One (Jev) API did not produce decision" in combined
    assert "fallback used" in combined


def test_c3_smoke_test_fails_on_http_500_server_error(capsys, monkeypatch):
    """Smoke test must exit with code 1 when Jev returns 500 Internal Server Error."""
    monkeypatch.setenv("JEV_API_KEY", "valid_format_key_12345")

    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(SystemExit) as exc_info:
            smoke_test.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Smoke test FAILED" in combined
    assert "TypeSafe System One (Jev) API did not produce decision" in combined


def test_c3_smoke_test_fails_on_network_timeout(capsys, monkeypatch):
    """Smoke test must exit with code 1 when Jev API times out and triggers fallback."""
    monkeypatch.setenv("JEV_API_KEY", "valid_format_key_12345")

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out")):
        with pytest.raises(SystemExit) as exc_info:
            smoke_test.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Smoke test FAILED" in combined
    assert "fallback used" in combined


def test_c3_smoke_test_succeeds_on_valid_jev_classification(capsys, monkeypatch):
    """Smoke test must complete with code 0 when Jev actively classifies the email."""
    monkeypatch.setenv("JEV_API_KEY", "valid_active_token_12345")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "answers": {
            "is_spam": {"type": "noul", "noul": 0.02},
            "is_threat": {"type": "noul", "noul": 0.01},
        }
    }

    with patch("requests.post", return_value=mock_resp):
        smoke_test.main()

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Smoke test completed successfully!" in combined
    assert '"classifier_used": "jev"' in combined


def test_c3_smoke_test_missing_key_guidance_and_exit_0(capsys, monkeypatch):
    """Smoke test must print guidance and exit with 0 when no key is configured."""
    monkeypatch.setenv("JEV_API_KEY", "")

    with pytest.raises(SystemExit) as exc_info:
        smoke_test.main()

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Jev key: missing" in captured.out
    assert "No valid JEV_API_KEY detected" in captured.out
