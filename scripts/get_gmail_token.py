#!/usr/bin/env python3
"""Interactive Google OAuth 2.0 authorization helper for Gmail Mailbox Connector.

Generates the authorization URL, handles the local loopback redirect,
exchanges the auth code for a permanent refresh token, and updates .env automatically.
"""

from __future__ import annotations

import argparse
import contextlib
import http.server
import logging
import os
import sys
import urllib.parse
import webbrowser
from pathlib import Path

import requests

logger = logging.getLogger("get_gmail_token")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"

SCOPES = "https://www.googleapis.com/auth/gmail.readonly"


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    auth_code: str | None = None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            OAuthCallbackHandler.auth_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:sans-serif;text-align:center;padding:50px;'>"
                b"<h2 style='color:#2e7d32;'>&#10004; Authorization Successful!</h2>"
                b"<p>You can close this tab and return to your terminal.</p>"
                b"</body></html>"
            )
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            err = params.get("error", ["Unknown error"])[0]
            self.wfile.write(f"<html><body><h2>Error: {err}</h2></body></html>".encode())

    def log_message(self, format: str, *args: object) -> None:
        pass


def update_env_variable(key: str, value: str) -> None:
    """Updates or appends a key-value pair in .env file safely."""
    lines: list[str] = []
    found = False

    if ENV_PATH.exists():
        with open(ENV_PATH, encoding="utf-8") as f:
            lines = f.readlines()

    new_lines: list[str] = []
    for line in lines:
        if line.strip().startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines.append("\n")
        new_lines.append(f"{key}={value}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def extract_code_from_input(user_input: str) -> str:
    """Extracts authorization code from either a raw code string or a full redirect URL."""
    cleaned = user_input.strip()
    if "code=" in cleaned:
        parsed = urllib.parse.urlparse(cleaned)
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            return params["code"][0]
        # In case the URL fragment or unparsed query is present
        match = urllib.parse.parse_qs(cleaned.split("?", 1)[-1])
        if "code" in match:
            return match["code"][0]
    return cleaned


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Google OAuth 2.0 Authorization Helper for Gmail Mailbox Connector"
    )
    parser.add_argument(
        "--redirect-uri",
        default=os.environ.get("GMAIL_REDIRECT_URI", "http://127.0.0.1:8080/"),
        help="Redirect URI configured in Google Cloud Console (default: http://127.0.0.1:8080/)",
    )
    parser.add_argument(
        "--localhost",
        action="store_true",
        help="Use http://localhost:8080/ instead of http://127.0.0.1:8080/",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Manual authorization mode: paste the authorization code or redirect URL directly",
    )
    args = parser.parse_args()

    redirect_uri = "http://localhost:8080/" if args.localhost else args.redirect_uri

    print("=" * 70)
    print(" Google OAuth 2.0 Authorization Helper for Gmail Connector")
    print("=" * 70)
    print(f"[*] Configured Redirect URI: {redirect_uri}")

    # 1. Load or prompt Client ID & Secret
    client_id = os.environ.get("GMAIL_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET", "").strip()

    if not client_id:
        client_id = input("\n[?] Enter GMAIL_CLIENT_ID: ").strip()
    if not client_secret:
        client_secret = input("[?] Enter GMAIL_CLIENT_SECRET: ").strip()

    if not client_id or not client_secret:
        print("\n[-] Error: GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are required.")
        sys.exit(1)

    update_env_variable("GMAIL_CLIENT_ID", client_id)
    update_env_variable("GMAIL_CLIENT_SECRET", client_secret)

    # 2. Build authorization URL
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPES,
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode(auth_params)
    )

    code: str | None = None

    if args.manual:
        print("\n[+] Manual Mode Enabled.")
        print(f"\n1. Open this URL in your browser:\n\n{auth_url}\n")
        print("2. Log into your Google account and grant read-only Gmail access.")
        print("3. When redirected, copy the FULL URL or the code parameter.")
        raw_code = input("\n[?] Paste Authorization Code or Redirect URL: ").strip()
        code = extract_code_from_input(raw_code)
    else:
        # Start local callback server
        parsed_uri = urllib.parse.urlparse(redirect_uri)
        port = parsed_uri.port or 8080
        server = http.server.HTTPServer(("127.0.0.1", port), OAuthCallbackHandler)

        print(f"\n[*] Starting local callback server on http://127.0.0.1:{port}/ ...")
        print("\n[+] Opening browser for Gmail authorization (Read-Only)...")
        print(f"\nIf browser does not open automatically, visit this URL:\n\n{auth_url}\n")
        with contextlib.suppress(Exception):
            webbrowser.open(auth_url)

        print("[*] Waiting for authorization in browser...")
        print("    (Tip: If your browser shows 'This site cannot be reached' after approving,")
        print("     you can press Ctrl+C to paste the redirected URL manually.)")

        try:
            while OAuthCallbackHandler.auth_code is None:
                server.handle_request()
            code = OAuthCallbackHandler.auth_code
        except KeyboardInterrupt:
            print("\n\n[!] Callback interrupted. Entering manual fallback mode...")
            raw_code = input("[?] Paste the URL from your browser address bar (or code): ").strip()
            code = extract_code_from_input(raw_code)
        finally:
            server.server_close()

    if not code:
        print("\n[-] Error: No authorization code received.")
        sys.exit(1)

    print("[+] Authorization code obtained!")

    # 3. Exchange code for tokens
    print("[*] Exchanging authorization code for permanent refresh token...")
    oauth_endpoint = "https://oauth2.googleapis.com/token"  # nosec B105
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    resp = requests.post(oauth_endpoint, data=token_data, timeout=15.0)
    if resp.status_code != 200:
        print(f"[-] Token exchange failed: HTTP {resp.status_code}\n{resp.text}")
        sys.exit(1)

    tokens = resp.json()
    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")

    if not refresh_token:
        print("[-] Warning: Google did not return a refresh_token.")
        print(
            "    Ensure your OAuth consent screen has access_type=offline and prompt=consent."
        )
        if access_token:
            update_env_variable("GMAIL_ACCESS_TOKEN", access_token)
            print("[+] Saved temporary GMAIL_ACCESS_TOKEN to .env.")
        sys.exit(1)

    # 4. Save to .env
    update_env_variable("GMAIL_REFRESH_TOKEN", refresh_token)
    if access_token:
        update_env_variable("GMAIL_ACCESS_TOKEN", access_token)

    print("\n" + "=" * 70)
    print(" [SUCCESS] Gmail Integration Configured Successfully!")
    print("=" * 70)
    print("[+] GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, and GMAIL_REFRESH_TOKEN have")
    print("    been saved securely to your .env file.")
    print("\nNext: Run `python scripts/poll_mailbox.py --live` to triage live emails!")


if __name__ == "__main__":
    main()
