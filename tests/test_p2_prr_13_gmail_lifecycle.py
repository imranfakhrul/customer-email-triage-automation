"""Tests for PRR-13: Gmail Ingestion Auth Refresh & Pagination Lifecycle."""

from unittest.mock import MagicMock

import pytest

from utils.mailbox.gmail_connector import GmailConnector


class TestGmailAuthRefreshAndPagination:
    """Verifies automatic 401 token refresh retry and bounded history pagination."""

    @pytest.fixture
    def mock_session(self):
        """Creates a mock requests.Session with mock token refresh."""
        session = MagicMock()
        # Mock oauth token response
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {
            "access_token": "ya29.refreshed_access_token_xyz",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        session.post.return_value = token_resp
        return session

    def test_history_sync_401_token_refresh_and_retry(self, mock_session):
        """Verifies 401 on history fetch triggers token refresh and retries successfully."""
        resp_401 = MagicMock()
        resp_401.status_code = 401

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "msg_after_refresh_1", "threadId": "t1"}}
                    ]
                }
            ],
            "historyId": "5002",
        }

        mock_session.get.side_effect = [resp_401, resp_200]

        connector = GmailConnector(
            client_id="mock_id",
            client_secret="mock_secret",
            refresh_token="mock_refresh",
            access_token="expired_token_123",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="5000")
        assert len(messages) == 1
        assert messages[0]["id"] == "msg_after_refresh_1"

        # Verify OAuth token refresh occurred
        mock_session.post.assert_called_once()
        assert "oauth2.googleapis.com/token" in mock_session.post.call_args[0][0]

        # Verify second GET request used the refreshed bearer token
        assert mock_session.get.call_count == 2
        retry_headers = mock_session.get.call_args_list[1][1]["headers"]
        assert retry_headers["Authorization"] == "Bearer ya29.refreshed_access_token_xyz"

    def test_initial_fetch_401_token_refresh_and_retry(self, mock_session):
        """Verifies 401 on initial messages fetch triggers token refresh and retries."""
        resp_401 = MagicMock()
        resp_401.status_code = 401

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {
            "messages": [{"id": "msg_initial_1", "threadId": "t1"}]
        }

        mock_session.get.side_effect = [resp_401, resp_200]

        connector = GmailConnector(
            client_id="mock_id",
            client_secret="mock_secret",
            refresh_token="mock_refresh",
            access_token="expired_token_123",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id=None)
        assert len(messages) == 1
        assert messages[0]["id"] == "msg_initial_1"
        assert mock_session.get.call_count == 2

    def test_history_sync_multi_page_pagination(self, mock_session):
        """Verifies iteration across nextPageToken accumulating messages."""
        page_1 = MagicMock(status_code=200)
        page_1.json.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "msg_page_1", "threadId": "t1"}}]}
            ],
            "nextPageToken": "token_page_2",
        }

        page_2 = MagicMock(status_code=200)
        page_2.json.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "msg_page_2", "threadId": "t2"}}]}
            ],
            "nextPageToken": "token_page_3",
        }

        page_3 = MagicMock(status_code=200)
        page_3.json.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "msg_page_3", "threadId": "t3"}}]}
            ],
            # Terminal page: no nextPageToken
        }

        mock_session.get.side_effect = [page_1, page_2, page_3]

        connector = GmailConnector(
            access_token="valid_token",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert len(messages) == 3
        msg_ids = [m["id"] for m in messages]
        assert msg_ids == ["msg_page_1", "msg_page_2", "msg_page_3"]
        assert mock_session.get.call_count == 3

    def test_history_sync_pagination_cap_at_five_pages(self, mock_session):
        """Verifies pagination loop halts at 5 pages even if nextPageToken continues."""
        pages = []
        for i in range(10):
            p = MagicMock(status_code=200)
            p.json.return_value = {
                "history": [
                    {"messagesAdded": [{"message": {"id": f"msg_{i}", "threadId": f"t{i}"}}]}
                ],
                "nextPageToken": f"token_page_{i+1}",
            }
            pages.append(p)

        mock_session.get.side_effect = pages

        connector = GmailConnector(
            access_token="valid_token",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert len(messages) == 5
        assert mock_session.get.call_count == 5

    def test_pagination_mid_stream_401_refresh(self, mock_session):
        """Verifies 401 encountered on subsequent page refreshes token without losing state."""
        page_1 = MagicMock(status_code=200)
        page_1.json.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "msg_p1", "threadId": "t1"}}]}
            ],
            "nextPageToken": "token_page_2",
        }

        page_2_401 = MagicMock(status_code=401)

        page_2_retry_200 = MagicMock(status_code=200)
        page_2_retry_200.json.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "msg_p2", "threadId": "t2"}}]}
            ],
        }

        mock_session.get.side_effect = [page_1, page_2_401, page_2_retry_200]

        connector = GmailConnector(
            client_id="mock_id",
            client_secret="mock_secret",
            refresh_token="mock_refresh",
            access_token="valid_token",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert len(messages) == 2
        msg_ids = [m["id"] for m in messages]
        assert msg_ids == ["msg_p1", "msg_p2"]
        mock_session.post.assert_called_once()  # Refreshed token on page 2

    def test_persistent_401_fails_closed_safely(self, mock_session):
        """Verifies persistent 401 fails closed safely without infinite loop."""
        resp_401_first = MagicMock(status_code=401)
        resp_401_retry = MagicMock(status_code=401)

        mock_session.get.side_effect = [resp_401_first, resp_401_retry]

        connector = GmailConnector(
            client_id="mock_id",
            client_secret="mock_secret",
            refresh_token="mock_refresh",
            access_token="expired_token",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert messages == []
        # Called initial + exactly 1 retry
        assert mock_session.get.call_count == 2

    def test_setup_watch_401_refresh_and_retry(self, mock_session):
        """Verifies setup_watch refreshes expired token on 401 and retries."""
        # 1st POST: setup_watch returns 401
        watch_401 = MagicMock(status_code=401)

        # 2nd POST: token endpoint returns 200
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {
            "access_token": "ya29.watch_refreshed_token",
            "expires_in": 3600,
        }

        # 3rd POST: setup_watch retry returns 200
        watch_200 = MagicMock(status_code=200)
        watch_200.json.return_value = {
            "historyId": "88888",
            "expiration": "1761667200000",
        }

        mock_session.post.side_effect = [watch_401, token_resp, watch_200]

        connector = GmailConnector(
            client_id="mock_id",
            client_secret="mock_secret",
            refresh_token="mock_refresh",
            access_token="expired_token",
            session=mock_session,
        )

        result = connector.setup_watch(topic_name="projects/p/topics/t")
        assert result.get("historyId") == "88888"
        assert mock_session.post.call_count == 3

    def test_history_sync_multi_page_deduplication(self, mock_session):
        """Verifies duplicate message IDs across multiple history pages are deduplicated."""
        page_1 = MagicMock(status_code=200)
        page_1.json.return_value = {
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "msg_001", "threadId": "t1"}},
                        {"message": {"id": "msg_002", "threadId": "t2"}},
                    ]
                }
            ],
            "nextPageToken": "page2_token",
        }

        page_2 = MagicMock(status_code=200)
        page_2.json.return_value = {
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "msg_002", "threadId": "t2"}},  # Duplicate
                        {"message": {"id": "msg_003", "threadId": "t3"}},
                    ]
                }
            ],
        }

        mock_session.get.side_effect = [page_1, page_2]

        connector = GmailConnector(
            access_token="valid_token",
            session=mock_session,
        )

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert len(messages) == 3
        msg_ids = [m["id"] for m in messages]
        assert msg_ids == ["msg_001", "msg_002", "msg_003"]
