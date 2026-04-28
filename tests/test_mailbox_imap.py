"""Tests for mailsuite.mailbox.imap.IMAPConnection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from imapclient.exceptions import IMAPClientError

from mailsuite.mailbox.imap import IMAPConnection


def _bare_connection() -> IMAPConnection:
    """Construct an IMAPConnection without doing IMAP I/O."""
    inst = IMAPConnection.__new__(IMAPConnection)
    inst._username = "user"
    inst._password = "pw"
    inst._verify = True
    inst._client = MagicMock()
    return inst


class TestIMAPConnection:
    def test_create_folder_delegates(self):
        conn = _bare_connection()
        conn.create_folder("Reports")
        conn._client.create_folder.assert_called_once_with("Reports")

    def test_fetch_messages_no_since(self):
        conn = _bare_connection()
        conn._client.search.return_value = [1, 2, 3]
        result = conn.fetch_messages("INBOX")
        conn._client.select_folder.assert_called_once_with("INBOX")
        conn._client.search.assert_called_once_with()
        assert result == [1, 2, 3]

    def test_fetch_messages_since(self):
        conn = _bare_connection()
        conn._client.search.return_value = [9]
        conn.fetch_messages("INBOX", since="01-Jan-2026")
        conn._client.search.assert_called_once_with("SINCE 01-Jan-2026")

    def test_fetch_message(self):
        conn = _bare_connection()
        conn._client.fetch_message.return_value = "raw msg"
        assert conn.fetch_message(42) == "raw msg"
        conn._client.fetch_message.assert_called_once_with(42, parse=False)

    def test_delete_message(self):
        conn = _bare_connection()
        conn.delete_message(42)
        conn._client.delete_messages.assert_called_once_with([42])

    def test_delete_message_fallback(self, caplog):
        conn = _bare_connection()
        conn._client.delete_messages.side_effect = IMAPClientError("server angry")
        conn.delete_message(42)
        # Falls back to add_flags + expunge
        conn._client.add_flags.assert_called_once_with(
            [42], [r"\Deleted"], silent=True
        )
        conn._client.expunge.assert_called_once()

    def test_move_message(self):
        conn = _bare_connection()
        conn.move_message(42, "Archive")
        conn._client.move_messages.assert_called_once_with([42], "Archive")

    def test_move_message_fallback(self):
        conn = _bare_connection()
        conn._client.move_messages.side_effect = IMAPClientError("nope")
        conn.move_message(42, "Archive")
        # Falls back to copy + delete
        conn._client.copy.assert_called_once_with([42], "Archive")
        conn._client.delete_messages.assert_called_once_with([42])

    def test_keepalive_calls_noop(self):
        conn = _bare_connection()
        conn.keepalive()
        conn._client.noop.assert_called_once()

    def test_send_message_raises(self):
        conn = _bare_connection()
        with pytest.raises(NotImplementedError, match="IMAP"):
            conn.send_message("a@example.com")
