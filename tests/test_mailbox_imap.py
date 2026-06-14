"""Tests for mailsuite.mailbox.imap.IMAPConnection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from imapclient.exceptions import IMAPClientError

from mailsuite.mailbox import FolderExistsError
from mailsuite.mailbox.imap import IMAPConnection


def _bare_connection() -> IMAPConnection:
    """Construct an IMAPConnection without doing IMAP I/O."""
    inst = IMAPConnection.__new__(IMAPConnection)
    inst._username = "user"
    inst._password = "pw"
    inst._verify = True
    inst._oauth2_token = None
    inst._oauth2_token_provider = None
    inst._oauth2_mechanism = "XOAUTH2"
    inst._oauth2_vendor = None
    inst._client = MagicMock()
    return inst


class TestIMAPConnection:
    def test_create_folder_delegates(self):
        conn = _bare_connection()
        conn.create_folder("Reports")
        conn._client.create_folder.assert_called_once_with("Reports")

    def test_rename_folder_delegates(self):
        conn = _bare_connection()
        conn._client.folder_exists.return_value = False
        conn.rename_folder("Reports", "Archive")
        conn._client.rename_folder.assert_called_once_with("Reports", "Archive")

    def test_rename_folder_conflict_raises(self):
        conn = _bare_connection()
        conn._client.folder_exists.return_value = True
        with pytest.raises(FolderExistsError):
            conn.rename_folder("Reports", "Archive")
        conn._client.rename_folder.assert_not_called()

    def test_folder_exists_delegates(self):
        conn = _bare_connection()
        conn._client.folder_exists.return_value = True
        assert conn.folder_exists("Reports") is True
        conn._client.folder_exists.assert_called_once_with("Reports")

    def test_folder_exists_false(self):
        conn = _bare_connection()
        conn._client.folder_exists.return_value = False
        assert conn.folder_exists("Nope") is False

    def test_delete_folder_delegates(self):
        conn = _bare_connection()
        conn.delete_folder("Junk")
        conn._client.delete_folder.assert_called_once_with("Junk")

    def test_do_move_folder_renames_to_full_path(self):
        # IMAP relocation is a RENAME to the full target path.
        conn = _bare_connection()
        conn._do_move_folder("Archive/Forensic", "Reports", "Reports/Forensic")
        conn._client.rename_folder.assert_called_once_with(
            "Archive/Forensic", "Reports/Forensic"
        )

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

    def test_watch_returns_when_config_reloading_truthy(self, monkeypatch):
        # A truthy config_reloading at the top of the loop returns before any
        # IMAPClient connection is attempted.
        conn = _bare_connection()
        client_calls = []
        monkeypatch.setattr(
            "mailsuite.mailbox.imap.IMAPClient",
            lambda *a, **kw: client_calls.append(kw),
        )
        conn.watch(lambda c: None, 1, config_reloading=lambda: True)
        assert client_calls == []

    def test_watch_forwards_config_reloading_to_client(self, monkeypatch):
        # config_reloading must thread through to the IMAPClient so the IDLE
        # loop itself can honor it. Return False once (enter the loop, build a
        # client) then True (exit after the connection returns).
        conn = _bare_connection()
        captured = {}
        monkeypatch.setattr(
            "mailsuite.mailbox.imap.IMAPClient",
            lambda *a, **kw: captured.update(kw),
        )
        states = iter([False, True])

        def config_reloading() -> bool:
            return next(states)

        conn.watch(lambda c: None, 1, config_reloading=config_reloading)
        assert captured["config_reloading"] is config_reloading

    def test_oauth2_kwargs_forwarded_to_client(self, monkeypatch):
        captured = {}

        def fake_imapclient_init(self, *args, **kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(
            "mailsuite.mailbox.imap.IMAPClient", fake_imapclient_init
        )

        def provider() -> str:
            return "tok"

        IMAPConnection(
            "host",
            "u@example.com",
            oauth2_token_provider=provider,
            oauth2_mechanism="OAUTHBEARER",
        )
        assert captured["oauth2_token_provider"] is provider
        assert captured["oauth2_mechanism"] == "OAUTHBEARER"
        assert captured["oauth2_token"] is None
        assert captured["oauth2_vendor"] is None
