"""Tests for mailsuite.imap.

Network I/O is bypassed: we construct IMAPClient instances via __new__
and stub the methods inherited from imapclient.IMAPClient that ours
delegate to. This focuses tests on the local logic — fetch retry
handling, delete/move chunking, folder normalization — rather than
re-testing imapclient itself.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import imapclient
import imapclient.exceptions
import pytest

from mailsuite.imap import IMAPClient, MaxRetriesExceeded, _chunks


def _bare_client(
    *,
    hierarchy_separator: str = "/",
    path_prefix: str = "",
    move_supported: bool = True,
    max_retries: int = 4,
) -> IMAPClient:
    """Build an IMAPClient without doing any network setup."""
    inst = IMAPClient.__new__(IMAPClient)
    inst._hierarchy_separator = hierarchy_separator
    inst._path_prefix = path_prefix
    inst._move_supported = move_supported
    inst.max_retries = max_retries
    inst._init_args = {
        "host": "h",
        "username": "u",
        "password": "p",
        "port": 993,
        "ssl": True,
        "ssl_context": None,
        "verify": True,
        "timeout": 30,
        "max_retries": max_retries,
        "initial_folder": "INBOX",
        "idle_callback": None,
        "idle_timeout": 30,
    }
    return inst


class TestChunks:
    def test_basic(self):
        assert list(_chunks([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]

    def test_empty(self):
        assert list(_chunks([], 5)) == []


class TestNormaliseFolder:
    def test_inbox_passthrough(self, monkeypatch):
        client = _bare_client(hierarchy_separator="/")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: f"NORMALISED:{name}",
        )
        # Special folders are returned by base impl directly
        assert "INBOX" in client._normalise_folder("INBOX")

    def test_bytes_input_decoded(self, monkeypatch):
        client = _bare_client(hierarchy_separator="/")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        assert client._normalise_folder(b"INBOX") == "INBOX"

    def test_bytearray_input_decoded(self, monkeypatch):
        client = _bare_client(hierarchy_separator="/")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        assert client._normalise_folder(bytearray(b"INBOX")) == "INBOX"

    def test_memoryview_input_decoded(self, monkeypatch):
        client = _bare_client(hierarchy_separator="/")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        assert client._normalise_folder(memoryview(b"INBOX")) == "INBOX"

    def test_translates_separators(self, monkeypatch):
        client = _bare_client(hierarchy_separator=".")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        # path with "/" should be converted to "."
        assert client._normalise_folder("Reports/2026") == "Reports.2026"

    def test_path_prefix_added(self, monkeypatch):
        client = _bare_client(hierarchy_separator="/", path_prefix="INBOX/")
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        assert client._normalise_folder("Reports") == "INBOX/Reports"


class TestFetchMessage:
    def _client(self):
        client = _bare_client()
        client.fetch = MagicMock()
        client.reset_connection = MagicMock()
        return client

    def test_first_fetch_succeeds(self):
        client = self._client()
        client.fetch.return_value = {42: {b"RFC822": b"raw msg"}}
        assert client.fetch_message(42) == "raw msg"

    def test_falls_back_to_body(self):
        client = self._client()
        # First two attempts return responses without RFC822 / BODY[] keys
        client.fetch.side_effect = [
            {42: {b"FLAGS": ()}},
            {42: {b"BODY[]": b"the body"}},
        ]
        assert client.fetch_message(42) == "the body"
        assert client.fetch.call_count == 2

    def test_falls_back_to_body_null(self):
        client = self._client()
        client.fetch.side_effect = [
            {42: {b"FLAGS": ()}},
            {42: {b"FLAGS": ()}},
            {42: {b"BODY[NULL]": b"null body"}},
        ]
        assert client.fetch_message(42) == "null body"
        assert client.fetch.call_count == 3

    def test_no_recognised_keys_raises(self):
        client = self._client()
        client.fetch.return_value = {42: {b"FLAGS": ()}}
        with pytest.raises(KeyError):
            client.fetch_message(42)

    def test_imapclient_error_skips_to_next_attempt(self):
        client = self._client()
        client.fetch.side_effect = [
            imapclient.exceptions.IMAPClientError("boom"),
            {42: {b"BODY[]": b"recovered"}},
        ]
        assert client.fetch_message(42) == "recovered"

    def test_socket_timeout_triggers_retry(self):
        client = self._client()
        client.max_retries = 2
        # first call raises socket.timeout, retry succeeds
        client.fetch.side_effect = [
            socket.timeout(),
            {42: {b"RFC822": b"after retry"}},
        ]
        assert client.fetch_message(42) == "after retry"
        client.reset_connection.assert_called_once()

    def test_max_retries_exceeded(self):
        client = self._client()
        client.max_retries = 2
        client.fetch.side_effect = socket.timeout()
        with pytest.raises(MaxRetriesExceeded):
            client.fetch_message(42)


class TestDeleteMessages:
    def _client(self):
        client = _bare_client()
        client.reset_connection = MagicMock()
        return client

    def test_int_coerced_to_list(self, monkeypatch):
        called = {}

        def fake_delete(self, messages, silent=True):
            called["messages"] = messages

        def fake_expunge(self, messages):
            called["expunged"] = messages

        monkeypatch.setattr(imapclient.IMAPClient, "delete_messages", fake_delete)
        monkeypatch.setattr(imapclient.IMAPClient, "expunge", fake_expunge)
        client = self._client()
        client.delete_messages(42)
        assert called["messages"] == [42]

    def test_retry_on_timeout(self, monkeypatch):
        attempts = {"n": 0}

        def fake_delete(self, messages, silent=True):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise socket.timeout()

        monkeypatch.setattr(imapclient.IMAPClient, "delete_messages", fake_delete)
        monkeypatch.setattr(
            imapclient.IMAPClient, "expunge", lambda self, m: None
        )
        client = self._client()
        client.max_retries = 3
        client.delete_messages([1, 2])
        assert attempts["n"] == 2

    def test_max_retries_raises(self, monkeypatch):
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "delete_messages",
            lambda self, m, silent=True: (_ for _ in ()).throw(socket.timeout()),
        )
        client = self._client()
        client.max_retries = 2
        with pytest.raises(MaxRetriesExceeded):
            client.delete_messages([1])


class TestCreateFolder:
    def test_skips_when_exists(self, monkeypatch):
        client = _bare_client()
        client.folder_exists = MagicMock(return_value=True)
        called = {"created": False}

        def fake_create(self, folder):
            called["created"] = True

        monkeypatch.setattr(imapclient.IMAPClient, "create_folder", fake_create)
        client.create_folder("Reports")
        assert called["created"] is False

    def test_creates_when_missing(self, monkeypatch):
        client = _bare_client()
        client.folder_exists = MagicMock(return_value=False)
        called = {"name": None}

        def fake_create(self, folder):
            called["name"] = folder

        monkeypatch.setattr(imapclient.IMAPClient, "create_folder", fake_create)
        client.create_folder("Reports")
        assert called["name"] == "Reports"

    def test_max_retries_on_timeout(self, monkeypatch):
        client = _bare_client()
        client.folder_exists = MagicMock(return_value=False)
        client.reset_connection = MagicMock()
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "create_folder",
            lambda self, folder: (_ for _ in ()).throw(socket.timeout()),
        )
        client.max_retries = 2
        with pytest.raises(MaxRetriesExceeded):
            client.create_folder("Reports")


class TestMoveMessages:
    def _client(self, move_supported=True):
        client = _bare_client(move_supported=move_supported)
        client.reset_connection = MagicMock()
        client.move = MagicMock()
        client.copy = MagicMock()
        return client

    def test_move_when_supported(self, monkeypatch):
        monkeypatch.setattr(
            imapclient.IMAPClient, "delete_messages", lambda *a, **k: None
        )
        monkeypatch.setattr(imapclient.IMAPClient, "expunge", lambda *a, **k: None)
        client = self._client(move_supported=True)
        client.move_messages([1, 2, 3], "Archive")
        client.move.assert_called_once()

    def test_copy_fallback_when_move_unsupported(self, monkeypatch):
        monkeypatch.setattr(
            imapclient.IMAPClient, "delete_messages", lambda *a, **k: None
        )
        monkeypatch.setattr(imapclient.IMAPClient, "expunge", lambda *a, **k: None)
        client = self._client(move_supported=False)
        client.move_messages([1], "Archive")
        client.copy.assert_called_once()
        client.move.assert_not_called()

    def test_copy_fallback_when_move_errors(self, monkeypatch):
        monkeypatch.setattr(
            imapclient.IMAPClient, "delete_messages", lambda *a, **k: None
        )
        monkeypatch.setattr(imapclient.IMAPClient, "expunge", lambda *a, **k: None)
        client = self._client(move_supported=True)
        client.move.side_effect = imapclient.exceptions.IMAPClientError("nope")
        client.move_messages([1], "Archive")
        # falls back to copy + delete
        client.copy.assert_called_once()


class TestExceptions:
    def test_max_retries_is_runtime_error(self):
        assert issubclass(MaxRetriesExceeded, RuntimeError)
