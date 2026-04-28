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
    other_namespace_prefixes: list[str] | None = None,
    move_supported: bool = True,
    max_retries: int = 4,
) -> IMAPClient:
    """Build an IMAPClient without doing any network setup."""
    inst = IMAPClient.__new__(IMAPClient)
    inst._hierarchy_separator = hierarchy_separator
    inst._path_prefix = path_prefix
    inst._other_namespace_prefixes = other_namespace_prefixes or []
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
        "oauth2_token": None,
        "oauth2_token_provider": None,
        "oauth2_mechanism": "XOAUTH2",
        "oauth2_vendor": None,
    }
    return inst


def _stub_network(monkeypatch):
    """Stub everything in the base IMAPClient that does network I/O."""
    monkeypatch.setattr(
        imapclient.IMAPClient, "__init__", lambda self, **kw: None
    )
    monkeypatch.setattr(
        imapclient.IMAPClient, "capabilities", lambda self: (b"IMAP4rev1",)
    )
    monkeypatch.setattr(
        imapclient.IMAPClient,
        "list_folders",
        lambda self: [((), b"/", b"INBOX")],
    )
    monkeypatch.setattr(
        imapclient.IMAPClient, "select_folder", lambda self, name: None
    )


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

    def test_other_users_namespace_passthrough(self, monkeypatch):
        # Reproduces issue #13: shared folders accessed via the "other users"
        # namespace must not get the personal prefix prepended.
        client = _bare_client(
            hierarchy_separator="/",
            path_prefix="INBOX/",
            other_namespace_prefixes=["user/"],
        )
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "_normalise_folder",
            lambda self, name: name,
        )
        assert (
            client._normalise_folder("user/colleague/Inbox")
            == "user/colleague/Inbox"
        )

    def test_personal_prefix_still_added_for_unprefixed_paths(self, monkeypatch):
        client = _bare_client(
            hierarchy_separator="/",
            path_prefix="INBOX/",
            other_namespace_prefixes=["user/"],
        )
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


class TestOAuth2Login:
    def test_password_auth_calls_login(self, monkeypatch):
        _stub_network(monkeypatch)
        called = {}
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "login",
            lambda self, u, p: called.update(user=u, pw=p),
        )
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "oauth2_login",
            lambda *a, **k: pytest.fail("oauth2_login should not be called"),
        )
        IMAPClient("host", "u@example.com", "secret")
        assert called == {"user": "u@example.com", "pw": "secret"}

    def test_static_oauth2_token_uses_xoauth2(self, monkeypatch):
        _stub_network(monkeypatch)
        called = {}

        def fake_oauth(self, user, token, mech="XOAUTH2", vendor=None):
            called.update(user=user, token=token, mech=mech, vendor=vendor)

        monkeypatch.setattr(imapclient.IMAPClient, "oauth2_login", fake_oauth)
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "login",
            lambda *a, **k: pytest.fail("login should not be called"),
        )
        IMAPClient("host", "u@example.com", oauth2_token="tok-123")
        assert called == {
            "user": "u@example.com",
            "token": "tok-123",
            "mech": "XOAUTH2",
            "vendor": None,
        }

    def test_token_provider_invoked_each_connect(self, monkeypatch):
        _stub_network(monkeypatch)
        tokens = iter(["tok-1", "tok-2", "tok-3"])
        provider_calls = {"n": 0}

        def provider():
            provider_calls["n"] += 1
            return next(tokens)

        seen_tokens: list[str] = []
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "oauth2_login",
            lambda self, user, token, mech="XOAUTH2", vendor=None: (
                seen_tokens.append(token)
            ),
        )
        client = IMAPClient(
            "host", "u@example.com", oauth2_token_provider=provider
        )
        # Reconnect: the provider must be called again so the new
        # connection uses a fresh access token.
        monkeypatch.setattr(client, "shutdown", lambda: None)
        client.reset_connection()
        assert provider_calls["n"] == 2
        assert seen_tokens == ["tok-1", "tok-2"]

    def test_oauthbearer_mechanism(self, monkeypatch):
        _stub_network(monkeypatch)
        called = {}
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "oauthbearer_login",
            lambda self, identity, token: called.update(
                identity=identity, token=token
            ),
        )
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "oauth2_login",
            lambda *a, **k: pytest.fail("oauth2_login should not be called"),
        )
        IMAPClient(
            "host",
            "u@example.com",
            oauth2_token="tok",
            oauth2_mechanism="OAUTHBEARER",
        )
        assert called == {"identity": "u@example.com", "token": "tok"}

    def test_yahoo_vendor_passed_through(self, monkeypatch):
        _stub_network(monkeypatch)
        seen = {}
        monkeypatch.setattr(
            imapclient.IMAPClient,
            "oauth2_login",
            lambda self, user, token, mech="XOAUTH2", vendor=None: seen.update(
                vendor=vendor
            ),
        )
        IMAPClient(
            "host",
            "u@yahoo.com",
            oauth2_token="tok",
            oauth2_vendor="yahoo",
        )
        assert seen == {"vendor": "yahoo"}

    def test_missing_credentials_raises(self):
        with pytest.raises(ValueError, match="password or an OAuth2"):
            IMAPClient("host", "u@example.com")

    def test_oauth_without_username_raises(self):
        with pytest.raises(ValueError, match="username is required"):
            IMAPClient("host", oauth2_token="tok")
