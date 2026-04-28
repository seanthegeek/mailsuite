"""Tests for mailsuite.mailbox.graph.MSGraphConnection.

The Graph SDK is fully mocked. We construct connections via __new__ and
inject a fake fluent client so the code paths that touch the SDK can be
exercised without real credentials or HTTP.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

# Skip everything if the optional [msgraph] extra isn't installed.
pytest.importorskip("msgraph")
pytest.importorskip("azure.identity")

from mailsuite.mailbox import MailboxConnection  # noqa: E402
from mailsuite.mailbox.graph import (  # noqa: E402
    DEFAULT_TOKEN_CACHE_NAME,
    AuthMethod,
    MSGraphConnection,
    _generate_credential,
    _run,
)


# ---------------------------------------------------------------------------
# Fluent SDK fake — mirrors the call chains MSGraphConnection actually uses
# ---------------------------------------------------------------------------


def _coro(value: Any):
    """Wrap a value in an awaitable that returns it."""

    async def _f():
        return value

    return _f()


class FakeMessages:
    def __init__(self):
        self.posted = None
        self.get_response = MagicMock()  # for create_folder calls? unused
        self.get_calls = []
        self.next_pages = []  # list of pages to return on subsequent .get / .with_url

    def get(self, request_configuration=None):
        self.get_calls.append(request_configuration)
        if self.next_pages:
            return _coro(self.next_pages.pop(0))
        return _coro(None)

    def with_url(self, url):
        self._next_url = url
        return self


class FakeMailFolderItem:
    def __init__(self, child_pages=None):
        self.messages = FakeMessages()
        self._child_pages = child_pages or []

    def get(self, request_configuration=None):
        return _coro(MagicMock(value=[MagicMock(id="folder123", display_name="x")]))

    @property
    def child_folders(self):
        cf = MagicMock()

        def _get(request_configuration=None):
            if self._child_pages:
                return _coro(self._child_pages.pop(0))
            return _coro(MagicMock(value=[]))

        cf.get = _get
        cf.post = MagicMock(return_value=_coro(None))
        return cf


class FakeMailFolders:
    def __init__(self):
        self.posts = []
        self._items: dict = {}
        self._listing_pages = []

    def by_mail_folder_id(self, fid):
        if fid not in self._items:
            self._items[fid] = FakeMailFolderItem()
        return self._items[fid]

    def get(self, request_configuration=None):
        if self._listing_pages:
            return _coro(self._listing_pages.pop(0))
        return _coro(MagicMock(value=[]))

    def post(self, body):
        self.posts.append(body)
        return _coro(None)


class FakeMessageItem:
    def __init__(self):
        self.deleted = False
        self.patched = None
        self.moved_body = None
        self.content = MagicMock()
        self.content.get = MagicMock(return_value=_coro(b"raw rfc822 bytes"))
        self.move = MagicMock()
        self.move.post = MagicMock(side_effect=self._move_post)

    def _move_post(self, body):
        self.moved_body = body
        return _coro(None)

    def delete(self):
        self.deleted = True
        return _coro(None)

    def patch(self, body):
        self.patched = body
        return _coro(None)


class FakeUserMessages:
    def __init__(self):
        self.items: dict = {}

    def by_message_id(self, mid):
        if mid not in self.items:
            self.items[mid] = FakeMessageItem()
        return self.items[mid]


class FakeSendMail:
    def __init__(self):
        self.last_body = None

    def post(self, body):
        self.last_body = body
        return _coro(None)


class FakeUserItem:
    def __init__(self):
        self.mail_folders = FakeMailFolders()
        self.messages = FakeUserMessages()
        self.send_mail = FakeSendMail()


class FakeUsers:
    def __init__(self):
        self._user: FakeUserItem | None = None

    def by_user_id(self, mailbox):
        if self._user is None:
            self._user = FakeUserItem()
        return self._user


class FakeGraphClient:
    def __init__(self):
        self.users = FakeUsers()


def _make_conn() -> MSGraphConnection:
    inst = MSGraphConnection.__new__(MSGraphConnection)
    inst._client = FakeGraphClient()
    inst.mailbox_name = "user@example.com"
    return inst


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRunHelper:
    def test_runs_coroutine(self):
        async def double():
            return 42

        assert _run(double()) == 42

    def test_rejects_running_loop(self):
        async def main():
            with pytest.raises(RuntimeError, match="running event loop"):
                _run(asyncio.sleep(0))

        asyncio.run(main())


class TestAuthMethodNames:
    def test_enum_values(self):
        assert AuthMethod.DeviceCode.name == "DeviceCode"
        assert AuthMethod.ClientSecret.name == "ClientSecret"

    def test_unknown_auth_method(self, tmp_path):
        with pytest.raises(RuntimeError, match="not found"):
            _generate_credential("BogusAuth", tmp_path / "tok")

    def test_certificate_requires_path(self, tmp_path):
        with pytest.raises(ValueError, match="certificate_path"):
            _generate_credential(
                AuthMethod.Certificate.name,
                tmp_path / "tok",
                client_id="c",
                tenant_id="t",
            )


class TestSubclass:
    def test_is_mailbox_connection(self):
        assert issubclass(MSGraphConnection, MailboxConnection)


class TestKeepalive:
    def test_no_op(self):
        _make_conn().keepalive()


class TestSendMessage:
    def test_send_with_plain_text(self):
        from msgraph.generated.models.body_type import BodyType

        conn = _make_conn()
        conn.send_message(
            message_from="ignored@example.com",
            message_to=["b@example.org"],
            subject="hi",
            plain_message="hello",
        )
        body = conn._client.users.by_user_id("x").send_mail.last_body
        assert body is not None
        assert body.message.subject == "hi"
        assert body.message.body.content_type == BodyType.Text
        assert body.message.body.content == "hello"
        assert body.save_to_sent_items is True

    def test_send_with_html(self):
        from msgraph.generated.models.body_type import BodyType

        conn = _make_conn()
        conn.send_message(
            message_from="x@example.com",
            message_to=["b@example.org"],
            subject="hi",
            html_message="<p>hi</p>",
        )
        body = conn._client.users.by_user_id("x").send_mail.last_body
        assert body.message.body.content_type == BodyType.Html
        assert body.message.body.content == "<p>hi</p>"

    def test_send_with_recipients(self):
        conn = _make_conn()
        conn.send_message(
            message_from="x@example.com",
            message_to=["a@e.com", "b@e.com"],
            message_cc=["c@e.com"],
            message_bcc=["d@e.com"],
            plain_message="hi",
        )
        body = conn._client.users.by_user_id("x").send_mail.last_body
        assert len(body.message.to_recipients) == 2
        assert len(body.message.cc_recipients) == 1
        assert len(body.message.bcc_recipients) == 1
        assert body.message.to_recipients[0].email_address.address == "a@e.com"

    def test_send_with_attachments(self):
        conn = _make_conn()
        conn.send_message(
            message_from="x@example.com",
            message_to=["b@example.org"],
            plain_message="hi",
            attachments=[("readme.txt", b"contents")],
        )
        body = conn._client.users.by_user_id("x").send_mail.last_body
        assert len(body.message.attachments) == 1
        att = body.message.attachments[0]
        assert att.name == "readme.txt"
        assert att.content_bytes == b"contents"


class TestMessageOps:
    def test_fetch_message(self):
        conn = _make_conn()
        result = conn.fetch_message("msg42")
        assert result == "raw rfc822 bytes"

    def test_fetch_message_str_passthrough(self):
        conn = _make_conn()
        # Patch content.get to return a str directly
        item = conn._client.users.by_user_id("x").messages.by_message_id("m1")
        item.content.get = MagicMock(return_value=_coro("already a string"))
        assert conn.fetch_message("m1") == "already a string"

    def test_fetch_message_none_returns_empty(self):
        conn = _make_conn()
        item = conn._client.users.by_user_id("x").messages.by_message_id("m2")
        item.content.get = MagicMock(return_value=_coro(None))
        assert conn.fetch_message("m2") == ""

    def test_fetch_message_mark_read(self):
        conn = _make_conn()
        conn.fetch_message("m3", mark_read=True)
        item = conn._client.users.by_user_id("x").messages.by_message_id("m3")
        # patched = Message(is_read=True)
        assert item.patched is not None
        assert item.patched.is_read is True

    def test_mark_message_read(self):
        conn = _make_conn()
        conn.mark_message_read("m4")
        item = conn._client.users.by_user_id("x").messages.by_message_id("m4")
        assert item.patched is not None

    def test_delete_message(self):
        conn = _make_conn()
        conn.delete_message("m5")
        item = conn._client.users.by_user_id("x").messages.by_message_id("m5")
        assert item.deleted is True


class TestFolderResolution:
    def test_finds_folder_by_display_name(self):
        conn = _make_conn()
        conn._client.users.by_user_id("x").mail_folders._listing_pages = [
            MagicMock(value=[MagicMock(id="abc123", display_name="Reports")]),
        ]
        assert conn._find_folder_id_from_folder_path("Reports") == "abc123"

    def test_unknown_folder_raises(self):
        conn = _make_conn()
        conn._client.users.by_user_id("x").mail_folders._listing_pages = [
            MagicMock(value=[]),
        ]
        with pytest.raises(RuntimeError, match="not found"):
            conn._find_folder_id_from_folder_path("DoesNotExist")

    def test_well_known_folder_fallback(self):
        conn = _make_conn()
        # Empty listing for the literal name…
        conn._client.users.by_user_id("x").mail_folders._listing_pages = [
            MagicMock(value=[]),
        ]
        # …but the well-known alias 'inbox' resolves
        item = conn._client.users.by_user_id("x").mail_folders.by_mail_folder_id(
            "inbox"
        )

        async def _inbox_get(request_configuration=None):
            return MagicMock(id="inbox-id")

        item.get = lambda request_configuration=None: _inbox_get(request_configuration)
        assert conn._find_folder_id_from_folder_path("Inbox") == "inbox-id"


class TestCreateFolder:
    def test_top_level_folder(self):
        conn = _make_conn()
        conn.create_folder("Reports")
        # Posted body has the right display name
        posts = conn._client.users.by_user_id("x").mail_folders.posts
        assert len(posts) == 1
        assert posts[0].display_name == "Reports"

    def test_already_exists_swallowed(self):
        conn = _make_conn()
        # Make post raise an "already exists" error
        async def _raise(*a, **k):
            raise RuntimeError("ErrorFolderExists: yep")

        conn._client.users.by_user_id("x").mail_folders.post = lambda body: _raise()
        # Should not raise
        conn.create_folder("Reports")

    def test_unknown_error_propagates(self):
        conn = _make_conn()

        async def _raise(*a, **k):
            raise RuntimeError("server explosion")

        conn._client.users.by_user_id("x").mail_folders.post = lambda body: _raise()
        with pytest.raises(RuntimeError, match="explosion"):
            conn.create_folder("Reports")


class TestFetchMessagesPagination:
    def test_single_page(self):
        conn = _make_conn()
        # Folder lookup returns an id directly (no pagination)
        conn._client.users.by_user_id("x").mail_folders._listing_pages = [
            MagicMock(value=[MagicMock(id="f1", display_name="Reports")]),
        ]
        # Messages page
        item = conn._client.users.by_user_id("x").mail_folders.by_mail_folder_id("f1")
        item.messages.next_pages = [
            MagicMock(
                value=[MagicMock(id="m1"), MagicMock(id="m2")],
                odata_next_link=None,
            )
        ]
        ids = conn.fetch_messages("Reports")
        assert ids == ["m1", "m2"]


class TestWatch:
    def test_exits_on_config_reload(self):
        conn = _make_conn()
        calls = {"n": 0}
        conn.watch(
            lambda c: calls.update(n=calls["n"] + 1),
            check_timeout=0,
            config_reloading=lambda: True,
        )
        assert calls["n"] == 0

    def test_calls_callback_then_exits(self):
        conn = _make_conn()
        calls = {"n": 0}

        def cb(c):
            calls["n"] += 1

        # The watch loop checks reload twice per iteration, callback runs in
        # between. We want both checks of iter 1 to return False (callback
        # runs) and the first check of iter 2 to return True (loop exits).
        def reload():
            return calls["n"] > 0

        conn.watch(cb, check_timeout=0, config_reloading=reload)
        assert calls["n"] == 1


class TestGraphUrl:
    """The graph_url parameter must override the httpx client base URL."""

    def _build(self, graph_url, monkeypatch):
        # Bypass real cert auth by stubbing _generate_credential to return a
        # ClientSecretCredential subclass — the constructor branches on that
        # type to skip the interactive `authenticate()` step.
        from azure.identity import ClientSecretCredential
        from mailsuite.mailbox import graph as graph_mod

        class FakeCred(ClientSecretCredential):
            def __init__(self):
                pass  # bypass real Azure SDK init

            def get_token(self, *a, **k):
                return None

        monkeypatch.setattr(
            graph_mod, "_generate_credential", lambda *a, **k: FakeCred()
        )
        return MSGraphConnection(
            auth_method=AuthMethod.ClientSecret.name,
            mailbox="user@example.com",
            client_id="c",
            client_secret="s",
            username=None,
            password=None,
            tenant_id="t",
            token_file="/tmp/unused-token",
            allow_unencrypted_storage=False,
            graph_url=graph_url,
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://graph.microsoft.us",
            "https://dod-graph.microsoft.us",
            "https://microsoftgraph.chinacloudapi.cn",
            "https://graph.microsoft.de",
            "https://graph.example.test",
            "https://graph.microsoft.us/",  # trailing slash stripped
        ],
    )
    def test_overrides_base_url(self, url, monkeypatch):
        conn = self._build(url, monkeypatch)
        base = str(conn._client.request_adapter._http_client.base_url)
        assert url.rstrip("/") in base
        assert base.endswith("/v1.0") or base.endswith("/v1.0/")


class TestCacheName:
    def test_default_constant(self):
        assert DEFAULT_TOKEN_CACHE_NAME == "mailsuite"

    def test_default_cache_name_passed_through(self, tmp_path, monkeypatch):
        captured = {}

        def fake_token_cache_options(name, allow_unencrypted_storage):
            captured["name"] = name
            return MagicMock()

        from mailsuite.mailbox import graph as graph_mod

        monkeypatch.setattr(
            graph_mod, "TokenCachePersistenceOptions", fake_token_cache_options
        )

        # Construct only the credential; bypass real DeviceCodeCredential
        class FakeDevCred:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        monkeypatch.setattr(graph_mod, "DeviceCodeCredential", FakeDevCred)

        _generate_credential(
            AuthMethod.DeviceCode.name,
            tmp_path / "tok",
            client_id="c",
            tenant_id="t",
            allow_unencrypted_storage=True,
        )
        assert captured["name"] == "mailsuite"

    def test_overridden_cache_name(self, tmp_path, monkeypatch):
        captured = {}

        def fake_token_cache_options(name, allow_unencrypted_storage):
            captured["name"] = name
            return MagicMock()

        from mailsuite.mailbox import graph as graph_mod

        monkeypatch.setattr(
            graph_mod, "TokenCachePersistenceOptions", fake_token_cache_options
        )

        class FakeDevCred:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        monkeypatch.setattr(graph_mod, "DeviceCodeCredential", FakeDevCred)

        _generate_credential(
            AuthMethod.DeviceCode.name,
            tmp_path / "tok",
            client_id="c",
            tenant_id="t",
            allow_unencrypted_storage=False,
            cache_name="parsedmarc",
        )
        assert captured["name"] == "parsedmarc"

    def test_cache_name_for_username_password(self, tmp_path, monkeypatch):
        captured = {}

        def fake_token_cache_options(name, allow_unencrypted_storage):
            captured["name"] = name
            return MagicMock()

        from mailsuite.mailbox import graph as graph_mod

        monkeypatch.setattr(
            graph_mod, "TokenCachePersistenceOptions", fake_token_cache_options
        )

        class FakeUPCred:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        monkeypatch.setattr(graph_mod, "UsernamePasswordCredential", FakeUPCred)

        _generate_credential(
            AuthMethod.UsernamePassword.name,
            tmp_path / "tok",
            client_id="c",
            client_secret="s",
            username="u",
            password="p",
            tenant_id="t",
            allow_unencrypted_storage=True,
            cache_name="parsedmarc",
        )
        assert captured["name"] == "parsedmarc"
