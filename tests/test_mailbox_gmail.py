"""Tests for mailsuite.mailbox.gmail.GmailConnection.

The Gmail SDK is fully mocked. We construct connections via __new__
and inject a fake service builder so we don't need real OAuth or
network I/O.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

# Skip everything if the optional [gmail] extra isn't installed.
pytest.importorskip("googleapiclient")
pytest.importorskip("google.oauth2.credentials")

from googleapiclient.errors import HttpError  # noqa: E402

from mailsuite.mailbox import MailboxConnection  # noqa: E402
from mailsuite.mailbox.gmail import GmailConnection, _get_creds  # noqa: E402


class FakeGmailService:
    """A chainable MagicMock that records the last operation result."""

    def __init__(self):
        self.users_obj = MagicMock()
        self.labels_obj = MagicMock()
        self.messages_obj = MagicMock()
        self.users_obj.return_value.labels.return_value = self.labels_obj
        self.users_obj.return_value.messages.return_value = self.messages_obj

    def users(self):
        return self.users_obj()


def _bare_connection(label_id: str = "L1") -> GmailConnection:
    """Build a GmailConnection bypassing OAuth + service.build()."""
    inst = GmailConnection.__new__(GmailConnection)
    inst.service = FakeGmailService()
    inst.include_spam_trash = False
    inst.reports_label_id = label_id
    inst.paginate_messages = True
    return inst


class TestSubclass:
    def test_is_mailbox_connection(self):
        assert issubclass(GmailConnection, MailboxConnection)


class TestGetCreds:
    def test_unsupported_auth_mode(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported"):
            _get_creds(
                str(tmp_path / "tok.json"),
                str(tmp_path / "creds.json"),
                ["scope"],
                0,
                auth_mode="bogus",
            )

    def test_service_account(self, tmp_path, monkeypatch):
        called = {}

        class FakeSACredentials:
            @classmethod
            def from_service_account_file(cls, file, scopes=None):
                called["file"] = file
                called["scopes"] = scopes
                inst = cls()
                inst._with_subject = None
                return inst

            def with_subject(self, user):
                self._with_subject = user
                return self

        # Patch the service_account module's Credentials class
        from mailsuite.mailbox import gmail as gmail_mod

        monkeypatch.setattr(
            gmail_mod.service_account, "Credentials", FakeSACredentials
        )
        creds = _get_creds(
            "ignored",
            str(tmp_path / "creds.json"),
            ["scope1"],
            0,
            auth_mode="service_account",
            service_account_user="user@example.com",
        )
        assert called["scopes"] == ["scope1"]
        assert creds._with_subject == "user@example.com"


class TestCreateFolder:
    def test_archive_skipped(self):
        conn = _bare_connection()
        conn.create_folder("Archive")
        # No call to labels().create
        conn.service.labels_obj.create.assert_not_called()

    def test_creates_label(self):
        conn = _bare_connection()
        conn.service.labels_obj.create.return_value.execute.return_value = {}
        conn.create_folder("Reports")
        conn.service.labels_obj.create.assert_called_once()

    def test_existing_label_409_swallowed(self):
        conn = _bare_connection()
        err = HttpError(
            resp=MagicMock(status=409, reason="Conflict"),
            content=b'{"error": "exists"}',
        )
        conn.service.labels_obj.create.return_value.execute.side_effect = err
        # Should not raise
        conn.create_folder("Reports")

    def test_other_http_error_propagates(self):
        conn = _bare_connection()
        err = HttpError(
            resp=MagicMock(status=500, reason="Server Error"),
            content=b'{"error": "boom"}',
        )
        conn.service.labels_obj.create.return_value.execute.side_effect = err
        with pytest.raises(HttpError):
            conn.create_folder("Reports")


class TestFetchMessages:
    def test_single_page(self):
        conn = _bare_connection()
        conn._find_label_id_for_label = MagicMock(return_value="L42")
        conn.service.messages_obj.list.return_value.execute.return_value = {
            "messages": [{"id": "m1"}, {"id": "m2"}],
        }
        ids = conn.fetch_messages("Reports")
        assert ids == ["m1", "m2"]

    def test_paginates(self):
        conn = _bare_connection()
        conn._find_label_id_for_label = MagicMock(return_value="L42")
        # Two pages: first has nextPageToken, second doesn't
        conn.service.messages_obj.list.return_value.execute.side_effect = [
            {"messages": [{"id": "m1"}], "nextPageToken": "tok"},
            {"messages": [{"id": "m2"}]},
        ]
        ids = conn.fetch_messages("Reports")
        assert ids == ["m1", "m2"]

    def test_pagination_disabled(self):
        conn = _bare_connection()
        conn.paginate_messages = False
        conn._find_label_id_for_label = MagicMock(return_value="L42")
        conn.service.messages_obj.list.return_value.execute.side_effect = [
            {"messages": [{"id": "m1"}], "nextPageToken": "tok"},
        ]
        ids = conn.fetch_messages("Reports")
        assert ids == ["m1"]

    def test_with_since_filter(self):
        conn = _bare_connection()
        conn._find_label_id_for_label = MagicMock(return_value="L42")
        conn.service.messages_obj.list.return_value.execute.return_value = {
            "messages": [{"id": "m1"}],
        }
        conn.fetch_messages("Reports", since="2026/04/01")
        # The list call was made with q="after:..."
        kwargs = conn.service.messages_obj.list.call_args.kwargs
        assert kwargs["q"] == "after:2026/04/01"


class TestFetchMessage:
    def test_decodes_raw(self):
        conn = _bare_connection()
        body = "From: a\r\nSubject: test\r\n\r\nbody\r\n"
        encoded = base64.urlsafe_b64encode(body.encode()).decode()
        conn.service.messages_obj.get.return_value.execute.return_value = {
            "raw": encoded
        }
        result = conn.fetch_message("m1")
        assert "Subject: test" in result


class TestDeleteMessage:
    def test_calls_delete(self):
        conn = _bare_connection()
        conn.delete_message("m1")
        conn.service.messages_obj.delete.assert_called_once_with(userId="me", id="m1")


class TestMoveMessage:
    def test_modifies_labels(self):
        conn = _bare_connection(label_id="REPORTS")
        conn._find_label_id_for_label = MagicMock(return_value="ARCHIVE")
        conn.move_message("m1", "Archive")
        kwargs = conn.service.messages_obj.modify.call_args.kwargs
        assert kwargs["id"] == "m1"
        assert kwargs["body"] == {
            "addLabelIds": ["ARCHIVE"],
            "removeLabelIds": ["REPORTS"],
        }


class TestSendMessage:
    def test_sends_encoded_message(self, dkim_keypair):
        conn = _bare_connection()
        conn.service.messages_obj.send.return_value.execute.return_value = {
            "id": "sent-123"
        }
        result = conn.send_message(
            message_from="a@example.com",
            message_to=["b@example.org"],
            subject="hi",
            plain_message="hello",
        )
        assert result == "sent-123"
        body = conn.service.messages_obj.send.call_args.kwargs["body"]
        assert "raw" in body
        # Decode the raw and check the message looks right
        raw = base64.urlsafe_b64decode(body["raw"]).decode()
        assert "Subject: hi" in raw
        assert "hello" in raw

    def test_send_with_attachments(self):
        conn = _bare_connection()
        conn.service.messages_obj.send.return_value.execute.return_value = {"id": "s2"}
        conn.send_message(
            message_from="a@example.com",
            message_to=["b@example.org"],
            attachments=[("file.txt", b"data")],
        )
        body = conn.service.messages_obj.send.call_args.kwargs["body"]
        raw = base64.urlsafe_b64decode(body["raw"]).decode()
        assert "file.txt" in raw


class TestKeepalive:
    def test_no_op(self):
        conn = _bare_connection()
        conn.keepalive()


class TestLabelLookup:
    def test_finds_by_name(self):
        conn = _bare_connection()
        conn.service.labels_obj.list.return_value.execute.return_value = {
            "labels": [
                {"id": "L1", "name": "INBOX"},
                {"id": "L42", "name": "Reports"},
            ]
        }
        # bypass the lru_cache on the bound method by using the function directly
        conn._find_label_id_for_label.cache_clear()
        assert conn._find_label_id_for_label("Reports") == "L42"

    def test_finds_by_id(self):
        conn = _bare_connection()
        conn.service.labels_obj.list.return_value.execute.return_value = {
            "labels": [{"id": "L42", "name": "Reports"}]
        }
        conn._find_label_id_for_label.cache_clear()
        assert conn._find_label_id_for_label("L42") == "L42"

    def test_missing_returns_empty(self):
        conn = _bare_connection()
        conn.service.labels_obj.list.return_value.execute.return_value = {"labels": []}
        conn._find_label_id_for_label.cache_clear()
        assert conn._find_label_id_for_label("Nope") == ""


class TestWatch:
    def test_exits_on_config_reload(self):
        conn = _bare_connection()
        calls = {"n": 0}
        conn.watch(
            lambda c: calls.update(n=calls["n"] + 1),
            check_timeout=0,
            config_reloading=lambda: True,
        )
        assert calls["n"] == 0

    def test_calls_callback_then_exits(self):
        conn = _bare_connection()
        calls = {"n": 0}

        def reload():
            return calls["n"] > 0

        def cb(c):
            calls["n"] += 1

        conn.watch(cb, check_timeout=0, config_reloading=reload)
        assert calls["n"] == 1


class TestTokenFileMkdir:
    """_get_creds must create the parent directory of the token file when
    persisting newly-issued credentials. Callers point token_file at paths
    inside fresh config directories.
    """

    def test_installed_app_creates_parent_dirs(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock

        from mailsuite.mailbox import gmail as gmail_mod

        token_path = tmp_path / "deep" / "nested" / "token.json"
        creds_file = tmp_path / "client_secrets.json"
        creds_file.write_text("{}")

        # Stub the OAuth flow — return a fake creds whose to_json() yields a
        # known string we can assert on.
        fake_creds = MagicMock()
        fake_creds.valid = True
        fake_creds.to_json.return_value = '{"access_token": "stub"}'
        fake_flow = MagicMock()
        fake_flow.run_local_server.return_value = fake_creds
        monkeypatch.setattr(
            gmail_mod.InstalledAppFlow,
            "from_client_secrets_file",
            classmethod(lambda cls, f, s: fake_flow),
        )

        assert not token_path.parent.exists()
        result = gmail_mod._get_creds(
            str(token_path), str(creds_file), ["scope"], oauth2_port=0
        )

        assert result is fake_creds
        assert token_path.exists()
        assert token_path.read_text() == '{"access_token": "stub"}'
