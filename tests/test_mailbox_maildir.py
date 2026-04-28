"""Tests for mailsuite.mailbox.maildir."""

from __future__ import annotations

import mailbox
import os

import pytest

from mailsuite.mailbox import MailboxConnection, MaildirConnection


@pytest.fixture
def maildir_path(tmp_path):
    md = tmp_path / "Maildir"
    md.mkdir()
    return str(md)


class TestMaildirConnection:
    def test_subclasses_mailbox_connection(self):
        assert issubclass(MaildirConnection, MailboxConnection)

    def test_create_with_subdirs(self, maildir_path):
        MaildirConnection(maildir_path, maildir_create=True)
        for sub in ("cur", "new", "tmp"):
            assert os.path.isdir(os.path.join(maildir_path, sub))

    def test_create_folder(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Reports")
        # subfolder is stored under .Reports per Maildir++ convention
        assert os.path.isdir(os.path.join(maildir_path, ".Reports"))

    def test_fetch_messages_inbox(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        box = mailbox.Maildir(maildir_path)
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: t\r\n\r\nbody\r\n")
        msg.add_flag("S")
        key = box.add(msg)
        assert key in conn.fetch_messages("INBOX")
        assert key in conn.fetch_messages("")

    def test_fetch_messages_subfolder(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Reports")
        box = mailbox.Maildir(maildir_path)
        folder = box.get_folder("Reports")
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: t\r\n\r\nbody\r\n")
        msg.add_flag("S")
        key = folder.add(msg)
        assert key in conn.fetch_messages("Reports")

    def test_fetch_message(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Reports")
        box = mailbox.Maildir(maildir_path)
        folder = box.get_folder("Reports")
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: hi\r\n\r\nbody\r\n")
        msg.add_flag("S")
        key = folder.add(msg)
        conn.fetch_messages("Reports")  # selects active folder
        raw = conn.fetch_message(key)
        assert "Subject: hi" in raw
        assert "body" in raw

    def test_fetch_message_missing_returns_empty(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.fetch_messages("INBOX")
        assert conn.fetch_message("does-not-exist") == ""

    def test_fetch_message_marks_read(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Reports")
        box = mailbox.Maildir(maildir_path)
        folder = box.get_folder("Reports")
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: t\r\n\r\nbody\r\n")
        # message starts in new/
        msg.set_subdir("new")
        key = folder.add(msg)
        conn.fetch_messages("Reports")
        conn.fetch_message(key, mark_read=True)
        # after fetch with mark_read, message is in cur/ with S flag
        refetched = mailbox.Maildir(maildir_path).get_folder("Reports")[key]
        assert refetched.get_subdir() == "cur"
        assert "S" in refetched.get_flags()

    def test_delete_message(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        box = mailbox.Maildir(maildir_path)
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: t\r\n\r\nbody\r\n")
        msg.add_flag("S")
        key = box.add(msg)
        conn.fetch_messages("INBOX")
        conn.delete_message(key)
        assert key not in conn.fetch_messages("INBOX")

    def test_move_message(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Archive")
        box = mailbox.Maildir(maildir_path)
        msg = mailbox.MaildirMessage(b"From: a\r\nSubject: t\r\n\r\nbody\r\n")
        msg.add_flag("S")
        key = box.add(msg)
        conn.fetch_messages("INBOX")
        conn.move_message(key, "Archive")
        # gone from inbox, present in archive
        assert key not in conn.fetch_messages("INBOX")
        archive_keys = conn.fetch_messages("Archive")
        assert len(archive_keys) == 1

    def test_move_missing_message_no_op(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        conn.create_folder("Archive")
        conn.fetch_messages("INBOX")
        # Should not raise even when the message ID doesn't exist
        conn.move_message("missing", "Archive")

    def test_keepalive_no_op(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        # Just verify it doesn't raise
        conn.keepalive()

    def test_send_raises(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        with pytest.raises(NotImplementedError, match="Maildir"):
            conn.send_message("a@example.com", ["b@example.org"])

    def test_watch_exits_on_config_reload(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        calls = {"n": 0}

        def reload():
            return True

        # Should exit immediately without calling check_callback
        conn.watch(lambda c: calls.update(n=calls["n"] + 1), check_timeout=1, config_reloading=reload)
        assert calls["n"] == 0

    def test_watch_calls_callback(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        calls = {"n": 0}
        flag = {"reload": False}

        def reload():
            # First check returns False so the callback runs;
            # after the callback we flip and exit.
            if calls["n"] >= 1:
                flag["reload"] = True
            return flag["reload"]

        def cb(c):
            calls["n"] += 1

        conn.watch(cb, check_timeout=0, config_reloading=reload)
        assert calls["n"] == 1

    def test_watch_callback_exception_logged(self, maildir_path):
        conn = MaildirConnection(maildir_path, maildir_create=True)
        flag = {"first": True}

        def reload():
            if flag["first"]:
                flag["first"] = False
                return False
            return True

        def cb(c):
            raise RuntimeError("boom")

        # Should log warning and exit cleanly without re-raising
        conn.watch(cb, check_timeout=0, config_reloading=reload)


class TestUidMismatch:
    """Maildir on Linux/Docker often runs with a non-root user that doesn't
    own the maildir directory. We must warn — not crash — so the operator
    can fix permissions instead of debugging an unhandled OSError on import.
    """

    def test_non_root_mismatch_warns(self, maildir_path, monkeypatch, caplog):
        import logging
        import os

        from mailsuite.mailbox import maildir as md_mod

        real_stat = os.stat(maildir_path)
        # os.stat returns a real stat_result; the .st_uid attribute is the
        # only field the implementation reads. Ensure mismatch by claiming
        # owner uid is one above whatever the runtime uid will be.
        runtime_uid = 1000
        owner_uid = runtime_uid + 1

        class FakeStat:
            st_uid = owner_uid

            def __getattr__(self, name):
                return getattr(real_stat, name)

        monkeypatch.setattr(md_mod.os, "stat", lambda p: FakeStat())
        monkeypatch.setattr(md_mod.os, "getuid", lambda: runtime_uid)

        with caplog.at_level(logging.WARNING, logger="mailsuite.mailbox.maildir"):
            # Should not raise — just warn
            MaildirConnection(maildir_path, maildir_create=False)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("differs from maildir" in r.getMessage() for r in warnings)

    def test_root_with_mismatch_attempts_setuid(self, maildir_path, monkeypatch):
        import os

        from mailsuite.mailbox import maildir as md_mod

        real_stat = os.stat(maildir_path)
        owner_uid = 1234

        class FakeStat:
            st_uid = owner_uid

            def __getattr__(self, name):
                return getattr(real_stat, name)

        setuid_calls = []
        monkeypatch.setattr(md_mod.os, "stat", lambda p: FakeStat())
        monkeypatch.setattr(md_mod.os, "getuid", lambda: 0)
        monkeypatch.setattr(md_mod.os, "setuid", lambda uid: setuid_calls.append(uid))

        MaildirConnection(maildir_path, maildir_create=False)
        assert setuid_calls == [owner_uid]

    def test_no_mismatch_no_warning(self, maildir_path, monkeypatch, caplog):
        import logging
        import os

        from mailsuite.mailbox import maildir as md_mod

        real_stat = os.stat(maildir_path)
        # owner uid matches the (faked) runtime uid → no warning, no setuid
        monkeypatch.setattr(md_mod.os, "getuid", lambda: real_stat.st_uid)

        with caplog.at_level(logging.WARNING, logger="mailsuite.mailbox.maildir"):
            MaildirConnection(maildir_path, maildir_create=False)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert not any("differs from maildir" in r.getMessage() for r in warnings)
        assert not any("Switching uid" in r.getMessage() for r in warnings)
