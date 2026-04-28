"""Tests for mailsuite.mailbox.base.MailboxConnection ABC."""

from __future__ import annotations

import pytest

from mailsuite.mailbox import MailboxConnection


class TestABCDefaultMethods:
    """Each method on the bare ABC should raise NotImplementedError."""

    @pytest.fixture
    def conn(self) -> MailboxConnection:
        # MailboxConnection is an ABC, but it has no abstractmethod decorators
        # — calling instantiates fine (a deliberate parsedmarc choice). Each
        # method just raises NotImplementedError.
        return MailboxConnection.__new__(MailboxConnection)

    def test_create_folder(self, conn):
        with pytest.raises(NotImplementedError):
            conn.create_folder("Reports")

    def test_fetch_messages(self, conn):
        with pytest.raises(NotImplementedError):
            conn.fetch_messages("INBOX")

    def test_fetch_message(self, conn):
        with pytest.raises(NotImplementedError):
            conn.fetch_message("id")

    def test_delete_message(self, conn):
        with pytest.raises(NotImplementedError):
            conn.delete_message("id")

    def test_move_message(self, conn):
        with pytest.raises(NotImplementedError):
            conn.move_message("id", "Archive")

    def test_keepalive(self, conn):
        with pytest.raises(NotImplementedError):
            conn.keepalive()

    def test_watch(self, conn):
        with pytest.raises(NotImplementedError):
            conn.watch(lambda c: None, 30)

    def test_send_message(self, conn):
        with pytest.raises(NotImplementedError):
            conn.send_message("a@example.com")
