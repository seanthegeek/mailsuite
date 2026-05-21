"""Tests for mailsuite.mailbox.base.MailboxConnection ABC."""

from __future__ import annotations

import pytest

from mailsuite.mailbox import (
    FolderExistsError,
    FolderNotFoundError,
    MailboxConnection,
)


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

    def test_rename_folder(self, conn):
        with pytest.raises(NotImplementedError):
            conn.rename_folder("Reports", "Archive")

    def test_folder_exists(self, conn):
        with pytest.raises(NotImplementedError):
            conn.folder_exists("Reports")

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


class TestFolderExistsError:
    def test_is_runtime_error(self):
        # Subclassing RuntimeError lets callers catch it as a domain error
        # without importing the specific type.
        assert issubclass(FolderExistsError, RuntimeError)

    def test_guard_raises_when_folder_present(self):
        conn = MailboxConnection.__new__(MailboxConnection)
        conn.folder_exists = lambda name: True  # type: ignore[method-assign]
        with pytest.raises(FolderExistsError):
            conn._ensure_no_folder_conflict("Archive")

    def test_guard_passes_when_absent(self):
        conn = MailboxConnection.__new__(MailboxConnection)
        conn.folder_exists = lambda name: False  # type: ignore[method-assign]
        conn._ensure_no_folder_conflict("Archive")  # no raise


class _FakeConn(MailboxConnection):
    """A minimal in-memory connection for exercising the generic move_folder
    and merge_folders orchestration (which lives on the base class)."""

    def __init__(self, folders=(), messages=None):
        self.folders = set(folders)
        self.messages = {k: list(v) for k, v in (messages or {}).items()}
        self.created = []
        self.deleted_folders = []
        self.relocated = []  # (source, target_parent, target_path)
        self.moved_messages = []  # (message_id, destination)

    def folder_exists(self, folder_name):
        return folder_name in self.folders

    def create_folder(self, folder_name):
        self.created.append(folder_name)
        self.folders.add(folder_name)

    def delete_folder(self, folder_name):
        self.deleted_folders.append(folder_name)
        self.folders.discard(folder_name)

    def fetch_messages(self, reports_folder, **kwargs):
        return list(self.messages.get(reports_folder, []))

    def move_message(self, message_id, folder_name):
        self.moved_messages.append((message_id, folder_name))

    def _do_move_folder(self, source, target_parent, target_path):
        self.relocated.append((source, target_parent, target_path))


class TestMoveFolder:
    def test_new_path(self):
        conn = _FakeConn(folders={"A/X", "B"})
        conn.move_folder("A/X", new_path="B/Y")
        assert conn.relocated == [("A/X", "B", "B/Y")]

    def test_new_parent_keeps_leaf(self):
        conn = _FakeConn(folders={"A/X", "B"})
        conn.move_folder("A/X", new_parent="B")
        assert conn.relocated == [("A/X", "B", "B/X")]

    def test_new_path_top_level_has_no_parent(self):
        conn = _FakeConn(folders={"A/X"})
        conn.move_folder("A/X", new_path="Y")
        assert conn.relocated == [("A/X", "", "Y")]

    def test_new_parent_root_keeps_leaf(self):
        conn = _FakeConn(folders={"A/X"})
        conn.move_folder("A/X", new_parent="")
        assert conn.relocated == [("A/X", "", "X")]

    def test_requires_exactly_one_destination(self):
        conn = _FakeConn(folders={"A/X"})
        with pytest.raises(ValueError):
            conn.move_folder("A/X")
        with pytest.raises(ValueError):
            conn.move_folder("A/X", new_path="B/Y", new_parent="B")

    def test_missing_source_raises(self):
        conn = _FakeConn(folders={"B"})
        with pytest.raises(FolderNotFoundError):
            conn.move_folder("A/X", new_path="B/Y")

    def test_missing_parent_raises_by_default(self):
        conn = _FakeConn(folders={"A/X"})
        with pytest.raises(FolderNotFoundError):
            conn.move_folder("A/X", new_path="B/Y")
        assert conn.relocated == []

    def test_missing_parent_created_when_requested(self):
        conn = _FakeConn(folders={"A/X"})
        conn.move_folder("A/X", new_parent="B", create=True)
        assert conn.created == ["B"]
        assert conn.relocated == [("A/X", "B", "B/X")]

    def test_conflict_raises(self):
        conn = _FakeConn(folders={"A/X", "B", "B/Y"})
        with pytest.raises(FolderExistsError):
            conn.move_folder("A/X", new_path="B/Y")
        assert conn.relocated == []


class TestMergeFolders:
    def test_moves_then_deletes_sources(self):
        conn = _FakeConn(folders={"Src", "Dest"}, messages={"Src": ["m1", "m2"]})
        conn.merge_folders("Src", "Dest")
        assert conn.moved_messages == [("m1", "Dest"), ("m2", "Dest")]
        assert conn.deleted_folders == ["Src"]

    def test_keep_source_folders(self):
        conn = _FakeConn(folders={"Src", "Dest"}, messages={"Src": ["m1"]})
        conn.merge_folders("Src", "Dest", keep_source_folders=True)
        assert conn.moved_messages == [("m1", "Dest")]
        assert conn.deleted_folders == []

    def test_multiple_sources(self):
        conn = _FakeConn(
            folders={"S1", "S2", "Dest"},
            messages={"S1": ["a"], "S2": ["b"]},
        )
        conn.merge_folders(["S1", "S2"], "Dest")
        assert conn.moved_messages == [("a", "Dest"), ("b", "Dest")]
        assert conn.deleted_folders == ["S1", "S2"]

    def test_creates_destination_when_requested(self):
        conn = _FakeConn(folders={"Src"}, messages={"Src": ["m1"]})
        conn.merge_folders("Src", "Dest", create=True)
        assert conn.created == ["Dest"]
        assert conn.moved_messages == [("m1", "Dest")]

    def test_missing_destination_raises_by_default(self):
        conn = _FakeConn(folders={"Src"})
        with pytest.raises(FolderNotFoundError):
            conn.merge_folders("Src", "Dest")

    def test_missing_source_raises(self):
        conn = _FakeConn(folders={"Dest"})
        with pytest.raises(FolderNotFoundError):
            conn.merge_folders("Src", "Dest")

    def test_merging_into_itself_is_a_no_op(self):
        conn = _FakeConn(folders={"Dest"}, messages={"Dest": ["m1"]})
        conn.merge_folders("Dest", "Dest")
        assert conn.moved_messages == []
        assert conn.deleted_folders == []
