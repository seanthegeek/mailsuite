"""Abstract base class for mailbox connections"""

from __future__ import annotations

from abc import ABC
from typing import Any, Callable, List, Optional, Tuple, Union


class FolderExistsError(RuntimeError):
    """Raised when a folder/label operation targets a name that is already
    taken — e.g. :meth:`MailboxConnection.rename_folder` or
    :meth:`MailboxConnection.move_folder` onto an existing name."""


class FolderNotFoundError(RuntimeError):
    """Raised when a folder/label referenced by an operation does not exist —
    e.g. the source of a :meth:`MailboxConnection.move_folder` /
    :meth:`MailboxConnection.merge_folders`, or a destination when its
    ``create`` parameter is left ``False``."""


class MailboxConnection(ABC):
    """
    A provider-agnostic interface for a mailbox

    Subclasses implement the methods for a specific protocol (IMAP, Microsoft
    Graph, Gmail, Maildir, etc.). Methods that don't apply to a given backend
    raise :class:`NotImplementedError`.
    """

    def create_folder(self, folder_name: str) -> None:
        """Create a folder/label in the mailbox"""
        raise NotImplementedError

    def delete_folder(self, folder_name: str) -> None:
        """Delete a folder/label from the mailbox"""
        raise NotImplementedError

    def rename_folder(self, old_name: str, new_name: str) -> None:
        """
        Rename a folder/label in the mailbox

        Implementations call :meth:`_ensure_no_folder_conflict` first, so a
        rename onto an existing name raises :class:`FolderExistsError`
        consistently rather than each backend's native behavior.

        Args:
            old_name: The current folder/label name (or path)
            new_name: The new folder/label name

        Raises:
            FolderExistsError: If ``new_name`` already exists.
        """
        raise NotImplementedError

    def folder_exists(self, folder_name: str) -> bool:
        """
        Return ``True`` if the named folder/label exists in the mailbox

        Args:
            folder_name: The folder/label name (or path) to check
        """
        raise NotImplementedError

    def _ensure_no_folder_conflict(self, folder_name: str) -> None:
        """Raise :class:`FolderExistsError` if ``folder_name`` already exists.

        Backends call this from :meth:`rename_folder` so a name collision
        fails uniformly, instead of each provider's native behavior — Graph
        silently creating a second folder with a duplicate display name,
        Maildir replacing an empty target directory, IMAP/Gmail raising
        provider-specific errors. Best-effort: a folder created between this
        check and the rename still falls back to the backend's behavior.
        """
        if self.folder_exists(folder_name):
            raise FolderExistsError(
                f"cannot rename to {folder_name!r}: a folder or label with "
                "that name already exists"
            )

    def move_folder(
        self,
        source: str,
        destination: str,
        destination_is_parent: bool = False,
        create: bool = False,
    ) -> None:
        """
        Relocate a folder (and its contents) to a new location

        By default ``destination`` is the folder's full new path. Set
        ``destination_is_parent=True`` to instead treat ``destination`` as
        the parent folder to move ``source`` under, keeping ``source``'s own
        leaf name (e.g. ``move_folder("Archive/Forensic", "Reports",
        destination_is_parent=True)`` yields ``Reports/Forensic``).

        Args:
            source: Path of the folder to move. Must exist.
            destination: New full path, or the parent path when
                ``destination_is_parent`` is set.
            destination_is_parent: Interpret ``destination`` as the parent
                folder rather than the full target path.
            create: Create the destination's parent path if it doesn't
                already exist. When ``False`` (default), a missing parent
                raises :class:`FolderNotFoundError`.

        Raises:
            FolderNotFoundError: If ``source`` (or, with ``create=False``,
                the destination parent) does not exist.
            FolderExistsError: If the target path is already taken.

        Note:
            On Gmail there are no real folders — only labels nested by a
            ``/`` naming convention — so a move renames the label's path and
            does not relocate independent descendant labels.
        """
        if not self.folder_exists(source):
            raise FolderNotFoundError(f"folder {source!r} not found")

        src_leaf = source.rpartition("/")[2]
        if destination_is_parent:
            target_parent = destination
            target_path = f"{destination}/{src_leaf}" if destination else src_leaf
        else:
            target_parent = destination.rpartition("/")[0]
            target_path = destination

        if target_parent and not self.folder_exists(target_parent):
            if create:
                self.create_folder(target_parent)
            else:
                raise FolderNotFoundError(
                    f"destination parent {target_parent!r} not found "
                    "(pass create=True to create it)"
                )

        self._ensure_no_folder_conflict(target_path)
        self._do_move_folder(source, target_parent, target_path)

    def merge_folders(
        self,
        sources: Union[str, List[str]],
        destination: str,
        create: bool = False,
        keep_source_folders: bool = False,
    ) -> None:
        """
        Move the contents of one or more folders into another

        Every message in each source folder is moved into ``destination``.

        Args:
            sources: A source folder path, or a list of them.
            destination: The folder to move messages into.
            create: Create ``destination`` if it doesn't already exist. When
                ``False`` (default), a missing destination raises
                :class:`FolderNotFoundError`.
            keep_source_folders: Leave the emptied source folders in place.
                When ``False`` (default), each source folder is deleted after
                its messages have been moved.

        Raises:
            FolderNotFoundError: If a source (or, with ``create=False``, the
                destination) does not exist.
        """
        if isinstance(sources, str):
            sources = [sources]

        if not self.folder_exists(destination):
            if create:
                self.create_folder(destination)
            else:
                raise FolderNotFoundError(
                    f"destination {destination!r} not found "
                    "(pass create=True to create it)"
                )

        for source in sources:
            if source == destination:
                continue
            if not self.folder_exists(source):
                raise FolderNotFoundError(f"folder {source!r} not found")
            for message_id in self.fetch_messages(source):
                self._move_message_from(message_id, source, destination)
            if not keep_source_folders:
                self.delete_folder(source)

    def _do_move_folder(
        self, source: str, target_parent: str, target_path: str
    ) -> None:
        """Backend-specific folder relocation, called by :meth:`move_folder`
        after it has validated existence, created any missing parent, and
        checked for a conflict. ``target_parent`` is ``""`` for the mailbox
        root."""
        raise NotImplementedError

    def _move_message_from(
        self, message_id: Any, source: str, destination: str
    ) -> None:
        """Move a single message from ``source`` to ``destination`` during a
        :meth:`merge_folders`. Defaults to :meth:`move_message`; backends
        whose ``move_message`` doesn't key off the message's current folder
        (Gmail labels) override this to drop the source label explicitly."""
        del source
        self.move_message(message_id, destination)

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> list:
        """Return a list of message identifiers in the given folder"""
        raise NotImplementedError

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        """Fetch the raw RFC 822 contents of a message by identifier"""
        raise NotImplementedError

    def delete_message(self, message_id: Any) -> None:
        """Permanently delete a message by identifier"""
        raise NotImplementedError

    def move_message(self, message_id: Any, folder_name: str) -> None:
        """Move a message to the named folder"""
        raise NotImplementedError

    def keepalive(self) -> None:
        """Send a no-op to keep the connection alive (if applicable)"""
        raise NotImplementedError

    def watch(
        self,
        check_callback: Callable[["MailboxConnection"], None],
        check_timeout: int,
        config_reloading: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Watch the mailbox for new messages, invoking ``check_callback`` when
        new mail arrives or on a polling interval

        Args:
            check_callback: Called with this :class:`MailboxConnection`
                instance whenever the watcher fires.
            check_timeout: Polling interval (or IDLE timeout) in seconds.
            config_reloading: Optional zero-argument callable. When it returns
                a truthy value, the watcher exits cleanly so the caller can
                reload configuration.
        """
        raise NotImplementedError

    def send_message(
        self,
        message_from: str,
        message_to: Optional[list[str]] = None,
        message_cc: Optional[list[str]] = None,
        message_bcc: Optional[list[str]] = None,
        subject: Optional[str] = None,
        message_headers: Optional[dict] = None,
        attachments: Optional[list[Tuple[str, bytes]]] = None,
        plain_message: Optional[str] = None,
        html_message: Optional[str] = None,
    ) -> Optional[str]:
        """
        Send a message through this mailbox's native send API (when supported)

        Backends without a native send (IMAP, Maildir) raise
        :class:`NotImplementedError`. Use :func:`mailsuite.smtp.send_email`
        directly when you need to send mail without a mailbox.

        Args:
            message_from: The value of the ``From`` header
            message_to: A list of recipient addresses
            message_cc: A list of Cc addresses
            message_bcc: A list of Bcc addresses
            subject: The message subject
            message_headers: Additional headers
            attachments: A list of ``(filename, bytes)`` tuples
            plain_message: The plain-text body
            html_message: The HTML body

        Returns:
            A provider-specific message identifier when available, otherwise
            ``None``.
        """
        raise NotImplementedError
