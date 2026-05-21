"""Abstract base class for mailbox connections"""

from __future__ import annotations

from abc import ABC
from typing import Any, Callable, Optional, Tuple


class FolderExistsError(RuntimeError):
    """Raised by :meth:`MailboxConnection.rename_folder` when the target
    name is already taken by another folder/label."""


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
