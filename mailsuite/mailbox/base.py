"""Abstract base class for mailbox connections"""

from __future__ import annotations

from abc import ABC
from typing import Any, Callable, Optional, Tuple


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
