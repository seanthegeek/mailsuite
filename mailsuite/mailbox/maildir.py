"""Maildir mailbox backend"""

from __future__ import annotations

import logging
import mailbox
import os
from time import sleep
from typing import Any, Callable, Dict, Optional

from mailsuite.mailbox.base import MailboxConnection

logger = logging.getLogger(__name__)


class MaildirConnection(MailboxConnection):
    """
    A :class:`MailboxConnection` backed by an on-disk Maildir

    Useful for local processing of messages dropped into a Maildir by an MTA
    (e.g. postfix delivering DMARC reports). Maildir has no concept of
    sending — :meth:`send_message` raises :class:`NotImplementedError`.
    """

    def __init__(
        self,
        maildir_path: str,
        maildir_create: bool = False,
    ):
        self._maildir_path = maildir_path
        self._maildir_create = maildir_create

        # When run as root over a user-owned Maildir, drop privileges to the
        # Maildir's owner so file creation/locking works correctly. This is
        # specific to UNIX-like systems with os.getuid()/setuid().
        getuid = getattr(os, "getuid", None)
        setuid = getattr(os, "setuid", None)
        if getuid is not None and setuid is not None:
            try:
                maildir_owner = os.stat(maildir_path).st_uid
            except OSError:
                maildir_owner = None
            current_uid = getuid()
            if maildir_owner is not None and current_uid != maildir_owner:
                if current_uid == 0:
                    try:
                        logger.warning(
                            "Switching uid to %s to access Maildir", maildir_owner
                        )
                        setuid(maildir_owner)
                    except OSError as e:
                        logger.warning(
                            "Failed to switch uid to %s: %s", maildir_owner, e
                        )
                else:
                    logger.warning(
                        "Runtime uid %s differs from maildir %s owner %s. "
                        "Access may fail if permissions are insufficient.",
                        current_uid,
                        maildir_path,
                        maildir_owner,
                    )

        if maildir_create:
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(maildir_path, subdir), exist_ok=True)
        self._client = mailbox.Maildir(maildir_path, create=maildir_create)
        self._active_folder: mailbox.Maildir = self._client
        self._subfolder_client: Dict[str, mailbox.Maildir] = {}

    def _get_folder(self, folder_name: str) -> mailbox.Maildir:
        if folder_name not in self._subfolder_client:
            self._subfolder_client[folder_name] = self._client.add_folder(folder_name)
        return self._subfolder_client[folder_name]

    def create_folder(self, folder_name: str) -> None:
        self._get_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> list:
        if reports_folder and reports_folder != "INBOX":
            self._active_folder = self._get_folder(reports_folder)
        else:
            self._active_folder = self._client
        return list(self._active_folder.keys())

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        msg = self._active_folder.get(message_id)
        if msg is None:
            return ""
        msg_str = msg.as_string()
        if kwargs.get("mark_read"):
            # Maildir spec: a message is "read" once it has been moved out of
            # new/ into cur/ with the "S" (Seen) flag set in its info field.
            msg.set_subdir("cur")
            msg.add_flag("S")
            self._active_folder[message_id] = msg
        return msg_str or ""

    def delete_message(self, message_id: Any) -> None:
        self._active_folder.remove(message_id)

    def move_message(self, message_id: Any, folder_name: str) -> None:
        message_data = self._active_folder.get(message_id)
        if message_data is None:
            return
        dest = self._get_folder(folder_name)
        dest.add(message_data)
        self._active_folder.remove(message_id)

    def keepalive(self) -> None:
        return

    def watch(
        self,
        check_callback: Callable[[MailboxConnection], None],
        check_timeout: int,
        config_reloading: Optional[Callable[[], bool]] = None,
    ) -> None:
        while True:
            if config_reloading and config_reloading():
                return
            try:
                check_callback(self)
            except Exception as e:
                logger.warning("Maildir init error. %s", e)
            if config_reloading and config_reloading():
                return
            sleep(check_timeout)

    def send_message(self, *args: Any, **kwargs: Any) -> Optional[str]:
        raise NotImplementedError(
            "Maildir cannot send mail; use mailsuite.smtp.send_email"
        )
