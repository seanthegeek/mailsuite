"""Maildir mailbox backend"""

from __future__ import annotations

import logging
import mailbox
import os
from collections.abc import Callable
from time import sleep
from typing import Any

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
        self._subfolder_client: dict[str, mailbox.Maildir] = {}

    def _get_folder(self, folder_name: str) -> mailbox.Maildir:
        if folder_name not in self._subfolder_client:
            self._subfolder_client[folder_name] = self._client.add_folder(folder_name)
        return self._subfolder_client[folder_name]

    def create_folder(self, folder_name: str) -> None:
        self._get_folder(folder_name)

    def rename_folder(self, old_name: str, new_name: str) -> None:
        # Maildir++ stores each folder as a sibling directory named
        # ".<folder>"; the stdlib mailbox.Maildir has no rename, so move the
        # directory and drop the stale cached client for the old name. Guard
        # first: os.rename would otherwise silently replace an empty target.
        self._ensure_no_folder_conflict(new_name)
        old_path = os.path.join(self._maildir_path, "." + old_name)
        new_path = os.path.join(self._maildir_path, "." + new_name)
        os.rename(old_path, new_path)
        self._subfolder_client.pop(old_name, None)
        self._subfolder_client.pop(new_name, None)

    def folder_exists(self, folder_name: str) -> bool:
        return os.path.isdir(os.path.join(self._maildir_path, "." + folder_name))

    def delete_folder(self, folder_name: str) -> None:
        # stdlib remove_folder requires the folder be empty of messages and
        # subfolders; merge_folders empties it first.
        self._client.remove_folder(folder_name)
        self._subfolder_client.pop(folder_name, None)

    def _do_move_folder(
        self, source: str, target_parent: str, target_path: str
    ) -> None:
        del target_parent
        os.rename(
            os.path.join(self._maildir_path, "." + source),
            os.path.join(self._maildir_path, "." + target_path),
        )
        self._subfolder_client.pop(source, None)
        self._subfolder_client.pop(target_path, None)

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> list:
        if reports_folder and reports_folder != "INBOX":
            self._active_folder = self._get_folder(reports_folder)
        else:
            self._active_folder = self._client
        return list(self._active_folder.keys())

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        """
        Return the message's stored bytes decoded as UTF-8 (undecodable bytes
        replaced), the same decoding
        ``mailsuite.imap.IMAPClient.fetch_message(parse=False)``
        applies to the IMAP backend's raw fetch. The file is not parsed or
        re-serialized, so a message ``email`` can parse but not generate
        (e.g. a ``\\x1c`` in a nested header, or deep ``multipart`` nesting)
        is returned as-is. ``Maildir.get_bytes`` converts ``os.linesep`` to
        ``\\n``, which is a no-op on POSIX. Returns ``""`` for an unknown
        ``message_id``.

        With ``mark_read=True`` the file is renamed into ``cur/`` with the
        ``S`` (Seen) flag added to its info suffix, which is what the Maildir
        spec defines a flag change to be; the content is untouched.
        """
        folder = self._active_folder
        try:
            msg_str = folder.get_bytes(message_id).decode("utf-8", "replace")
        except KeyError:
            return ""
        if kwargs.get("mark_read"):
            # mailbox.Maildir has no public way to get a message's on-disk
            # name (or its own path) without parsing the message; _lookup(),
            # _path, and _toc are what its own get_bytes/remove/__setitem__
            # use. _lookup() only rescans a stale name when _refresh() sees
            # the directory as changed, so record the new name in _toc the
            # way CPython 3.13+'s Maildir.set_info() does after its rename.
            subpath = folder._lookup(message_id)  # pyright: ignore[reportAttributeAccessIssue]
            name = os.path.basename(subpath)
            flags = mailbox.MaildirMessage()
            if folder.colon in name:
                flags.set_info(name.split(folder.colon)[-1])
            flags.add_flag("S")
            new_subpath = os.path.join(
                "cur", message_id + folder.colon + flags.get_info()
            )
            os.rename(
                os.path.join(folder._path, subpath),
                os.path.join(folder._path, new_subpath),
            )
            folder._toc[message_id] = new_subpath  # pyright: ignore[reportAttributeAccessIssue]
        return msg_str

    def delete_message(self, message_id: Any) -> None:
        self._active_folder.remove(message_id)

    def move_message(self, message_id: Any, folder_name: str) -> None:
        """
        Move the message's file into the same subdirectory (``new``/``cur``)
        of ``folder_name``, keeping its filename, flags, and bytes, instead of
        re-serializing it through ``Maildir.add``. Maildir++ folders live
        under the same root, so this is a same-filesystem rename; if a folder
        is a separate mount, ``os.rename`` raises ``OSError`` (``EXDEV``).
        Raises ``mailbox.ExternalClashError`` rather than overwriting if the
        destination already holds a message with the same key (including a
        move into the active folder itself).
        """
        folder = self._active_folder
        try:
            subpath = folder._lookup(message_id)  # pyright: ignore[reportAttributeAccessIssue]
        except KeyError:
            return
        dest = self._get_folder(folder_name)
        if message_id in dest:
            raise mailbox.ExternalClashError(
                f"Folder {folder_name} already contains message {message_id}"
            )
        os.rename(
            os.path.join(folder._path, subpath),
            os.path.join(dest._path, subpath),
        )
        # Keep both tables of contents current; see fetch_message's mark_read.
        folder._toc.pop(message_id, None)  # pyright: ignore[reportAttributeAccessIssue]
        dest._toc[message_id] = subpath  # pyright: ignore[reportAttributeAccessIssue]

    def keepalive(self) -> None:
        return

    def watch(
        self,
        check_callback: Callable[[MailboxConnection], None],
        check_timeout: int,
        config_reloading: Callable[[], bool] | None = None,
    ) -> None:
        while True:
            if config_reloading and config_reloading():
                return
            try:
                check_callback(self)
            except Exception as e:  # noqa: BLE001
                logger.warning("Maildir init error. %s", e)
            if config_reloading and config_reloading():
                return
            sleep(check_timeout)

    def send_message(self, *args: Any, **kwargs: Any) -> str | None:
        raise NotImplementedError(
            "Maildir cannot send mail; use mailsuite.smtp.send_email"
        )
