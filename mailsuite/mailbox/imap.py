"""IMAP mailbox backend"""

from __future__ import annotations

import logging
from socket import timeout
from time import sleep
from typing import Any, Callable, Optional, cast

from imapclient.exceptions import IMAPClientError

from mailsuite.imap import IMAPClient
from mailsuite.mailbox.base import MailboxConnection

logger = logging.getLogger(__name__)


class IMAPConnection(MailboxConnection):
    """
    A :class:`MailboxConnection` backed by IMAP

    Wraps :class:`mailsuite.imap.IMAPClient` and adds the
    :class:`MailboxConnection` semantics (folder/label management, polling
    via IDLE, etc.).

    IMAP is a receive-only protocol — :meth:`send_message` raises
    :class:`NotImplementedError`. Use :func:`mailsuite.smtp.send_email` for
    sending.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 993,
        ssl: bool = True,
        verify: bool = True,
        timeout: int = 30,
        max_retries: int = 4,
    ):
        self._username = user
        self._password = password
        self._verify = verify
        self._client = IMAPClient(
            host,
            user,
            password,
            port=port,
            ssl=ssl,
            verify=verify,
            timeout=timeout,
            max_retries=max_retries,
        )

    def create_folder(self, folder_name: str) -> None:
        self._client.create_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> list:
        self._client.select_folder(reports_folder)
        since = kwargs.get("since")
        if since is not None:
            return self._client.search(f"SINCE {since}")
        return self._client.search()

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        return cast(str, self._client.fetch_message(message_id, parse=False))

    def delete_message(self, message_id: Any) -> None:
        try:
            self._client.delete_messages([message_id])
        except IMAPClientError as error:
            logger.warning(
                "IMAP delete fallback for message %s due to server error: %s",
                message_id,
                error,
            )
            self._client.add_flags([message_id], [r"\Deleted"], silent=True)
            self._client.expunge()

    def move_message(self, message_id: Any, folder_name: str) -> None:
        try:
            self._client.move_messages([message_id], folder_name)
        except IMAPClientError as error:
            logger.warning(
                "IMAP move fallback for message %s due to server error: %s",
                message_id,
                error,
            )
            self._client.copy([message_id], folder_name)
            self.delete_message(message_id)

    def keepalive(self) -> None:
        self._client.noop()

    def watch(
        self,
        check_callback: Callable[[MailboxConnection], None],
        check_timeout: int,
        config_reloading: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Watch for new messages over an IDLE connection and dispatch each batch
        to ``check_callback``
        """

        def idle_callback_wrapper(client: IMAPClient) -> None:
            self._client = client
            check_callback(self)

        while True:
            if config_reloading and config_reloading():
                return
            try:
                IMAPClient(
                    host=self._client.host,
                    username=self._username,
                    password=self._password,
                    port=self._client.port,
                    ssl=self._client.ssl,
                    verify=self._verify,
                    idle_callback=idle_callback_wrapper,
                    idle_timeout=check_timeout,
                )
            except (timeout, IMAPClientError):
                logger.warning("IMAP connection timeout. Reconnecting...")
                sleep(check_timeout)
            except Exception as e:
                logger.warning("IMAP connection error. {0}. Reconnecting...".format(e))
                sleep(check_timeout)
            if config_reloading and config_reloading():
                return

    def send_message(self, *args: Any, **kwargs: Any) -> Optional[str]:
        raise NotImplementedError(
            "IMAP cannot send mail; use mailsuite.smtp.send_email"
        )
