"""Gmail mailbox backend"""

from __future__ import annotations

import base64
import logging
from functools import lru_cache
from pathlib import Path
from time import sleep
from typing import Any, Callable, List, Optional, Tuple

from mailsuite.mailbox.base import MailboxConnection
from mailsuite.utils import create_email

try:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError as e:
    raise ImportError(
        "GmailConnection requires the 'gmail' extra: pip install mailsuite[gmail]"
    ) from e

logger = logging.getLogger(__name__)


def _get_creds(
    token_file: str,
    credentials_file: str,
    scopes: List[str],
    oauth2_port: int,
    auth_mode: str = "installed_app",
    service_account_user: Optional[str] = None,
):
    normalized_auth_mode = (auth_mode or "installed_app").strip().lower()
    if normalized_auth_mode == "service_account":
        creds = service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=scopes,
        )
        if service_account_user:
            creds = creds.with_subject(service_account_user)
        return creds
    if normalized_auth_mode != "installed_app":
        raise ValueError(
            f"Unsupported Gmail auth_mode '{auth_mode}'. "
            "Expected 'installed_app' or 'service_account'."
        )

    creds = None
    if Path(token_file).exists():
        creds = Credentials.from_authorized_user_file(token_file, scopes)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
            creds = flow.run_local_server(open_browser=False, oauth2_port=oauth2_port)
        Path(token_file).parent.mkdir(parents=True, exist_ok=True)
        with Path(token_file).open("w") as token:
            token.write(creds.to_json())
    return creds


class GmailConnection(MailboxConnection):
    """
    A :class:`MailboxConnection` backed by the Gmail API

    Sends mail through ``users.messages.send`` with the message built by
    :func:`mailsuite.utils.create_email`. Sending requires a scope that
    includes the send permission (``gmail.send``,
    ``gmail.modify``, or full ``mail.google.com``).

    Requires the ``gmail`` extra::

        pip install mailsuite[gmail]
    """

    def __init__(
        self,
        token_file: str,
        credentials_file: str,
        scopes: List[str],
        include_spam_trash: bool,
        reports_folder: str,
        oauth2_port: int,
        paginate_messages: bool,
        auth_mode: str = "installed_app",
        service_account_user: Optional[str] = None,
    ):
        creds = _get_creds(
            token_file,
            credentials_file,
            scopes,
            oauth2_port,
            auth_mode=auth_mode,
            service_account_user=service_account_user,
        )
        self.service = build("gmail", "v1", credentials=creds)
        self.include_spam_trash = include_spam_trash
        self.reports_label_id = self._find_label_id_for_label(reports_folder)
        self.paginate_messages = paginate_messages

    def create_folder(self, folder_name: str) -> None:
        # Gmail uses labels; "Archive" isn't a real Gmail concept
        if folder_name == "Archive":
            return

        logger.debug("Creating label %s", folder_name)
        request_body = {"name": folder_name, "messageListVisibility": "show"}
        try:
            self.service.users().labels().create(
                userId="me", body=request_body
            ).execute()
        except HttpError as e:
            if e.status_code == 409:
                logger.debug("Folder %s already exists, skipping creation", folder_name)
            else:
                raise

    def _fetch_all_message_ids(
        self,
        reports_label_id: str,
        page_token: Optional[str] = None,
        since: Optional[str] = None,
    ):
        if since:
            results = (
                self.service.users()
                .messages()
                .list(
                    userId="me",
                    includeSpamTrash=self.include_spam_trash,
                    labelIds=[reports_label_id],
                    pageToken=page_token,
                    q=f"after:{since}",
                )
                .execute()
            )
        else:
            results = (
                self.service.users()
                .messages()
                .list(
                    userId="me",
                    includeSpamTrash=self.include_spam_trash,
                    labelIds=[reports_label_id],
                    pageToken=page_token,
                )
                .execute()
            )
        for message in results.get("messages", []):
            yield message["id"]

        if "nextPageToken" in results and self.paginate_messages:
            yield from self._fetch_all_message_ids(
                reports_label_id, results["nextPageToken"]
            )

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> List[str]:
        reports_label_id = self._find_label_id_for_label(reports_folder)
        since = kwargs.get("since")
        if since:
            return list(self._fetch_all_message_ids(reports_label_id, since=since))
        return list(self._fetch_all_message_ids(reports_label_id))

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        msg = (
            self.service.users()
            .messages()
            .get(userId="me", id=message_id, format="raw")
            .execute()
        )
        return base64.urlsafe_b64decode(msg["raw"]).decode(errors="replace")

    def delete_message(self, message_id: Any) -> None:
        self.service.users().messages().delete(userId="me", id=message_id).execute()

    def move_message(self, message_id: Any, folder_name: str) -> None:
        label_id = self._find_label_id_for_label(folder_name)
        logger.debug("Moving message UID %s to %s", message_id, folder_name)
        request_body = {
            "addLabelIds": [label_id],
            "removeLabelIds": [self.reports_label_id],
        }
        self.service.users().messages().modify(
            userId="me", id=message_id, body=request_body
        ).execute()

    def keepalive(self) -> None:
        return

    def watch(
        self,
        check_callback: Callable[[MailboxConnection], None],
        check_timeout: int,
        config_reloading: Optional[Callable[[], bool]] = None,
    ) -> None:
        """Poll the mailbox at ``check_timeout``-second intervals"""
        while True:
            if config_reloading and config_reloading():
                return
            sleep(check_timeout)
            if config_reloading and config_reloading():
                return
            check_callback(self)

    def send_message(
        self,
        message_from: str,
        message_to: Optional[List[str]] = None,
        message_cc: Optional[List[str]] = None,
        message_bcc: Optional[List[str]] = None,
        subject: Optional[str] = None,
        message_headers: Optional[dict] = None,
        attachments: Optional[List[Tuple[str, bytes]]] = None,
        plain_message: Optional[str] = None,
        html_message: Optional[str] = None,
    ) -> Optional[str]:
        raw = create_email(
            message_from=message_from,
            message_to=message_to,
            message_cc=message_cc,
            subject=subject,
            message_headers=message_headers,
            attachments=attachments,
            plain_message=plain_message,
            html_message=html_message,
        )
        encoded = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
        body: dict = {"raw": encoded}
        sent = (
            self.service.users()
            .messages()
            .send(userId="me", body=body)
            .execute()
        )
        return sent.get("id")

    @lru_cache(maxsize=10)
    def _find_label_id_for_label(self, label_name: str) -> str:
        results = self.service.users().labels().list(userId="me").execute()
        for label in results.get("labels", []):
            if label_name == label["id"] or label_name == label["name"]:
                return label["id"]
        return ""
