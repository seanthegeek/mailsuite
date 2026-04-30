"""Microsoft Graph mailbox backend"""

from __future__ import annotations

import asyncio
import atexit
import logging
from enum import Enum
from functools import lru_cache
from pathlib import Path
from time import sleep
from typing import Any, Callable, List, Optional, Tuple, Union

from mailsuite.mailbox.base import MailboxConnection

try:
    from azure.identity import (
        AuthenticationRecord,
        CertificateCredential,
        ClientSecretCredential,
        DeviceCodeCredential,
        TokenCachePersistenceOptions,
        UsernamePasswordCredential,
    )
    from kiota_authentication_azure.azure_identity_authentication_provider import (
        AzureIdentityAuthenticationProvider,
    )
    from msgraph.graph_request_adapter import GraphRequestAdapter
    from msgraph.graph_service_client import GraphServiceClient
    from msgraph.generated.models.body_type import BodyType
    from msgraph.generated.models.email_address import EmailAddress
    from msgraph.generated.models.file_attachment import FileAttachment
    from msgraph.generated.models.item_body import ItemBody
    from msgraph.generated.models.mail_folder import MailFolder
    from msgraph.generated.models.message import Message
    from msgraph.generated.models.recipient import Recipient
    from msgraph.generated.users.item.mail_folders.item.child_folders.child_folders_request_builder import (  # noqa: E501
        ChildFoldersRequestBuilder,
    )
    from msgraph.generated.users.item.mail_folders.mail_folders_request_builder import (
        MailFoldersRequestBuilder,
    )
    from msgraph.generated.users.item.mail_folders.item.messages.messages_request_builder import (  # noqa: E501
        MessagesRequestBuilder,
    )
    from msgraph.generated.users.item.messages.item.move.move_post_request_body import (
        MovePostRequestBody,
    )
    from msgraph.generated.users.item.send_mail.send_mail_post_request_body import (
        SendMailPostRequestBody,
    )
    from msgraph_core import GraphClientFactory
except ImportError as e:
    raise ImportError(
        "MSGraphConnection requires the 'msgraph' extra: "
        "pip install mailsuite[msgraph]"
    ) from e

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    DeviceCode = 1
    UsernamePassword = 2
    ClientSecret = 3
    Certificate = 4


DEFAULT_TOKEN_CACHE_NAME = "mailsuite"


def _get_cache_args(
    token_path: Path,
    allow_unencrypted_storage: bool,
    cache_name: str = DEFAULT_TOKEN_CACHE_NAME,
) -> dict:
    cache_args: dict = {
        "cache_persistence_options": TokenCachePersistenceOptions(
            name=cache_name, allow_unencrypted_storage=allow_unencrypted_storage
        )
    }
    auth_record = _load_token(token_path)
    if auth_record:
        cache_args["authentication_record"] = AuthenticationRecord.deserialize(
            auth_record
        )
    return cache_args


def _load_token(token_path: Path) -> Optional[str]:
    if not token_path.exists():
        return None
    with token_path.open() as token_file:
        return token_file.read()


def _cache_auth_record(record: AuthenticationRecord, token_path: Path) -> None:
    token = record.serialize()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    with token_path.open("w") as token_file:
        token_file.write(token)


def _generate_credential(auth_method: str, token_path: Path, **kwargs):
    cache_name = kwargs.get("cache_name", DEFAULT_TOKEN_CACHE_NAME)
    if auth_method == AuthMethod.DeviceCode.name:
        return DeviceCodeCredential(
            client_id=kwargs["client_id"],
            disable_automatic_authentication=True,
            tenant_id=kwargs["tenant_id"],
            **_get_cache_args(
                token_path,
                allow_unencrypted_storage=kwargs["allow_unencrypted_storage"],
                cache_name=cache_name,
            ),
        )
    if auth_method == AuthMethod.UsernamePassword.name:
        return UsernamePasswordCredential(
            client_id=kwargs["client_id"],
            client_credential=kwargs["client_secret"],
            disable_automatic_authentication=True,
            username=kwargs["username"],
            password=kwargs["password"],
            **_get_cache_args(
                token_path,
                allow_unencrypted_storage=kwargs["allow_unencrypted_storage"],
                cache_name=cache_name,
            ),
        )
    if auth_method == AuthMethod.ClientSecret.name:
        return ClientSecretCredential(
            client_id=kwargs["client_id"],
            tenant_id=kwargs["tenant_id"],
            client_secret=kwargs["client_secret"],
        )
    if auth_method == AuthMethod.Certificate.name:
        cert_path = kwargs.get("certificate_path")
        if not cert_path:
            raise ValueError(
                "certificate_path is required when auth_method is 'Certificate'"
            )
        return CertificateCredential(
            client_id=kwargs["client_id"],
            tenant_id=kwargs["tenant_id"],
            certificate_path=cert_path,
            password=kwargs.get("certificate_password"),
        )
    raise RuntimeError(f"Auth method {auth_method} not found")


_persistent_loop: Optional[asyncio.AbstractEventLoop] = None


def _run(coro):
    """Run a coroutine to completion on a persistent event loop.

    Refuses to nest in a running loop. We retain a single persistent
    loop across calls because the Graph SDK's underlying
    ``httpx.AsyncClient`` keeps connection-pool resources bound to the
    loop that issued the first request — closing the loop between calls
    (as ``asyncio.run`` does) invalidates those resources and surfaces
    on the next call as ``RuntimeError: Event loop is closed``. See
    https://github.com/domainaware/parsedmarc/issues/742.
    """
    global _persistent_loop
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "MSGraphConnection cannot be called from inside a running event loop. "
            "Use msgraph.GraphServiceClient directly from async code."
        )

    if _persistent_loop is None or _persistent_loop.is_closed():
        _persistent_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_persistent_loop)
    return _persistent_loop.run_until_complete(coro)


@atexit.register
def _close_persistent_loop() -> None:
    global _persistent_loop
    if _persistent_loop is not None and not _persistent_loop.is_closed():
        _persistent_loop.close()
    _persistent_loop = None


class MSGraphConnection(MailboxConnection):
    """
    A :class:`MailboxConnection` backed by Microsoft Graph

    Supports DeviceCode, UsernamePassword, ClientSecret, and Certificate
    auth via :mod:`azure.identity`. Send mail goes through
    ``/users/{mailbox}/sendMail`` with a structured ``Message`` body
    (Graph automatically saves a copy to Sent Items).

    Required Microsoft Graph **API permissions** on the app registration
    (combine as needed):

    * Read-only (``fetch_message``, ``fetch_messages``): ``Mail.Read``
    * Read + modify (mark read, delete, move, create folder):
      ``Mail.ReadWrite``
    * Send mail (``send_message``): ``Mail.Send``

    Delegated flows (``DeviceCode``, ``UsernamePassword``) targeting a
    shared mailbox (i.e. ``mailbox != username``) use the ``.Shared``
    variants — ``Mail.Read.Shared``, ``Mail.ReadWrite.Shared``,
    ``Mail.Send.Shared``. App-only flows (``ClientSecret``,
    ``Certificate``) do not need the ``.Shared`` variants. See the
    README "Microsoft Graph permissions" section for the full mapping.

    Note: delegated flows always request ``Mail.ReadWrite`` at
    authenticate time, so even read-only callers must consent to at
    least ``Mail.ReadWrite``.

    Requires the ``msgraph`` extra::

        pip install mailsuite[msgraph]
    """

    _WELL_KNOWN_FOLDERS = {
        "inbox": "inbox",
        "archive": "archive",
        "drafts": "drafts",
        "sentitems": "sentitems",
        "deleteditems": "deleteditems",
        "junkemail": "junkemail",
    }

    def __init__(
        self,
        auth_method: str,
        mailbox: str,
        client_id: str,
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        tenant_id: str,
        token_file: str,
        allow_unencrypted_storage: bool,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[Union[str, bytes]] = None,
        graph_url: Optional[str] = None,
        token_cache_name: str = DEFAULT_TOKEN_CACHE_NAME,
    ):
        """
        Args:
            auth_method: One of the names in :class:`AuthMethod`
            mailbox: The mailbox UPN (e.g. ``user@example.com``)
            client_id: Application (client) ID
            client_secret: Client secret (required for ClientSecret auth)
            username: User principal name (required for UsernamePassword auth)
            password: Password (required for UsernamePassword auth)
            tenant_id: Azure AD tenant ID
            token_file: Path to the file used to persist the
                ``AuthenticationRecord`` between runs
            allow_unencrypted_storage: Pass through to
                :class:`azure.identity.TokenCachePersistenceOptions`
            certificate_path: PEM/PFX path for Certificate auth
            certificate_password: Optional password for the certificate
            graph_url: Microsoft Graph endpoint URL. Defaults to the worldwide
                cloud. Pass a sovereign cloud URL (e.g.
                ``"https://graph.microsoft.us"``) or any other Graph endpoint
                to override.
            token_cache_name: ``msal``/``azure-identity`` token cache name.
                Defaults to ``"mailsuite"``. Downstream consumers migrating
                from a previous installation can pass the old cache name
                (e.g. ``"parsedmarc"``) so existing cached
                ``AuthenticationRecord``s and tokens continue to work.
        """
        token_path = Path(token_file)
        credential = _generate_credential(
            auth_method,
            client_id=client_id,
            client_secret=client_secret,
            certificate_path=certificate_path,
            certificate_password=certificate_password,
            username=username,
            password=password,
            tenant_id=tenant_id,
            token_path=token_path,
            allow_unencrypted_storage=allow_unencrypted_storage,
            cache_name=token_cache_name,
        )

        scopes: Optional[List[str]] = None
        if not isinstance(credential, (ClientSecretCredential, CertificateCredential)):
            scopes = ["Mail.ReadWrite"]
            # Detect if mailbox is shared
            if mailbox and username and username != mailbox:
                scopes = ["Mail.ReadWrite.Shared"]
            auth_record = credential.authenticate(scopes=scopes)
            _cache_auth_record(auth_record, token_path)

        if graph_url is None:
            self._client = GraphServiceClient(credentials=credential, scopes=scopes)
        else:
            httpx_client = GraphClientFactory.create_with_default_middleware()
            httpx_client.base_url = f"{graph_url.rstrip('/')}/v1.0"
            auth_provider = AzureIdentityAuthenticationProvider(
                credentials=credential, scopes=scopes or []
            )
            adapter = GraphRequestAdapter(
                auth_provider=auth_provider, client=httpx_client
            )
            self._client = GraphServiceClient(request_adapter=adapter)
        self.mailbox_name = mailbox

    # — folder management —

    def create_folder(self, folder_name: str) -> None:
        path_parts = folder_name.split("/")
        parent_folder_id: Optional[str] = None
        if len(path_parts) > 1:
            for folder in path_parts[:-1]:
                parent_folder_id = self._find_folder_id_with_parent(
                    folder, parent_folder_id
                )
            folder_name = path_parts[-1]

        body = MailFolder(display_name=folder_name)
        try:
            if parent_folder_id is None:
                _run(
                    self._client.users.by_user_id(
                        self.mailbox_name
                    ).mail_folders.post(body)
                )
            else:
                _run(
                    self._client.users.by_user_id(self.mailbox_name)
                    .mail_folders.by_mail_folder_id(parent_folder_id)
                    .child_folders.post(body)
                )
            logger.debug("Created folder %s", folder_name)
        except Exception as e:
            if getattr(e, "response_status_code", None) == 409:
                logger.debug("Folder %s already exists, skipping", folder_name)
                return
            raise

    # — message reading —

    def fetch_messages(self, reports_folder: str, **kwargs: Any) -> List[str]:
        folder_id = self._find_folder_id_from_folder_path(reports_folder)
        since = kwargs.get("since") or None
        batch_size = kwargs.get("batch_size") or 0
        return _run(self._fetch_messages_async(folder_id, batch_size, since))

    async def _fetch_messages_async(
        self, folder_id: str, batch_size: int, since: Optional[str]
    ) -> List[str]:
        query = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
            select=["id"],
            top=batch_size if batch_size > 0 else 100,
        )
        if since:
            query.filter = f"receivedDateTime ge {since}"
        config = (
            MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
                query_parameters=query
            )
        )
        page = (
            await self._client.users.by_user_id(self.mailbox_name)
            .mail_folders.by_mail_folder_id(folder_id)
            .messages.get(request_configuration=config)
        )
        ids: List[str] = []
        while page is not None and page.value:
            ids.extend(m.id for m in page.value if m.id)
            next_link = page.odata_next_link
            keep_going = since is not None or batch_size == 0 or len(ids) < batch_size
            if not next_link or not keep_going:
                break
            page = (
                await self._client.users.by_user_id(self.mailbox_name)
                .mail_folders.by_mail_folder_id(folder_id)
                .messages.with_url(next_link)
                .get()
            )
        return ids

    def fetch_message(self, message_id: Any, **kwargs: Any) -> str:
        raw = _run(
            self._client.users.by_user_id(self.mailbox_name)
            .messages.by_message_id(str(message_id))
            .content.get()
        )
        if kwargs.get("mark_read"):
            self.mark_message_read(str(message_id))
        if raw is None:
            return ""
        return bytes(raw).decode("utf-8", errors="replace")

    def mark_message_read(self, message_id: str) -> None:
        _run(
            self._client.users.by_user_id(self.mailbox_name)
            .messages.by_message_id(message_id)
            .patch(Message(is_read=True))
        )

    def delete_message(self, message_id: Any) -> None:
        _run(
            self._client.users.by_user_id(self.mailbox_name)
            .messages.by_message_id(str(message_id))
            .delete()
        )

    def move_message(self, message_id: Any, folder_name: str) -> None:
        folder_id = self._find_folder_id_from_folder_path(folder_name)
        body = MovePostRequestBody(destination_id=folder_id)
        _run(
            self._client.users.by_user_id(self.mailbox_name)
            .messages.by_message_id(str(message_id))
            .move.post(body)
        )

    def keepalive(self) -> None:
        # Graph uses bearer tokens; nothing to ping
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

    # — sending —

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
        # Graph derives ``From`` from the authenticated mailbox; ``message_from``
        # and ``message_headers`` are accepted for API parity but not used by
        # the structured /sendMail endpoint.
        del message_from, message_headers

        if html_message is not None:
            body = ItemBody(content_type=BodyType.Html, content=html_message)
        else:
            body = ItemBody(content_type=BodyType.Text, content=plain_message or "")

        def _to_recipients(addrs: Optional[List[str]]) -> Optional[List[Recipient]]:
            if not addrs:
                return None
            return [
                Recipient(email_address=EmailAddress(address=addr)) for addr in addrs
            ]

        graph_attachments: Optional[List[Any]] = None
        if attachments:
            graph_attachments = [
                FileAttachment(
                    odata_type="#microsoft.graph.fileAttachment",
                    name=filename,
                    content_bytes=payload,
                )
                for filename, payload in attachments
            ]

        message = Message(
            subject=subject,
            body=body,
            to_recipients=_to_recipients(message_to),
            cc_recipients=_to_recipients(message_cc),
            bcc_recipients=_to_recipients(message_bcc),
            attachments=graph_attachments,
        )
        request = SendMailPostRequestBody(message=message, save_to_sent_items=True)
        _run(
            self._client.users.by_user_id(self.mailbox_name).send_mail.post(request)
        )
        return None

    # — folder ID resolution —

    @lru_cache(maxsize=10)
    def _find_folder_id_from_folder_path(self, folder_name: str) -> str:
        path_parts = folder_name.split("/")
        parent_folder_id: Optional[str] = None
        if len(path_parts) > 1:
            for folder in path_parts[:-1]:
                parent_folder_id = self._find_folder_id_with_parent(
                    folder, parent_folder_id
                )
            return self._find_folder_id_with_parent(path_parts[-1], parent_folder_id)
        return self._find_folder_id_with_parent(folder_name, None)

    def _get_well_known_folder_id(self, folder_name: str) -> Optional[str]:
        folder_key = folder_name.lower().replace(" ", "").replace("-", "")
        alias = self._WELL_KNOWN_FOLDERS.get(folder_key)
        if alias is None:
            return None
        try:
            folder = _run(
                self._client.users.by_user_id(self.mailbox_name)
                .mail_folders.by_mail_folder_id(alias)
                .get()
            )
        except Exception:
            return None
        return folder.id if folder else None

    def _find_folder_id_with_parent(
        self, folder_name: str, parent_folder_id: Optional[str]
    ) -> str:
        try:
            folders = self._list_folders_filtered(folder_name, parent_folder_id)
        except Exception as e:
            if parent_folder_id is None:
                well_known = self._get_well_known_folder_id(folder_name)
                if well_known:
                    return well_known
            raise RuntimeError(f"Failed to list folders: {e}") from e

        for folder in folders:
            if folder.display_name == folder_name and folder.id:
                return folder.id

        if parent_folder_id is None:
            well_known = self._get_well_known_folder_id(folder_name)
            if well_known:
                return well_known
        raise RuntimeError(f"folder {folder_name} not found")

    def _list_folders_filtered(
        self, folder_name: str, parent_folder_id: Optional[str]
    ) -> List[MailFolder]:
        # OData string-literal escape: single quotes are doubled.
        escaped = folder_name.replace("'", "''")
        if parent_folder_id is None:
            query = MailFoldersRequestBuilder.MailFoldersRequestBuilderGetQueryParameters(
                filter=f"displayName eq '{escaped}'"
            )
            config = MailFoldersRequestBuilder.MailFoldersRequestBuilderGetRequestConfiguration(
                query_parameters=query
            )
            page = _run(
                self._client.users.by_user_id(
                    self.mailbox_name
                ).mail_folders.get(request_configuration=config)
            )
        else:
            child_query = ChildFoldersRequestBuilder.ChildFoldersRequestBuilderGetQueryParameters(
                filter=f"displayName eq '{escaped}'"
            )
            child_config = ChildFoldersRequestBuilder.ChildFoldersRequestBuilderGetRequestConfiguration(
                query_parameters=child_query
            )
            page = _run(
                self._client.users.by_user_id(self.mailbox_name)
                .mail_folders.by_mail_folder_id(parent_folder_id)
                .child_folders.get(request_configuration=child_config)
            )
        return list(page.value or []) if page is not None else []
