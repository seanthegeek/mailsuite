import email.utils
import logging
import smtplib
import socket
from collections.abc import Callable
from ssl import CERT_NONE, CertificateError, SSLError, create_default_context
from typing import cast

from mailsuite.dkim import sign_email as _dkim_sign_email
from mailsuite.utils import create_email

logger = logging.getLogger(__name__)


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


def _xoauth2_auth_string(
    username: str, token: str, vendor: str | None = None
) -> str:
    """Build the SASL ``XOAUTH2`` initial-response string.

    Gmail and Microsoft 365 accept the base form; Yahoo additionally
    requires the ``vendor`` portion.
    """
    auth_string = f"user={username}\x01auth=Bearer {token}\x01"
    if vendor:
        auth_string += f"vendor={vendor}\x01"
    auth_string += "\x01"
    return auth_string


def _oauthbearer_auth_string(username: str, token: str) -> str:
    """Build the SASL ``OAUTHBEARER`` initial-response string (RFC 7628)."""
    identity = username.replace("=", "=3D").replace(",", "=2C")
    return f"n,a={identity},\x01auth=Bearer {token}\x01\x01"


def send_email(
    host: str,
    message_from: str,
    message_to: list[str] | None = None,
    message_cc: list | None = None,
    message_bcc: list | None = None,
    port: int = 0,
    require_encryption: bool = False,
    verify: bool = True,
    username: str | None = None,
    password: str | None = None,
    oauth2_token: str | None = None,
    oauth2_token_provider: Callable[[], str] | None = None,
    oauth2_mechanism: str = "XOAUTH2",
    oauth2_vendor: str | None = None,
    envelope_from: str | None = None,
    subject: str | None = None,
    message_headers: dict | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
    plain_message: str | None = None,
    html_message: str | None = None,
    dkim_private_key: str | None = None,
    dkim_selector: str | None = None,
    dkim_domain: str | None = None,
    dkim_additional_headers: list[str] | None = None,
    starttls: bool | None = None,
):
    """
    Send an email using a SMTP relay

    Args:
        host: Mail server hostname or IP address
        message_from: The value of the message "From" header
        message_to: A list of addresses to send mail to
        message_cc: A list of addresses to Carbon Copy (CC)
        message_bcc: A list of addresses to Blind Carbon Copy (BCC)
        port: Port to use
        require_encryption: Require a SSL/TLS connection from the start
        verify: Verify the SSL/TLS certificate
        username: An optional username
        password: An optional password (omit when using OAuth2)
        oauth2_token: A static OAuth2 access token. Provide this (or
            ``oauth2_token_provider``) together with ``username`` to
            authenticate with OAuth2 instead of a password.
        oauth2_token_provider: A zero-arg callable returning a current
            OAuth2 access token, invoked at send time so a fresh token is
            used. Takes precedence over ``oauth2_token``.
        oauth2_mechanism: ``"XOAUTH2"`` (default — Gmail / Microsoft 365 /
            Yahoo) or ``"OAUTHBEARER"`` (Gmail's standards-track variant)
        oauth2_vendor: Optional vendor string required by Yahoo's XOAUTH2
            implementation (XOAUTH2 only)
        envelope_from: Overrides the SMTP envelope "mail from" header
        subject: The message subject
        message_headers: Custom message headers
        attachments: A list of tuples, containing filenames and bytes
        plain_message: The plain text message body
        html_message: The HTML message body
        dkim_private_key: A PEM-encoded RSA private key. When provided
            (along with ``dkim_selector`` and ``dkim_domain``), the message
            is DKIM-signed before sending.
        dkim_selector: The DKIM selector to use when signing
        dkim_domain: The DKIM signing domain (defaults to the domain of
            ``message_from`` when ``dkim_private_key`` is set but
            ``dkim_domain`` is not)
        dkim_additional_headers: Additional header names to include in the
            DKIM signature. Headers not present in the message are skipped.
        starttls: Whether to upgrade a plain-text
            (``require_encryption=False``) connection with STARTTLS.
            ``None`` (default) upgrades when the server advertises
            STARTTLS. When it does not, ``None`` raises
            :class:`SMTPError` before authenticating if credentials
            (``username`` and ``password``, or an OAuth2 token or token
            provider) were given, so they are never sent in plain text;
            without credentials the message is sent in plain text and a
            warning is logged. ``False`` never upgrades, so
            the connection stays plain text even when STARTTLS is
            advertised, and any credentials are sent unencrypted (a warning
            is logged when they are). ``True`` requires the upgrade and
            raises :class:`SMTPError` if the server does not advertise
            STARTTLS. Ignored when ``require_encryption=True``, because the
            connection is already TLS.
    """

    using_oauth = oauth2_token is not None or oauth2_token_provider is not None
    if using_oauth and not username:
        raise ValueError("username is required when authenticating with OAuth2")
    using_password = not using_oauth and bool(username and password)
    # Computed once so the plain-text guard below and the login dispatch can
    # never disagree about whether credentials are about to be sent.
    authenticating = using_oauth or using_password

    msg = create_email(
        message_from=message_from,
        message_to=message_to,
        message_cc=message_cc,
        subject=subject,
        message_headers=message_headers,
        attachments=attachments,
        plain_message=plain_message,
        html_message=html_message,
    )

    if dkim_private_key:
        if not dkim_selector:
            raise ValueError("dkim_selector is required when dkim_private_key is set")
        if not dkim_domain:
            from_addr = email.utils.parseaddr(message_from)[1]
            if "@" not in from_addr:
                raise ValueError(
                    "Could not infer dkim_domain from message_from; pass dkim_domain explicitly"
                )
            dkim_domain = from_addr.rsplit("@", 1)[-1]
        msg = _dkim_sign_email(
            msg,
            selector=dkim_selector,
            domain=dkim_domain,
            private_key=dkim_private_key,
            additional_headers=dkim_additional_headers,
        )

    try:
        ssl_context = create_default_context()
        if verify is False:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = CERT_NONE
        # smtplib's constructors connect when given a host, so no explicit
        # connect() call is needed (one would open and leak a second socket).
        if require_encryption:
            server = smtplib.SMTP_SSL(host, port=port, context=ssl_context)
            server.ehlo_or_helo_if_needed()
        else:
            server = smtplib.SMTP(host, port=port)
            server.ehlo_or_helo_if_needed()
            starttls_advertised = server.has_extn("starttls")
            if starttls is False:
                if starttls_advertised:
                    logger.info(
                        "SMTP server supports STARTTLS, but it is disabled"
                        " ... staying in plain text"
                    )
                if authenticating:
                    logger.warning(
                        "Sending SMTP credentials unencrypted because starttls=False"
                    )
            elif starttls_advertised:
                server.starttls(context=ssl_context)
                server.ehlo()
            elif starttls:
                raise SMTPError("STARTTLS required but not supported by the server")
            elif authenticating:
                raise SMTPError(
                    "The SMTP server does not advertise STARTTLS, so credentials"
                    " would be sent in plain text. Use require_encryption=True"
                    " for implicit TLS, or pass starttls=False to allow"
                    " plain-text authentication"
                )
            else:
                logger.warning(
                    "SMTP server does not support STARTTLS. Proceeding in plain text!"
                )
        if using_oauth:
            token = (
                oauth2_token_provider()
                if oauth2_token_provider is not None
                else cast(str, oauth2_token)
            )
            if oauth2_mechanism.upper() == "OAUTHBEARER":
                auth_string = _oauthbearer_auth_string(cast(str, username), token)
                mechanism = "OAUTHBEARER"
            else:
                auth_string = _xoauth2_auth_string(
                    cast(str, username), token, oauth2_vendor
                )
                mechanism = oauth2_mechanism.upper()
            server.auth(mechanism, lambda challenge=None: auth_string)
        elif using_password:
            server.login(cast(str, username), cast(str, password))
        if envelope_from is None:
            envelope_from = message_from
        if message_to is None:
            raise ValueError("message_to cannot be None")
        # The SMTP envelope must list every recipient — To, Cc, and Bcc — or
        # the omitted ones never receive the message. (Bcc is intentionally
        # absent from the message headers, so the envelope is its only path.)
        envelope_to = list(message_to)
        if message_cc is not None:
            envelope_to += message_cc
        if message_bcc is not None:
            envelope_to += message_bcc
        envelope_to = list(set(envelope_to))
        server.sendmail(envelope_from, envelope_to, msg)
    except smtplib.SMTPException as error:
        error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
        raise SMTPError(error)
    except socket.gaierror:
        raise SMTPError("DNS resolution failed")
    except ConnectionRefusedError:
        raise SMTPError("Connection refused")
    except ConnectionResetError:
        raise SMTPError("Connection reset")
    except ConnectionAbortedError:
        raise SMTPError("Connection aborted")
    except TimeoutError:
        raise SMTPError("Connection timed out")
    except CertificateError as error:
        raise SMTPError(f"Certificate error: {error.__str__()}")
    except SSLError as error:
        raise SMTPError(f"SSL error: {error.__str__()}")
