import email.utils
import logging
import socket
import smtplib
from ssl import SSLError, CertificateError, create_default_context, CERT_NONE
from typing import Callable, Optional, Tuple, cast

from mailsuite.utils import create_email
from mailsuite.dkim import sign_email as _dkim_sign_email

logger = logging.getLogger(__name__)


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


def _xoauth2_auth_string(
    username: str, token: str, vendor: Optional[str] = None
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
    message_to: Optional[list[str]] = None,
    message_cc: Optional[list] = None,
    message_bcc: Optional[list] = None,
    port: int = 0,
    require_encryption: bool = False,
    verify: bool = True,
    username: Optional[str] = None,
    password: Optional[str] = None,
    oauth2_token: Optional[str] = None,
    oauth2_token_provider: Optional[Callable[[], str]] = None,
    oauth2_mechanism: str = "XOAUTH2",
    oauth2_vendor: Optional[str] = None,
    envelope_from: Optional[str] = None,
    subject: Optional[str] = None,
    message_headers: Optional[dict] = None,
    attachments: Optional[list[Tuple[str, bytes]]] = None,
    plain_message: Optional[str] = None,
    html_message: Optional[str] = None,
    dkim_private_key: Optional[str] = None,
    dkim_selector: Optional[str] = None,
    dkim_domain: Optional[str] = None,
    dkim_additional_headers: Optional[list[str]] = None,
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
    """

    using_oauth = oauth2_token is not None or oauth2_token_provider is not None
    if using_oauth and not username:
        raise ValueError("username is required when authenticating with OAuth2")

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
        if require_encryption:
            server = smtplib.SMTP_SSL(host, port=port, context=ssl_context)
            server.connect(host, port)
            server.ehlo_or_helo_if_needed()
        else:
            server = smtplib.SMTP(host, port=port)
            server.connect(host, port)
            server.ehlo_or_helo_if_needed()
            if server.has_extn("starttls"):
                server.starttls(context=ssl_context)
                server.ehlo()
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
        elif username and password:
            server.login(username, password)
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
        raise SMTPError("Certificate error: {0}".format(error.__str__()))
    except SSLError as error:
        raise SMTPError("SSL error: {0}".format(error.__str__()))
