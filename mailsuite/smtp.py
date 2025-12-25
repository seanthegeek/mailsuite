import logging
import socket
import smtplib
from ssl import SSLError, CertificateError, create_default_context, CERT_NONE
from typing import Tuple, Optional

from mailsuite.utils import create_email

logger = logging.getLogger(__name__)


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


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
    envelope_from: Optional[str] = None,
    subject: Optional[str] = None,
    message_headers: Optional[dict] = None,
    attachments: Optional[list[Tuple[str, bytes]]] = None,
    plain_message: Optional[str] = None,
    html_message: Optional[str] = None,
):
    """
    Send an email using a SMTP relay

    Args:
        host: Mail server hostname or IP address
        message_from: The value of the message from header
        message_to: A list of addresses to send mail to
        message_cc: A List of addresses to Carbon Copy (CC)
        message_bcc:  A list of addresses to Blind Carbon Copy (BCC)
        port: Port to use
        require_encryption: Require a SSL/TLS connection from the start
        verify: Verify the SSL/TLS certificate
        username: An optional username
        password: An optional password
        envelope_from: Overrides the SMTP envelope "mail from" header
        subject: The message subject
        message_headers: Custom message headers
        attachments: A list of tuples, containing filenames and bytes
        plain_message: The plain text message body
        html_message: The HTML message body
    """

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
        if username and password:
            server.login(username, password)
        if envelope_from is None:
            envelope_from = message_from
        if message_to is None and message_to is None:
            raise ValueError("message_to and envelope_to cannot both be None")
        envelope_to = message_to.copy()
        if message_cc is not None:
            message_to += message_cc
        if message_bcc is not None:
            message_to += message_bcc
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
