import logging
import email
import socket
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils
import smtplib
from ssl import SSLError, CertificateError, create_default_context, CERT_NONE

logger = logging.getLogger(__name__)


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


def send_email(host, message_from, message_to=None, message_cc=None,
               message_bcc=None, port=0, require_encryption=False,
               verify=True, username=None, password=None, envelope_from=None,
               subject=None, attachments=None, plain_message=None,
               html_message=None):
    """
    ESend an email using a SMTP relay

    Args:
        host (str): Mail server hostname or IP address
        message_from (str): The value of the message from header
        message_to (list): A list of addresses to send mail to
        message_cc (list): A List of addresses to Carbon Copy (CC)
        message_bcc (list:  A list of addresses to Blind Carbon Copy (BCC)
        port (int): Port to use
        require_encryption (bool): Require a SSL/TLS connection from the start
        verify (bool): Verify the SSL/TLS certificate
        username (str): An optional username
        password (str): An optional password
        envelope_from (str): Overrides the SMTP envelope "mail from" header
        subject (str): The message subject
        attachments (list): A list of tuples, containing filenames as bytes
        plain_message (str): The plain text message body
        html_message (str): The HTML message body
    """
    msg = MIMEMultipart()
    msg['From'] = message_from
    msg['To'] = ", ".join(message_to)
    if message_cc is not None:
        msg['Cc'] = ", ".join(message_cc)
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(plain_message, "plain"))
    if html_message is not None:
        msg.attach(MIMEText(plain_message, "html"))

    for attachment in attachments:
        filename = attachment[0]
        payload = attachment[1]
        part = MIMEApplication(payload, Name=filename)
        content_disposition = 'attachment; filename="{0}"'.format(filename)
        part['Content-Disposition'] = content_disposition
        msg.attach(part)

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
                logger.warning("SMTP server does not support STARTTLS. "
                               "Proceeding in plain text!")
        if username and password:
            server.login(username, password)
        if envelope_from is None:
            envelope_from = message_from
        envelope_to = message_to.copy()
        if message_cc is not None:
            message_to += message_cc
        if message_bcc is not None:
            message_to += message_bcc
        envelope_to = list(set(envelope_to))
        server.sendmail(envelope_from, envelope_to, msg.as_string())
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
    except SSLError as error:
        raise SMTPError("SSL error: {0}".format(error.__str__()))
    except CertificateError as error:
        raise SMTPError("Certificate error: {0}".format(error.__str__()))
