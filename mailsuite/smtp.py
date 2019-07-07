import logging
from datetime import datetime
import email
import socket
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils
import smtplib
from ssl import SSLError, CertificateError, create_default_context

logger = logging.getLogger("mailsuite.smtp")


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


def email_results(results, host, mail_from, mail_to, port=0,
                  ssl=False, user=None, password=None, subject=None,
                  attachments=None, message=None,
                  ssl_context=None):
    """
    Emails parsing results as a zip file

    Args:
        results (OrderedDict): Parsing results
        host: Mail server hostname or IP address
        mail_from: The value of the message from header
        mail_to : A list of addresses to mail to
        port (int): Port to use
        ssl (bool): Require a SSL connection from the start
        user: An optional username
        password: An optional password
        subject: Overrides the default message subject
        attachments (list): A list of tuples, containing filenames ans bytes
        message: The plain text message body
        ssl_context: SSL context options
    """
    logging.debug("Emailing report to: {0}".format(",".join(mail_to)))
    date_string = datetime.now().strftime("%Y-%m-%d")

    assert isinstance(mail_to, list)

    msg = MIMEMultipart()
    msg['From'] = mail_from
    msg['To'] = ", ".join(mail_to)
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Subject'] = subject or "DMARC results for {0}".format(date_string)
    text = message or "Please see the attached zip file\n"

    msg.attach(MIMEText(text))

    zip_bytes = get_report_zip(results)
    part = MIMEApplication(zip_bytes, Name=filename)

    part['Content-Disposition'] = 'attachment; filename="{0}"'.format(filename)
    msg.attach(part)

    try:
        if ssl_context is None:
            ssl_context = create_default_context()
        if ssl:
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
        if user and password:
            server.login(user, password)
        server.sendmail(mail_from, mail_to, msg.as_string())
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