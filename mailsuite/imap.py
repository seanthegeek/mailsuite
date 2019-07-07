import imapclient
import imapclient.exceptions


class IMAPError(RuntimeError):
    """Raised when an IMAP error occurs"""

