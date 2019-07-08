import imapclient
import imapclient.exceptions


class IMAPError(RuntimeError):
    """Raised when an IMAP error occurs"""


class IMAPClient(imapclient.IMAPClient):
    """A simplified IMAP client"""

