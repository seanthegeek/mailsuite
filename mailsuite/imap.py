import logging
import imapclient
import imapclient.exceptions

from wrapt_timeout_decorator import *

logger = logging.getLogger("mailsuite.imap")


def _chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


class IMAPError(RuntimeError):
    """Raised when an IMAP error occurs"""


class IMAPClient(imapclient.IMAPClient):
    """A simplified IMAP client"""
    def __init__(self, host, port, username, password, ssl=True,
                 ssl_context=None, initial_folder="INBOX",
                 fetch_timeout=5, action_timeout=2, max_attempts=2):
        imapclient.IMAPClient.__init__(self,
                                       host=host,
                                       port=port,
                                       ssl=ssl,
                                       ssl_context=ssl_context,
                                       use_uid=True)
        self.login(username, password)
        self.server_capabilities = self.capabilities()
        self._move_supported = "MOVE" in self.server_capabilities
        self.select_folder(initial_folder)
