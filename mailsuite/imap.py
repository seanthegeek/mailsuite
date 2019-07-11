import logging
import socket
import imapclient
import imapclient.exceptions
from ssl import CERT_NONE, SSLError, CertificateError, create_default_context

from wrapt_timeout_decorator import *

import mailsuite.utils

logger = logging.getLogger("mailsuite.imap")


def _chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


class _IMAPTimeout(Exception):
    """Raised when an IMAP action times out"""


class IMAPClient(imapclient.IMAPClient):
    """A simplified IMAP client"""
    fetch_timeout = 10
    action_timeout = 2

    def __init__(self, host, username, password, port=None, ssl=True,
                 verify=True, initial_folder="INBOX",
                 idle_callback=None, max_attempts=3):

        ssl_context = create_default_context()
        if verify is False:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = CERT_NONE
        self._init_args = dict(host=host, username=username,
                               password=password, port=port, ssl=True,
                               verify=verify,
                               initial_folder="INBOX",
                               idle_callback=idle_callback,
                               max_attempts=max_attempts)
        self.idle_callback = idle_callback
        self.max_attempts = max_attempts
        if not ssl:
            logger.debug("Connecting to IMAP over plain text")
        imapclient.IMAPClient.__init__(self,
                                       host=host,
                                       port=port,
                                       ssl=ssl,
                                       ssl_context=ssl_context,
                                       use_uid=True)
        try:
            self.login(username, password)
            self.server_capabilities = self.capabilities()
            self._move_supported = "MOVE" in self.server_capabilities
            self._idle_supported = "IDLE" in self.server_capabilities
            self.select_folder(initial_folder)

        except (ConnectionResetError, socket.error,
                TimeoutError,
                imapclient.exceptions.IMAPClientError) as error:
            error = error.__str__().lstrip("b'").rstrip("'").rstrip(
                ".")
            raise imapclient.exceptions.IMAPClientError(error)
        except ConnectionAbortedError:
            raise imapclient.exceptions.IMAPClientError("Connection aborted")
        except TimeoutError:
            raise imapclient.exceptions.IMAPClientError("Connection timed out")
        except SSLError as error:
            raise imapclient.exceptions.IMAPClientError(
                "SSL error: {0}".format(error.__str__()))
        except CertificateError as error:
            raise imapclient.exceptions.IMAPClientError(
                "Certificate error: {0}".format(error.__str__()))
        except BrokenPipeError:
            raise imapclient.exceptions.IMAPClientError("Broken pipe")

    def reset_connection(self):
        logger.debug("Reconnecting to IMAP")
        try:
            self.shutdown()
        except Exception as e:
            logger.debug(
                "Failed to log out: {0}".format(e.__str__()))
        self.__init__(self._init_args["host"],
                      self._init_args["username"],
                      self._init_args["password"],
                      port=self._init_args["port"],
                      ssl=self._init_args["ssl"],
                      verify=self._init_args["verify"],
                      initial_folder=self._init_args["initial_folder"],
                      idle_callback=self._init_args["idle_callback"],
                      max_attempts=self._init_args["max_attempts"]
                      )

    @timeout(fetch_timeout, timeout_exception=_IMAPTimeout)
    def fetch_message(self, msg_uid, attempt=1, parse=False):
        logger.debug("Fetching message UID {0} attempt {1} of {2}".format(
            msg_uid, attempt, self.max_attempts))
        try:
            raw_msg = self.fetch(msg_uid, ["RFC822"])[msg_uid]
            msg_keys = [b'RFC822', b'BODY[NULL]', b'BODY[]']
            msg_key = ''
            for key in msg_keys:
                if key in raw_msg.keys():
                    msg_key = key
                    break
            message =  raw_msg[msg_key]
            if parse:
                message = mailsuite.utils.parse_email(message)
            return message
        except (ConnectionResetError, socket.error,
                TimeoutError, BrokenPipeError) as error:
            error = error.__str__().lstrip("b'").rstrip("'").rstrip(
                ".")
            logger.debug("IMAP error: {0}".format(error.__str__()))
            if attempt <= self.max_attempts:
                attempt = attempt + 1
                self.reset_connection()
                return self.fetch_message(msg_uid, attempt=attempt,
                                          parse=parse)
        except _IMAPTimeout:
            if attempt <= self.max_attempts:
                attempt = attempt + 1
                return self.fetch_message(msg_uid, attempt=attempt,
                                          parse=parse)
            else:
                raise imapclient.exceptions.IMAPClientError(
                    "MAx fetch attempts reached"
                )

    @timeout(action_timeout, timeout_exception=_IMAPTimeout)
    def delete_messages(self, msg_uids, silent=True, attempt=1):
        logger.debug("Deleting message UID(s) {0}".format(",".join(
            str(uid) for uid in msg_uids)))
        if type(msg_uids) == str or type(msg_uids) == int:
            msg_uids = [int(msg_uids)]
        try:
            imapclient.IMAPClient.delete_messages(self, msg_uids,
                                                  silent=silent)
            imapclient.IMAPClient.expunge(self, msg_uids)
        except (ConnectionResetError, socket.error,
                TimeoutError, BrokenPipeError) as error:
            error = error.__str__().lstrip("b'").rstrip("'").rstrip(
                ".")
            logger.debug("IMAP error: {0}".format(error.__str__()))
            if attempt <= self.max_attempts:
                attempt = attempt + 1
                self.reset_connection()
                return self.delete_messages(msg_uids, silent=silent,
                                            attempt=attempt)
        except _IMAPTimeout:
            return

    def create_folder(self, folder_path):
        folder_path = folder_path.replace("\\", "/").strip("/")
        if not self.folder_exists(folder_path):
            logger.debug("Creating folder: {0}".format(folder_path))
        try:
            imapclient.IMAPClient.create_folder(self, folder_path)
        except imapclient.exceptions.IMAPClientError:
            # Try replacing / with . (Required by the devcot server
            folder_path = folder_path.replace("/", ".")
            self.create_folder(folder_path)

    @timeout(action_timeout, timeout_exception=_IMAPTimeout)
    def move_messages(self, msg_uids, folder_path):
        folder_path = folder_path.replace("\\", "/").strip("/")
        if type(msg_uids) == str or type(msg_uids) == int:
            msg_uids = [int(msg_uids)]
        for chunk in _chunks(msg_uids, 100):
            if self._move_supported:
                logger.debug("Moving message UID(s) {0} to {1}".format(
                    ",".join(str(uid) for uid in chunk), folder_path
                ))
                try:
                    self.move(chunk, folder_path)
                except _IMAPTimeout:
                    return
                except imapclient.exceptions.IMAPClientError as e:
                    e = e.__str__().lstrip("b'").rstrip(
                        "'").rstrip(".")
                    message = "Error moving message UIDs"
                    e = "{0} {1}: " "{2}".format(message, msg_uids, e)
                    logger.debug("IMAP error: {0}".format(e))
                    logger.debug(
                        "Copying message UID(s) {0} to {1}".format(
                            ",".join(str(uid) for uid in chunk), folder_path
                        ))
                    try:
                        self.copy(msg_uids, folder_path)
                        self.delete_messages(msg_uids)
                    except _IMAPTimeout:
                        return
            else:
                logger.debug("Copying message UID(s) {0} to {1}".format(
                    ",".join(str(uid) for uid in chunk), folder_path
                ))
                try:
                    self.copy(msg_uids, folder_path)
                    self.delete_messages(msg_uids)
                except _IMAPTimeout:
                    return
