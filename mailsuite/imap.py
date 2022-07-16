import logging
from typing import Union, List, Dict
import time
import socket
from ssl import (CERT_NONE, SSLError, CertificateError, SSLContext,
                 create_default_context)

import imapclient
import imapclient.exceptions
import imaplib

import mailsuite.utils

logger = logging.getLogger(__name__)


class MaxRetriesExceeded(RuntimeError):
    """Raised when the maximum number of retries in exceeded"""


def _chunks(list_like_object, n: int):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(list_like_object), n):
        yield list_like_object[i:i + n]


class IMAPClient(imapclient.IMAPClient):
    """A simplified IMAP client"""

    def _normalise_folder(self, folder_name: str) -> str:
        """
        Returns an appropriate path based on the namespace (if any) and
        hierarchy separator

        Args:
            folder_name: The path to correct

        Returns:
            A corrected path
        """
        if folder_name in ["", "*", "INBOX"]:
            return imapclient.IMAPClient._normalise_folder(self, folder_name)
        folder_name = folder_name.rstrip("/")
        folder_name = folder_name.replace(self._path_prefix, "")
        if not self._hierarchy_separator == "/":
            folder_name = folder_name.replace(self._hierarchy_separator, "")
            folder_name = folder_name.replace("/", self._hierarchy_separator)
        folder_name = "{0}{1}".format(self._path_prefix, folder_name)

        return imapclient.IMAPClient._normalise_folder(self, folder_name)

    def _start_idle(self, idle_callback, idle_timeout: int = 30):
        """
        Starts an IMAP IDLE session

        Args:
            idle_callback: A callback function
            idle_timeout: Number of seconds to wait for an IDLE response
        """
        if self._idle_supported is False:
            raise imapclient.exceptions.IMAPClientError(
                "IDLE is not supported by the server")
        idle_callback(self)
        idle_start_time = time.monotonic()
        self.idle()
        while True:
            try:
                # Refresh the IDLE session every 5 minutes to stay connected
                if time.monotonic() - idle_start_time > 5 * 60:
                    logger.info("IMAP: Refreshing IDLE session")
                    self.idle_done()
                    idle_start_time = time.monotonic()
                    self.idle(self)
                responses = self.idle_check(timeout=idle_timeout)
                if responses is not None:
                    if len(responses) == 0:
                        # Gmail/G-Suite returns an empty list
                        self.idle_done()
                        idle_callback(self)
                        idle_start_time = time.monotonic()
                        self.idle()
                    else:
                        for r in responses:
                            if r[0] != 0 and r[1] == b'RECENT':
                                self.idle_done()
                                idle_callback(self)
                                idle_start_time = time.monotonic()
                                self.idle()
                                break
            except (KeyError, socket.error, BrokenPipeError,
                    ConnectionResetError):
                logger.debug("IMAP error: Connection reset")
                self.reset_connection()
            except imapclient.exceptions.IMAPClientError as error:
                error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
                # Workaround for random Exchange/Microsoft 365 IMAP errors
                if "unexpected response" in error or "BAD" in error:
                    self.reset_connection()
            except KeyboardInterrupt:
                break
        try:
            self.idle_done()
        except BrokenPipeError:
            pass

    def __init__(self, host: str, username: str, password: str,
                 port: int = None, ssl: bool = True,
                 ssl_context: SSLContext = None, verify: bool = True,
                 timeout: int = 30, max_retries: int = 4,
                 initial_folder: str = "INBOX", idle_callback=None,
                 idle_timeout: int = 30):
        """
        Connects to an IMAP server

        Args:
            host: The server hostname or IP address
            username: The username
            password: The password
            port: The port
            ssl: Use SSL or TLS
            ssl_context: For more advanced TLS options
            verify: Verify the SSL/TLS certificate
            timeout: Number of seconds to wait for an operation
            max_retries: The maximum number of retries after a timeout
            initial_folder: The initial folder to select
            idle_callback: The function to call when new messages are detected
            idle_timeout: Number of seconds to wait for an IDLE
                                  response
        """

        if ssl_context is None:
            ssl_context = create_default_context()
        if verify is False:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = CERT_NONE
        self._init_args = dict(host=host, username=username,
                               password=password, port=port, ssl=ssl,
                               ssl_context=ssl_context, verify=verify,
                               timeout=timeout,
                               max_retries=max_retries,
                               initial_folder=initial_folder,
                               idle_callback=idle_callback,
                               idle_timeout=idle_timeout)
        self.max_retries = max_retries
        self.idle_callback = idle_callback
        self.idle_timeout = idle_timeout
        self._path_prefix = ""
        self._hierarchy_separator = ""
        if not ssl:
            logger.info("Connecting to IMAP over plain text")
        imapclient.IMAPClient.__init__(self,
                                       host=host,
                                       port=port,
                                       ssl=ssl,
                                       ssl_context=ssl_context,
                                       use_uid=True,
                                       timeout=timeout)
        try:
            if not ssl and b"STARTTLS" in self.capabilities():
                logger.info("IMAP server supports STARTTLS ... activating now")
                self.starttls(ssl_context=ssl_context)
            self.login(username, password)
            self.server_capabilities = self.capabilities()
            self._move_supported = b"MOVE" in self.server_capabilities
            self._idle_supported = b"IDLE" in self.server_capabilities
            self._namespace = b"NAMESPACE" in self.server_capabilities
            self._hierarchy_separator = self.list_folders()[0][1]
            if not self._hierarchy_separator:
                self._hierarchy_separator = ""
            if type(self._hierarchy_separator) == bytes:
                self._hierarchy_separator = bytes(
                    self._hierarchy_separator).decode("utf-8")
            if self._namespace:
                self._namespace = self.namespace()
                personal_namespace = self._namespace.personal
                if len(personal_namespace) > 0:
                    self._hierarchy_separator = personal_namespace[0][1]
                    if not personal_namespace[0][0] == "":
                        self._path_prefix = personal_namespace[0][0]
                        if type(self._path_prefix) == bytes:
                            self._path_prefix = self._path_prefix.decode(
                                "utf-8")
            else:
                self._namespace = None
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

        if idle_callback is not None:
            self._start_idle(idle_callback, idle_timeout=idle_timeout)

    def reset_connection(self):
        """Resets the connection to the IMAP server"""
        logger.info("Reconnecting to IMAP")
        try:
            self.shutdown()
        except Exception as e:
            logger.info(
                "Failed to log out: {0}".format(e.__str__()))
        self.__init__(self._init_args["host"],
                      self._init_args["username"],
                      self._init_args["password"],
                      port=self._init_args["port"],
                      ssl=self._init_args["ssl"],
                      ssl_context=self._init_args["ssl_context"],
                      verify=self._init_args["verify"],
                      timeout=self._init_args["timeout"],
                      max_retries=self._init_args["max_retries"],
                      initial_folder=self._init_args["initial_folder"],
                      idle_callback=self._init_args["idle_callback"],
                      idle_timeout=self._init_args["idle_timeout"],
                      )

    def fetch_message(self, msg_uid: int, parse: bool = False,
                      _attempt: int = 1) -> Union[str, Dict]:
        """
        Fetch a message by UID, and optionally parse it

        Args:
            msg_uid: The message UID
            parse: Return parsed results from mailparser
            _attempt: The attempt number

        Returns:
            str: The raw mail message, including headers
            dict: A parsed email message
        """
        try:
            raw_msg = self.fetch(msg_uid, ["RFC822"])[msg_uid]
        except (socket.timeout, imaplib.IMAP4.abort):
            _attempt = _attempt + 1
            if _attempt > self.max_retries:
                raise MaxRetriesExceeded("Maximum retries exceeded")
            logger.info("Attempt {0} of {1} timed out. Retrying...".format(
                _attempt,
                self.max_retries))
            self.reset_connection()
            return self.fetch_message(msg_uid, parse=parse, _attempt=_attempt)
        msg_keys = [b'RFC822', b'BODY[NULL]', b'BODY[]']
        msg_key = ''
        for key in msg_keys:
            if key in raw_msg.keys():
                msg_key = key
                break
        message = raw_msg[msg_key].decode("utf-8", "replace")
        if parse:
            message = mailsuite.utils.parse_email(message)
        return message

    def delete_messages(self, msg_uids: Union[List[int], List[str], str, int],
                        silent: bool = True, _attempt: int = 1):
        """
        Deletes the given messages by Message UIDs

        Args:
            msg_uids: A list of UIDs of messages to delete
            silent: Do it silently
            _attempt: The attempt number
        """
        logger.info("Deleting message UID(s) {0}".format(",".join(
            str(uid) for uid in msg_uids)))
        if type(msg_uids) == str or type(msg_uids) == int:
            msg_uids = [int(msg_uids)]
        try:
            imapclient.IMAPClient.delete_messages(self, msg_uids,
                                                  silent=silent)
            imapclient.IMAPClient.expunge(self, msg_uids)
        except (socket.timeout, imaplib.IMAP4.abort):
            _attempt = _attempt + 1
            if _attempt > self.max_retries:
                raise MaxRetriesExceeded("Maximum retries exceeded")
            logger.info("Attempt {0} of {1} timed out. Retrying...".format(
                _attempt,
                self.max_retries))
            self.reset_connection()
            self.delete_messages(msg_uids, silent=silent, _attempt=_attempt)

    def create_folder(self, folder_path: str, _attempt: int = 1):
        """
        Creates an IMAP folder at the given path

        Args:
            folder_path: The path of the folder to create
            _attempt: The attempt number
        """
        if not self.folder_exists(folder_path):
            logger.info("Creating folder: {0}".format(folder_path))
            try:
                imapclient.IMAPClient.create_folder(self, folder_path)
            except (socket.timeout, imaplib.IMAP4.abort):
                _attempt = _attempt + 1
                if _attempt > self.max_retries:
                    raise MaxRetriesExceeded("Maximum retries exceeded")
                logger.info("Attempt {0} of {1} timed out. Retrying...".format(
                    _attempt,
                    self.max_retries))
                self.reset_connection()
                self.create_folder(folder_path, _attempt=_attempt)

    def _move_messages(self, msg_uids: Union[int, List[int]],
                       folder_path: str):
        """
        Move the emails with the given UIDs to the given folder

        Args:
            msg_uids: A UID or list of UIDs of messages to move
            folder_path: The path of the destination folder
        """
        folder_path = folder_path.replace("\\", "/").rstrip("/")
        if type(msg_uids) == str or type(msg_uids) == int:
            msg_uids = [int(msg_uids)]
        for chunk in _chunks(msg_uids, 100):
            if self._move_supported:
                logger.info("Moving message UID(s) {0} to {1}".format(
                    ",".join(str(uid) for uid in chunk), folder_path
                ))
                try:
                    self.move(chunk, folder_path)
                except imapclient.exceptions.IMAPClientError as e:
                    e = e.__str__().lstrip("b'").rstrip(
                        "'").rstrip(".")
                    message = "Error moving message UIDs"
                    e = "{0} {1}: " "{2}".format(message, msg_uids, e)
                    logger.info("IMAP error: {0}".format(e))
                    logger.info(
                        "Copying message UID(s) {0} to {1} by copy".format(
                            ",".join(str(uid) for uid in chunk), folder_path
                        ))
                    self.copy(msg_uids, folder_path)
                    self.delete_messages(msg_uids)
            else:
                logger.info("Moving message UID(s) {0} to {1} by copy".format(
                    ",".join(str(uid) for uid in chunk), folder_path
                ))
                self.copy(msg_uids, folder_path)
                self.delete_messages(msg_uids)

    def move_messages(self, msg_uids: Union[int, List[int]], folder_path: str,
                      _attempt: int = 1):
        """
        Move the emails with the given UIDs to the given folder

        Args:
            msg_uids: A UID or list of UIDs of messages to move
            folder_path: The path of the destination folder
            _attempt: The attempt number
        """
        try:
            self._move_messages(msg_uids, folder_path)
        except (socket.timeout, imaplib.IMAP4.abort):
            _attempt = _attempt + 1
            if _attempt > self.max_retries:
                raise MaxRetriesExceeded("Maximum retries exceeded")
            logger.info("Attempt {0} of {1} timed out. Retrying...".format(
                _attempt,
                self.max_retries))
            self.reset_connection()
            self._move_messages(msg_uids, folder_path)
