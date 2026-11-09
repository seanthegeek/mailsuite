import base64
import email
import email.errors
import email.feedparser
import email.message
import email.policy
import email.utils
import hashlib
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import dns.exception
import dns.resolver
import dns.reversename
import html2text
import mailparser
import mailparser.exceptions
import publicsuffix2
from expiringdict import ExpiringDict
from publicsuffix2 import get_sld

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
mailparser_logger = logging.getLogger("mailparser")
mailparser_logger.setLevel(logging.CRITICAL)

# The lookbehind starts a scheme only where a run of letters starts; without
# it every offset inside a long run is retried, which is quadratic
url_regex = re.compile(
    r"(?<![A-Za-z])([A-Za-z]+://)([-\w]+(?:\.\w[-\w]*)+)(:\d+)?(/[^.!,?"
    r"\"<>\[\]{}\s\x7F-\xFF]*(?:[.!,?]+[^.!,?"
    r"\"<>\[\]{}\s\x7F-\xFF]+)*)?"
)
header_regex = re.compile(r"^([a-zA-Z-]+): (.+)", re.MULTILINE)

null_file = open(os.devnull, "w")  # noqa: SIM115

markdown_maker = html2text.HTML2Text()
markdown_maker.unicode_snob = True
if hasattr(markdown_maker, "decode_errors"):
    # setattr keeps pyright happy: decode_errors only exists on some
    # html2text versions, so it isn't in the type stubs
    setattr(markdown_maker, "decode_errors", "replace")  # noqa: B010
markdown_maker.body_width = 0
markdown_maker.protect_links = True
authentication_results_headers = [
    "authentication-results",
    "authentication-results-original",
]
address_headers = ["from", "sender", "delivered-to"]
addresses_headers = ["reply-to", "to", "cc", "bcc"]

#: Longest header field accepted by :func:`check_message_limits`, in
#: characters of its name, colon and raw value, folded lines included; also
#: the longest address header value :func:`parse_email` reads. RFC 5322
#: section 2.1.1 limits a line to 998 characters; this is far above that.
MAX_HEADER_FIELD_LENGTH = 65_536
#: Most header lines (folded lines and lines the parser keeps as defects
#: included), over all parts, accepted by :func:`check_message_limits`
MAX_HEADER_LINES = 100_000
#: Most parts (the message itself, MIME parts, ``message/*`` bodies and
#: ``message/delivery-status`` blocks) accepted by
#: :func:`check_message_limits`
MAX_MIME_PARTS = 10_000
#: Deepest nesting of parts accepted by :func:`check_message_limits`, the
#: message itself being 1
MAX_PART_DEPTH = 100
#: Most tests of a line against an open multipart boundary or
#: delivery-status block end accepted by :func:`check_message_limits`: the
#: parser tests every line against each one open, so its time grows with
#: lines times nesting
MAX_BOUNDARY_TESTS = 20_000_000
# Address header values longer than this lose their group syntax before
# they are parsed; shorter ones parse in milliseconds even so
_ADDRESS_GROUP_PARSE_LIMIT = 8_192
# A domain literal (RFC 5322 section 3.4.1 dtext, which RFC 5321's
# General-address-literal fits). The class also excludes quotes, angle
# brackets, parentheses and white space, so a literal cannot span a quoted
# string, an angle address or a comment, and both brackets, so matching is
# linear.
_domain_literal_regex = re.compile(r'\[[^\[\]\\"<>()\s]*\]')
_literal_placeholder_regex = re.compile(r"\[ms-[0-9a-f]{16}-[0-9]+\]")
#: Most characters in the values of the address headers mail-parser parses
#: (``From``, ``Reply-To``, ``To``, ``Cc``, ``Bcc``, ``Delivered-To``) plus
#: ``Sender``, which :func:`parse_email` parses, counted in every part,
#: accepted by :func:`check_message_limits`; mail-parser does work per
#: malformed address item in each of them
MAX_ADDRESS_HEADER_CHARS = 262_144
# Those headers, lower case. mail-parser reads them only from the top-level
# message (mailparser/const.py ADDRESSES_HEADERS); counting every part is
# the conservative choice.
_address_header_names = frozenset(
    ("from", "reply-to", "to", "cc", "bcc", "delivered-to", "sender")
)


class EmailParserError(RuntimeError):
    """Raised when an email parsing error occurs"""


class MessageLimitExceeded(ValueError):
    """Raised when a message exceeds a limit of :func:`check_message_limits`"""


def decode_base64(data: str) -> bytes:
    """
    Decodes a base64 string, with padding being optional

    Args:
        data: A base64 encoded string

    Returns: The decoded bytes

    """
    data_bytes = data.encode("ascii")
    missing_padding = len(data_bytes) % 4
    if missing_padding != 0:
        data_bytes += b"=" * (4 - missing_padding)
    return base64.b64decode(data_bytes)


def parse_email_address(email_address: tuple | str) -> dict:
    """
    Parse an email address into its components

    Addresses that ``email.utils.parseaddr`` cannot handle are split
    manually and flagged as noncompliant.

    Args:
        email_address: An address string, or a ``(display_name, address)``
            tuple as returned by ``email.utils.parseaddr``

    Returns:
        An ``OrderedDict`` with the keys ``display_name``, ``address``,
        ``local``, ``domain``, ``sld`` (the second-level domain), and
        ``compliant`` (``False`` when the address had to be parsed by the
        fallback splitter)
    """
    compliant = True
    display_name = None
    if isinstance(email_address, str):
        parsed_address = email.utils.parseaddr(email_address)
        if parsed_address == ("", ""):
            compliant = False
            parsed_address = email_address.split("<")
            parsed_address = (
                parsed_address[0].strip().strip('"'),
                parsed_address[-1].strip(">"),
            )
    elif isinstance(email_address, tuple):
        parsed_address = email_address
    else:
        raise TypeError("email_address must be a str or a (display_name, address) tuple")
    if parsed_address[0] != "":
        display_name = parsed_address[0]
    address = parsed_address[1]
    address_parts = address.split("@")
    local = None
    domain = None
    sld = None
    if len(address_parts) > 1:
        local = address_parts[0].lower()
        domain = address_parts[-1].lower()
        sld = get_sld(domain)

    return OrderedDict(
        [
            ("display_name", display_name),
            ("address", address),
            ("local", local),
            ("domain", domain),
            ("sld", sld),
            ("compliant", compliant),
        ]
    )


def get_filename_safe_string(string: str | None, max_length: int = 146) -> str:
    """
    Converts a string to a string that is safe for a filename

    Args:
        string: A string to make safe for a filename
        max_length : Truncate strings longer than this length

    Warning:
        Windows has a 260 character length limit on file paths

    Returns: A string safe for a filename
    """
    invalid_filename_chars = ["\\", "/", ":", '"', "*", "?", "<", ">", "|", "\n", "\r"]
    if string is None:
        string = "None"

    for char in invalid_filename_chars:
        string = string.replace(char, "")
    string = string.rstrip(".")

    string = (string[:max_length]) if len(string) > max_length else string

    return string


def is_outlook_msg(content: bytes) -> bool:
    """
    Checks if the given content is an Outlook msg OLE file

    Args:
        content: Content to check

    Returns: A flag that indicates if a file is an Outlook MSG file
    """
    return type(content) is bytes and content.startswith(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    )


def convert_outlook_msg(msg_bytes: bytes) -> str:
    """
    Uses the ``msgconvert`` Perl utility to convert an Outlook .msg file to
    standard RFC 822 format

    .. warning::
      Anomalies are introduced during conversion that make the results
      unsuitable for forensic analysis.

    Args:
        msg_bytes: the content of the .msg file

    Returns: A RFC 822 string

    Raises:
        ValueError: The bytes are not an Outlook .msg file.
        EmailParserError: ``msgconvert`` is missing, could not be run,
          failed, produced no output, or its output could not be read.
        OSError: The temporary directory could not be created or written.
    """
    url = "https://seanthegeek.github.io/mailsuite/#email-samples-and-outlook-clients"
    if not is_outlook_msg(msg_bytes):
        raise ValueError("The supplied bytes are not an Outlook .msg file")
    logger.warning(
        f"Converting Outlook .msg file for parsing. Results are not "
        f"suitable for forensics. See {url} for more details."
    )
    orig_dir = os.getcwd()
    tmp_dir = tempfile.mkdtemp()
    try:
        os.chdir(tmp_dir)
        with open("sample.msg", "wb") as msg_file:
            msg_file.write(msg_bytes)
        try:
            subprocess.check_call(
                ["msgconvert", "sample.msg"], stdout=null_file, stderr=null_file
            )
        except FileNotFoundError as e:
            raise EmailParserError(
                "Failed to convert Outlook .msg file: msgconvert utility not found"
            ) from e
        except subprocess.CalledProcessError as e:
            raise EmailParserError(
                f"Failed to convert Outlook .msg file: msgconvert failed with "
                f"exit status {e.returncode}"
            ) from e
        except OSError as e:
            raise EmailParserError(
                f"Failed to convert Outlook .msg file: msgconvert could not be "
                f"run: {type(e).__name__}"
            ) from e
        try:
            with open("sample.eml", "rb") as eml_file:
                rfc822 = eml_file.read().decode("utf-8", errors="replace")
        except FileNotFoundError as e:
            raise EmailParserError(
                "Failed to convert Outlook .msg file: msgconvert produced no output"
            ) from e
        except OSError as e:
            raise EmailParserError(
                f"Failed to convert Outlook .msg file: could not read msgconvert "
                f"output: {type(e).__name__}"
            ) from e
    finally:
        try:
            os.chdir(orig_dir)
        except OSError as e:
            logger.warning(f"Could not restore the working directory: {e}")
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return rfc822


def parse_authentication_results(
    authentication_results: str | list, from_domain: str | None = None
) -> dict | list[dict]:
    """
    Parses and normalizes an Authentication-Results header value or list of \
    values

    Args:
        authentication_results: The value of the header or list of values
        from_domain: The message From domain

    Returns: A parsed header value or list of parsed values
    """

    def parse_result(authentication_results_, from_domain_):
        authentication_results_ = authentication_results_.lower()
        authentication_results_ = re.sub(r"(\n|\r\n)\s+", " ", authentication_results_)
        parts = authentication_results_.split(";")
        parsed_parts = {}
        for part in parts:
            parsed_part = re.findall(r"([a-z.]+)=([a-z\d.\-_@+]+)", part)
            if len(parsed_part) == 0:
                parsed_parts["server"] = part
            else:
                parsed_parts[parsed_part[0][0]] = {}
                parsed_parts[parsed_part[0][0]]["result"] = parsed_part[0][1]
                for i_ in range(1, len(parsed_part)):
                    key = parsed_part[i_][0]
                    value = parsed_part[i_][1]
                    parsed_parts[parsed_part[0][0]][key] = value
        if "dkim" in parsed_parts:
            dkim = parsed_parts["dkim"]
            if "header.i" in dkim and "header.d" not in dkim:
                domain = dkim["header.i"].split("@")[-1]
                dkim["header.d"] = domain
            elif "from" in dkim and "header.d" not in dkim:
                dkim["header.d"] = dkim["from"]
                del dkim["from"]
        if "dmarc" in parsed_parts:
            dmarc = parsed_parts["dmarc"]
            if "action" in dmarc and "disp" not in dmarc:
                dmarc["disp"] = dmarc["action"]
                del dmarc["action"]
            if "header.from" not in dmarc and from_domain_ is not None:
                dmarc["header.from"] = from_domain_
            if "d" in dmarc:
                # Some email providers add the ``d`` value from DKIM
                del dmarc["d"]

        return parsed_parts

    if isinstance(authentication_results, str):
        try:
            return parse_result(
                authentication_results_=authentication_results, from_domain_=from_domain
            )
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"Unable to parse authentication header: {e}")
    elif isinstance(authentication_results, list):
        results = authentication_results.copy()
        for i in range(len(results)):
            try:
                results[i] = parse_result(results[i], from_domain_=from_domain)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Unable to parse authentication header: {e}")
        return results
    else:
        raise ValueError("Must be a string or list")  # noqa: TRY004


def parse_dkim_signature(dkim_signature: str | dict) -> dict | list:
    """
    Parses a DKIM-Signature header value or list of values

    Args:
        dkim_signature: A DKIM-Signature header value or list of values

    Returns: A parsed DKIM-Signature header value or parsed values
    """

    def parse_header(dkim_signature_: str) -> dict[str, object]:
        parsed_signature = {}
        dkim_signature_ = re.sub(r"(\n|\r\n)\s+", " ", dkim_signature_)
        parts = dkim_signature_.split(";")
        for part in parts:
            key_value = part.split("=")
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                parsed_signature[key] = value

        if "h" in parsed_signature:
            signed_headers = str(parsed_signature["h"]).split(":")
            for _i in range(len(signed_headers)):
                signed_headers[_i] = signed_headers[_i].strip()
            parsed_signature["h"] = signed_headers

        return parsed_signature

    if isinstance(dkim_signature, str):
        try:
            return parse_header(dkim_signature_=dkim_signature)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"Unable to parse DKIM-Signature header: {e}")
    elif isinstance(dkim_signature, list):
        signatures = dkim_signature.copy()
        for i in range(len(signatures)):
            try:
                signatures[i] = parse_header(signatures[i])
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Unable to DKIM-Signature header: {e}")
        return signatures
    else:
        raise ValueError("Must be a string or list")  # noqa: TRY004


def _limit_exceeded(name: str, value: int) -> MessageLimitExceeded:
    return MessageLimitExceeded(f"Message exceeds {name} ({value})")


# BufferedSubFile is missing from typeshed's email.feedparser stub
class _CountingInput(email.feedparser.BufferedSubFile):  # pyright: ignore[reportAttributeAccessIssue]
    """The feed parser's line buffer, stopped after a number of end tests"""

    def __init__(self, max_tests: int):
        super().__init__()
        self._test_limit = max_tests
        self.test_count = 0

    # Each line read is tested against every open multipart boundary and
    # delivery-status block end (BufferedSubFile._eofstack, private and
    # unchanged since Python 2), so the parse costs lines times nesting
    def readline(self):
        self.test_count += len(self._eofstack)
        if self.test_count > self._test_limit:
            raise _limit_exceeded("max_boundary_tests", self._test_limit)
        return super().readline()


class _BoundedFeedParser(email.feedparser.FeedParser):
    """The email package's parser, stopped at a number or depth of parts"""

    def __init__(
        self,
        max_parts: int,
        max_depth: int,
        max_boundary_tests: int,
        max_header_lines: int,
    ):
        super().__init__(policy=email.policy.compat32)
        self._input = _CountingInput(max_boundary_tests)
        self._part_limit = max_parts
        self._depth_limit = max_depth
        self._header_line_limit = max_header_lines
        self.part_count = 0
        self.header_line_count = 0

    # FeedParser._new_message() creates every part (the message itself,
    # multipart parts, message/* bodies and each block of a
    # message/delivery-status body) and FeedParser._msgstack holds the parts
    # still open. Both are private, and unchanged since Python 2; a test
    # fails if either goes away.
    def _new_message(self) -> None:
        self.part_count += 1
        if self.part_count > self._part_limit:
            raise _limit_exceeded("max_parts", self._part_limit)
        if len(self._msgstack) + 1 > self._depth_limit:  # pyright: ignore[reportAttributeAccessIssue]
            raise _limit_exceeded("max_depth", self._depth_limit)
        super()._new_message()  # pyright: ignore[reportAttributeAccessIssue]

    # FeedParser._parse_headers() receives each header block as its lines,
    # before it turns them into fields and defects (":x", a misplaced
    # "From x", a leading continuation line), so every line is counted
    def _parse_headers(self, lines: list[str]) -> None:
        self.header_line_count += len(lines)
        if self.header_line_count > self._header_line_limit:
            raise _limit_exceeded("max_header_lines", self._header_line_limit)
        super()._parse_headers(lines)  # pyright: ignore[reportAttributeAccessIssue]


def _parse_within_limits(
    text: str,
    max_parts: int,
    max_depth: int,
    max_boundary_tests: int,
    max_header_field_length: int,
    max_header_lines: int,
    max_address_header_chars: int,
) -> email.message.Message:
    parser = _BoundedFeedParser(
        max_parts, max_depth, max_boundary_tests, max_header_lines
    )
    parser.feed(text)
    message = parser.close()
    address_chars = 0
    for part in message.walk():
        for name, value in part.raw_items():
            value = str(value)
            if len(name) + 1 + len(value) > max_header_field_length:
                raise _limit_exceeded(
                    "max_header_field_length", max_header_field_length
                )
            if name.lower() in _address_header_names:
                address_chars += len(value)
                if address_chars > max_address_header_chars:
                    raise _limit_exceeded(
                        "max_address_header_chars", max_address_header_chars
                    )
    return message


def check_message_limits(
    data: str | bytes,
    *,
    max_parts: int = MAX_MIME_PARTS,
    max_depth: int = MAX_PART_DEPTH,
    max_boundary_tests: int = MAX_BOUNDARY_TESTS,
    max_header_field_length: int = MAX_HEADER_FIELD_LENGTH,
    max_header_lines: int = MAX_HEADER_LINES,
    max_address_header_chars: int = MAX_ADDRESS_HEADER_CHARS,
) -> None:
    """
    Reject a message whose structure would make parsing it slow or
    memory-hungry

    The message is parsed with the email package's own parser and policy
    (``compat32``, which ``email.message_from_string()`` and mail-parser
    use), counting the parts it creates (the message itself, MIME parts,
    ``message/*`` bodies and each block of a ``message/delivery-status``
    body), how deeply they nest, and how many times it tests a line against
    an open boundary or block end (an upper bound: it tests each one open
    until one matches), and the lines of its header blocks, including those
    it keeps only as defects; the parse stops as soon as a count goes above
    its limit, the header lines being counted after each header block is
    read, so one oversized block is read once before it is rejected. The
    header fields of the parsed parts are then limited in length, and in
    the total length of the address headers mail-parser parses (``From``,
    ``Reply-To``, ``To``, ``Cc``, ``Bcc``, ``Delivered-To``) plus
    ``Sender``, which :func:`parse_email` parses, counted in every part.

    mail-parser parses one more text: when any part has a
    ``StartBoundaryNotFoundDefect``, it parses the text of the top-level
    epilogue between the first ``--<boundary>`` and the next
    ``--<boundary>--`` (``mailparser/core.py`` lines 735-752 and
    ``find_between()`` in ``mailparser/utils.py`` lines 374-380, 4.9.0 and
    4.10.0). That text is checked with the same limits.

    Args:
        data: An RFC 822 message; bytes are decoded as UTF-8, with
          undecodable bytes replaced
        max_parts: Most parts, the message itself included
        max_depth: Deepest nesting of parts, the message itself being 1
        max_boundary_tests: Most tests of a line against an open multipart
          boundary or delivery-status block end
        max_header_field_length: Longest header field, in characters of
          its name, colon and raw value, folded lines included
        max_header_lines: Most header lines, folded lines and lines kept
          as defects included, over all parts
        max_address_header_chars: Most characters in the values of the
          ``From``, ``Reply-To``, ``To``, ``Cc``, ``Bcc``, ``Delivered-To``
          and ``Sender`` headers, counted in every part

    Raises:
        MessageLimitExceeded: The message exceeds one of the limits; the
          message names the limit and its value
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    limits = (
        max_parts,
        max_depth,
        max_boundary_tests,
        max_header_field_length,
        max_header_lines,
        max_address_header_chars,
    )
    message = _parse_within_limits(data, *limits)
    if not any(
        isinstance(defect, email.errors.StartBoundaryNotFoundDefect)
        for part in message.walk()
        for defect in part.defects
    ):
        return
    boundary = message.get_boundary()
    epilogue = message.epilogue
    if boundary is None or not isinstance(epilogue, str):
        return
    start = epilogue.find(f"--{boundary}")
    if start < 0:
        return
    start += len(boundary) + 2
    end = epilogue.find(f"--{boundary}--", start)
    if end < 0:
        return
    _parse_within_limits(epilogue[start:end].strip(), *limits)


def _without_address_groups(value: str) -> tuple[str, dict[str, str]]:
    """
    Remove RFC 5322 group syntax from a long address header value

    Parsing a group with many members whole takes time out of proportion
    to its size, so a value longer than
    ``_ADDRESS_GROUP_PARSE_LIMIT`` loses each group's display name and its
    ``:``, and each group's ``;`` becomes a comma before a following
    address; these are found outside quoted strings, comments and angle
    brackets. Every other ``:`` is removed too, since email.utils lexes some
    text differently (a route address ends one character past its address)
    and with no ``:`` it cannot find a group; a domain literal holding one
    (``[IPv6:2001:db8::1]``) is first swapped for a placeholder carrying a
    random token, returned in the mapping for :func:`_with_literals`, so a
    sender cannot write one. Shorter values are unchanged. The removal loses
    the ``:`` of a quoted display name or local part (``"a:b"@c.example``
    becomes ``"ab"@c.example``) and of an angle address's local part
    (``<a:b@c.example>`` is read as ``ab@c.example``) and a source route's
    address, and a malformed literal holding ``[`` or ``\\`` can make the
    strict parser return no address for the whole value.
    """
    if len(value) <= _ADDRESS_GROUP_PARSE_LIMIT:
        return value, {}
    literals: dict[str, str] = {}
    token = secrets.token_hex(8)

    def placeholder(match: re.Match[str]) -> str:
        if ":" not in match.group():
            return match.group()
        key = f"[ms-{token}-{len(literals)}]"
        literals[key] = match.group()
        return key

    value = _domain_literal_regex.sub(placeholder, value)
    kept: list[str] = []
    # Where the current address starts in kept
    segment = 0
    quoted = escaped = angle = after_group = False
    comment_depth = 0
    for char in value:
        if after_group and not (escaped or quoted or comment_depth or char.isspace()):
            # Keep the address after a group apart from the group's last one
            after_group = False
            if char not in ",;":
                kept.append(",")
                segment = len(kept)
        if escaped:
            escaped = False
        elif quoted or comment_depth:
            if char == "\\":
                escaped = True
            elif quoted:
                quoted = char != '"'
            elif char == "(":
                comment_depth += 1
            elif char == ")":
                comment_depth -= 1
        elif char == '"':
            quoted = True
        elif char == "(":
            comment_depth = 1
        elif char == "<":
            angle = True
        elif char == ">":
            angle = False
            kept.append(char)
            segment = len(kept)
            continue
        elif char == "," and not angle:
            kept.append(char)
            segment = len(kept)
            continue
        elif char == ":" and not angle:
            del kept[segment:]
            continue
        elif char == ";" and not angle:
            segment = len(kept)
            after_group = True
            continue
        kept.append(char)
    return "".join(kept).replace(":", ""), literals


def _restore_literals(text: str, literals: dict[str, str]) -> str:
    # Put back the domain literals _without_address_groups() swapped out;
    # any other text that looks like a placeholder is the sender's own
    if not literals:
        return text
    return _literal_placeholder_regex.sub(
        lambda match: literals.get(match.group(), match.group()), text
    )


def _with_literals(
    address: tuple[str, str], literals: dict[str, str]
) -> tuple[str, str]:
    return (
        _restore_literals(address[0], literals),
        _restore_literals(address[1], literals),
    )


def _address_with_literals(parsed: dict, literals: dict[str, str]) -> dict:
    # parse_email_address() output with the domain literals put back in the
    # display name and address, and the local part, domain and SLD derived
    # again from the restored address as parse_email_address() derives them,
    # since a literal may hold an "@"
    if not literals:
        return parsed
    if parsed["display_name"] is not None:
        parsed["display_name"] = _restore_literals(parsed["display_name"], literals)
    address = parsed["address"] = _restore_literals(parsed["address"], literals)
    address_parts = address.split("@")
    parsed["local"] = parsed["domain"] = parsed["sld"] = None
    if len(address_parts) > 1:
        parsed["local"] = address_parts[0].lower()
        parsed["domain"] = address_parts[-1].lower()
        parsed["sld"] = get_sld(parsed["domain"])
    return parsed


def parse_email(
    data: str | bytes, strip_attachment_payloads: bool = False
) -> dict:
    """
    A simplified email parser

    Args:
        data: RFC 822 message string, or Microsoft .msg bytes
        strip_attachment_payloads: Remove attachment payloads

    Returns: Parsed email data

    Raises:
        MessageLimitExceeded: The message exceeds a limit of
          :func:`check_message_limits`, checked with its defaults before
          parsing; an address header value, read up to the next ``\\n``,
          is longer than ``MAX_HEADER_FIELD_LENGTH``; or an address header
          nests comments too deeply to parse. It is a ``ValueError``.
        ValueError: The data is not an email, or mail-parser could not parse
          it (the mail-parser error is the ``__cause__``).
        EmailParserError: A ``.msg`` file could not be converted, because
          ``msgconvert`` is missing, not runnable, failed, produced no
          output, or its output could not be read. A failure to create or
          write the temporary directory stays an ``OSError``.

    .. note::
      Attachment dictionaries with binary payloads contain the value
      ``binary: True``. Use ``mailsuite.utils.decode_base64`` to convert the
      payload to bytes.
    """

    data_str: str
    if isinstance(data, bytes):
        if is_outlook_msg(data):
            data_str = convert_outlook_msg(data)
        else:
            data_str = data.decode("utf-8", errors="replace")
    elif isinstance(data, str):
        data_str = data
    else:
        raise TypeError("data must be a file path, RFC 822 string, or bytes")

    check_message_limits(data_str)
    try:
        _parsed_email = mailparser.parse_from_string(data_str)
    except mailparser.exceptions.MailParserError as e:
        raise ValueError(f"mail-parser could not parse the message: {e}") from e
    parsed_email = _parsed_email.mail
    # mail-parser <=4.6.1 returns the input string for unparseable input;
    # 4.6.2+ returns a dict with no headers instead.
    if isinstance(parsed_email, str) or not _parsed_email.headers:
        raise ValueError("Not an email")
    headers_str = re.split(r"(\n|\r\n){2,}", data_str)[0]
    parsed_email["raw_headers"] = headers_str
    headers_str = re.sub(r"(\n|\r\n)\s+", " ", headers_str)
    if "to_domains" in parsed_email and "" in parsed_email["to_domains"]:
        parsed_email["to_domains"].remove("")
    # mail-parser gives a list for a repeated field; the first one is used.
    # Only the first field at the start of the text or after a "\n" is replaced
    # with its decoded text, and a line break in that text becomes a space:
    # it would otherwise add a header line of the sender's choosing, and RFC
    # 2047 section 5 asks decoders to make sure displaying decoded text has
    # no unwanted side-effects. A function replacement keeps backslash
    # sequences (e.g. "\1") from being group references, and the field's
    # own line terminator is kept.
    for name, key in (("Subject", "subject"), ("Thread-Topic", "thread-topic")):
        if key in parsed_email:
            if isinstance(parsed_email[key], list):
                parsed_email[key] = parsed_email[key][0]
            decoded = str(parsed_email[key]).replace("\r", " ").replace("\n", " ")
            headers_str = re.sub(
                rf"^{name}:[^\r\n]*",
                lambda _m, text=f"{name}: {decoded}": text,
                headers_str,
                count=1,
                flags=re.MULTILINE | re.IGNORECASE,
            )
    parsed_email["headers_string"] = headers_str
    _headers = {}
    _header_matches = header_regex.findall(headers_str)
    for header in _header_matches:
        _headers[header[0].lower()] = header[1]
    for header in address_headers + addresses_headers:
        if len(_headers.get(header, "")) > MAX_HEADER_FIELD_LENGTH:
            raise MessageLimitExceeded(
                f"Message {header} header exceeds max_header_field_length "
                f"({MAX_HEADER_FIELD_LENGTH})"
            )
    try:
        for header in address_headers:
            if header not in _headers:
                parsed_email[header] = None
            else:
                value, literals = _without_address_groups(_headers[header])
                parsed_email[header] = _address_with_literals(
                    parse_email_address(value), literals
                )
        for header in addresses_headers:
            if header not in _headers:
                parsed_email[header] = []
            else:
                value, literals = _without_address_groups(_headers[header])
                parsed_email[header] = [
                    parse_email_address(_with_literals(address, literals))
                    for address in email.utils.getaddresses([value])
                ]
    except RecursionError:
        # email.utils parses nested comments recursively
        raise MessageLimitExceeded(
            "Message has an address header nested too deeply to parse"
        ) from None
    from_domain = None
    if "from" in parsed_email:
        if (
            parsed_email["from"] is not None
            and "domain" in parsed_email["from"]
        ):
            from_domain = parsed_email["from"]["domain"]
        else:
            logger.warning("Message from header could not be parsed")
    if "dkim-signature" in parsed_email and isinstance(
        parsed_email["dkim-signature"], str
    ):
        try:
            dkim_list = parse_dkim_signature(parsed_email["dkim-signature"])
            parsed_email["dkim-signature"] = dkim_list
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"Unable to parse DKIM-Signature header: {e}")
    for header in authentication_results_headers:
        if header in parsed_email and isinstance(parsed_email[header], str):
            authentication_results = parsed_email[header]
            try:
                authentication_results = parse_authentication_results(
                    authentication_results, from_domain=from_domain
                )
                parsed_email[header] = authentication_results
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Failed to parse {header} header: {e}")
    if "body" not in parsed_email or parsed_email["body"] is None:
        parsed_email["body"] = ""
    parsed_email["body_markdown"] = parsed_email["body"]
    parsed_email["raw_body"] = parsed_email["body"]
    parsed_email["text_plain"] = _parsed_email.text_plain.copy()
    parsed_email["text_html"] = _parsed_email.text_html.copy()
    if len(parsed_email["text_plain"]) > 0:
        parsed_email["body"] = "\n\n".join(parsed_email["text_plain"])
        parsed_email["body_markdown"] = parsed_email["body"]
    if len(parsed_email["text_html"]) > 0:
        parsed_email["body"] = "\n\n".join(parsed_email["text_html"])
        parsed_email["body_markdown"] = markdown_maker.handle(parsed_email["body"])
    body_urls = url_regex.findall(parsed_email["body_markdown"])
    for i in range(len(body_urls)):
        body_urls[i] = "".join(body_urls[i]).rstrip(")")
    parsed_email["body_urls"] = body_urls
    if "received" in parsed_email:
        for received in parsed_email["received"]:
            if "date_utc" in received:
                if received["date_utc"] is None:
                    del received["date_utc"]
                else:
                    received["date_utc"] = received["date_utc"].replace("T", " ")

    if "from" not in parsed_email:
        parsed_email["from"] = None

    if "date" in parsed_email:
        if isinstance(parsed_email["date"], datetime):
            parsed_email["date"] = (
                parsed_email["date"].replace(microsecond=0).isoformat()
            )
        else:
            parsed_email["date"] = str(parsed_email["date"]).replace("T", " ")

    else:
        parsed_email["date"] = None
    if "attachments" not in parsed_email:
        parsed_email["attachments"] = []
    else:
        for attachment in parsed_email["attachments"]:
            if "payload" in attachment:
                payload = attachment["payload"]
                try:
                    if "binary" in attachment:
                        if attachment["binary"]:
                            payload = decode_base64(payload)
                        else:
                            payload = str.encode(payload)
                    attachment["sha256"] = hashlib.sha256(payload).hexdigest()
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"Unable to decode attachment: {e.__str__()}")
        if strip_attachment_payloads:
            for attachment in parsed_email["attachments"]:
                if "payload" in attachment:
                    del attachment["payload"]

    if "subject" not in parsed_email:
        parsed_email["subject"] = None

    parsed_email["filename_safe_subject"] = get_filename_safe_string(
        parsed_email["subject"]
    )

    # RFC 3834: a message is an automatic response/submission when it carries
    # an Auto-Submitted header with any value other than "no" — e.g. Gmail's
    # "auto-replied", Microsoft 365 / Exchange's "auto-generated", and MTA
    # bounces/DSNs. Exchange's X-Auto-Response-Suppress (set on Out-of-Office
    # replies) is a secondary, vendor-specific signal.
    auto_submitted = parsed_email.get("auto-submitted")
    auto_reply = (
        auto_submitted is not None
        and str(auto_submitted).split(";")[0].strip().lower() not in ("", "no")
    ) or parsed_email.get("x-auto-response-suppress") is not None
    parsed_email["automatic_reply"] = auto_reply

    return parsed_email


def from_trusted_domain(
    message: str | bytes | dict,
    trusted_domains: list[str] | str,
    include_sld: bool = True,
    allow_multiple_authentication_results: bool = False,
    use_authentication_results_original: bool = False,
) -> bool:
    """
    Checks if an email is from a trusted domain based on the contents of the
    ``Authentication-Results`` header

    .. warning ::
      Authentication results are not verified by this function, so only use it
      on emails that have been received by trusted mail servers, and not on
      third-party emails.

    .. warning::
      Set ``allow_multiple_authentication_results`` to ``True``
      **if and only if** the receiving mail service splits the results of each
      authentication method in separate ``Authentication-Results`` headers
      **and always** includes DMARC results.

    .. warning::
      Set ``use_authentication_results_original`` to ``True``
      **if and only if** you use an email security gateway that adds an
      ``Authentication-Results-Original`` header, such as Proofpoint or Cisco
      IronPort. This **does not** include API-based email security solutions,
      such as Abnormal Security.

    Args:
        message: An email
        trusted_domains: A list of trusted domains
        include_sld: Also return ``True`` if the Second-Level Domain (SLD) \
        of an authenticated domain is in ``trusted_domains``
        allow_multiple_authentication_results: Allow multiple
         ``Authentication-Results`` headers
        use_authentication_results_original: Use the
         ``Authentication-Results-Original`` header instead of the
         ``Authentication-Results`` header

    Returns:
        Results of the check

    Raises:
        MessageLimitExceeded: ``message`` is not a dict and
          :func:`parse_email` rejects it
    """
    if isinstance(message, dict):
        parsed_email = message
    else:
        parsed_email = parse_email(message)

    if isinstance(trusted_domains, str):
        trusted_domains = re.split(r"(\n|\r\n)", trusted_domains)

    for i in range(len(trusted_domains)):
        trusted_domains[i] = trusted_domains[i].lower().strip()
    trusted_domains = list(set(trusted_domains))
    if "" in trusted_domains:
        trusted_domains.remove("")
    trusted_domains = list(trusted_domains)

    header_name = "authentication-results"
    if (
        use_authentication_results_original
        and "authentication-results-original" in parsed_email
    ):
        header_name = "authentication-results-original"

    if header_name not in parsed_email:
        return False
    results = parsed_email[header_name]

    if isinstance(results, dict):
        if "dkim" in results:
            dkim = results["dkim"]
            dkim_result = dkim["result"]
            domain = dkim["header.d"].lower().strip()
            sld = publicsuffix2.get_sld(domain)

            if dkim_result == "pass" and domain in trusted_domains:
                return True
            if include_sld and dkim_result == "pass" and sld in trusted_domains:
                return True
        if "dmarc" in results:
            dmarc = results["dmarc"]
            dmarc_result = dmarc["result"]
            if "header.from" not in dmarc:
                return False
            domain = dmarc["header.from"].lower().strip()
            sld = publicsuffix2.get_sld(domain)
            if dmarc_result == "pass" and domain in trusted_domains:
                return True
            if include_sld and dmarc_result == "pass" and sld in trusted_domains:
                return True
        return False
    if isinstance(results, list) and allow_multiple_authentication_results:
        dmarc = None
        for header in results:
            # parse_email yields raw strings for multiple Authentication-Results
            # headers; parse each into the same dict shape as the single-header
            # path before inspecting it.
            if isinstance(header, str):
                try:
                    header = parse_authentication_results(header)
                except ValueError:
                    continue
            if not isinstance(header, dict) or "dmarc" not in header:
                continue
            if dmarc is not None:
                # More than one DMARC result across the headers is ambiguous
                return False
            dmarc = header["dmarc"]
            if dmarc.get("result") != "pass" or "header.from" not in dmarc:
                continue
            domain = dmarc["header.from"].lower().strip()
            sld = publicsuffix2.get_sld(domain)
            if domain in trusted_domains:
                return True
            if include_sld and sld in trusted_domains:
                return True
    return False


def query_dns(
    domain: str,
    record_type: str,
    cache: ExpiringDict | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 2.0,
):
    """
    Queries DNS

    Args:
        domain: The domain or subdomain to query about
        record_type: The record type to query for
        cache: Cache storage
        nameservers: A list of one or more nameservers to use
        timeout: DNS timeout in seconds

    Returns:
        A list of answers
    """
    domain = str(domain).lower()
    record_type = record_type.upper()
    cache_key = f"{domain}_{record_type}"
    if cache:
        records = cache.get(cache_key, None)
        if records:
            return records

    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if record_type == "TXT":
        resource_records = [
            r.strings
            for r in resolver.resolve(domain, record_type, tcp=True, lifetime=timeout)
        ]
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records
            if resource_record
        ]
        records = [r.decode() for r in _resource_record]
    else:
        records = [
            r.to_text().replace('"', "").rstrip(".")
            for r in resolver.resolve(domain, record_type, tcp=True, lifetime=timeout)
        ]
    if cache:
        cache[cache_key] = records

    return records


def get_reverse_dns(
    ip_address: str,
    cache: ExpiringDict | None = None,
    nameservers: list[str] | None = None,
    timeout: float = 2.0,
) -> str | None:
    """
    Resolves an IP address to a hostname using a reverse DNS query

    Args:
        ip_address: The IP address to resolve
        cache: Cache storage
        nameservers: A list of one or more nameservers to use
        timeout: Sets the DNS query timeout in seconds

    Returns: The reverse DNS hostname (if any)
    """
    hostname = None
    try:
        address = str(dns.reversename.from_address(ip_address))
        hostname = query_dns(
            address, "PTR", cache=cache, nameservers=nameservers, timeout=timeout
        )[0]

    except dns.exception.DNSException:
        pass

    return hostname


def create_email(
    message_from: str,
    message_to: list[str] | None = None,
    message_cc: list[str] | None = None,
    subject: str | None = None,
    message_headers: dict | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
    plain_message: str | None = None,
    html_message: str | None = None,
) -> str:
    """
    Creates an RFC 822 email message and returns it as a string

    Args:
        message_from: The value of the message from header
        message_to: A list of addresses to send mail to
        message_cc: A List of addresses to Carbon Copy (CC)
        subject: The message subject
        message_headers: Custom message headers
        attachments: A list of tuples, containing a filename and bytes
        plain_message: The plain text message body
        html_message: The HTML message body

    Returns: A RFC 822 email message
    """
    msg = MIMEMultipart()
    msg["From"] = message_from
    if message_to:
        msg["To"] = ", ".join(message_to)
    if message_cc:
        msg["Cc"] = ", ".join(message_cc)
    msg["Date"] = email.utils.formatdate(localtime=True)
    if subject:
        msg["Subject"] = subject
    if message_headers is not None:
        for header in message_headers:
            msg[header] = message_headers[header]
    if attachments is None:
        attachments = []

    if plain_message is not None:
        msg.attach(MIMEText(plain_message, "plain"))
    if html_message is not None:
        msg.attach(MIMEText(html_message, "html"))

    for attachment in attachments:
        filename = attachment[0]
        payload = attachment[1]
        part = MIMEApplication(payload, Name=filename)
        content_disposition = f'attachment; filename="{filename}"'
        part["Content-Disposition"] = content_disposition
        msg.attach(part)

    return msg.as_string()
