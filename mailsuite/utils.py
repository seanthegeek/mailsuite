import logging
from typing import Union, Optional
from datetime import datetime
import os
from collections import OrderedDict
import tempfile
import subprocess
import shutil
import hashlib
import base64
import re
import email
import email.utils
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import mailparser
import html2text
import dns.reversename
import dns.resolver
import dns.exception
import publicsuffix2
from publicsuffix2 import get_sld
from expiringdict import ExpiringDict


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
mailparser_logger = logging.getLogger("mailparser")
mailparser_logger.setLevel(logging.CRITICAL)

url_regex = re.compile(
    r"([A-Za-z]+://)([-\w]+(?:\.\w[-\w]*)+)(:\d+)?(/[^.!,?"
    r"\"<>\[\]{}\s\x7F-\xFF]*(?:[.!,?]+[^.!,?"
    r"\"<>\[\]{}\s\x7F-\xFF]+)*)?"
)
header_regex = re.compile(r"([a-zA-Z-]+): (.+)")

null_file = open(os.devnull, "w")

markdown_maker = html2text.HTML2Text()
markdown_maker.unicode_snob = True
if hasattr(markdown_maker, "decode_errors"):
    setattr(markdown_maker, "decode_errors", "replace")
markdown_maker.body_width = 0
markdown_maker.protect_links = True
authentication_results_headers = [
    "authentication-results",
    "authentication-results-original",
]
address_headers = ["from", "sender", "delivered-to"]
addresses_headers = ["reply-to", "to", "cc", "bcc"]


class EmailParserError(RuntimeError):
    """Raised when an email parsing error occurs"""


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


def parse_email_address(email_address: Union[tuple, str]) -> dict:
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


def get_filename_safe_string(string: Union[str, None], max_length: int = 146) -> str:
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

    Returns: A flag the indicates if a file is an Outlook MSG file
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
    """
    url = "https://seanthegeek.github.io/mailsuite/#email-samples-and-outlook-clients"
    if not is_outlook_msg(msg_bytes):
        raise ValueError("The supplied bytes are not an Outlook .msg file")
    logger.warning(
        f"Converting Outlook .msg file for parsing. Results are not"
        f"suitable for forensics  See {url} for more details."
    )
    orig_dir = os.getcwd()
    tmp_dir = tempfile.mkdtemp()
    os.chdir(tmp_dir)
    with open("sample.msg", "wb") as msg_file:
        msg_file.write(msg_bytes)
    try:
        subprocess.check_call(
            ["msgconvert", "sample.msg"], stdout=null_file, stderr=null_file
        )
        eml_path = "sample.eml"
        with open(eml_path, "r") as eml_file:
            rfc822 = eml_file.read()
    except FileNotFoundError:
        raise EmailParserError(
            "Failed to convert Outlook .msg file: msgconvert utility not found"
        )
    finally:
        os.chdir(orig_dir)
        shutil.rmtree(tmp_dir)

    return rfc822


def parse_authentication_results(
    authentication_results: Union[str, list], from_domain: Optional[str] = None
) -> Union[dict, list[dict]]:
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
        except Exception as e:
            raise ValueError(f"Unable to parse authentication header: {e}")
    elif isinstance(authentication_results, list):
        results = authentication_results.copy()
        for i in range(len(results)):
            try:
                results[i] = parse_result(results[i], from_domain_=from_domain)
            except Exception as e:
                logger.warning(f"Unable to parse authentication header: {e}")
        return results
    else:
        raise ValueError("Must be a string or list")


def parse_dkim_signature(dkim_signature: Union[str, dict]) -> Union[dict, list]:
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
        except Exception as e:
            raise ValueError(f"Unable to parse DKIM-Signature header: {e}")
    elif isinstance(dkim_signature, list):
        signatures = dkim_signature.copy()
        for i in range(len(signatures)):
            try:
                signatures[i] = parse_header(signatures[i])
            except Exception as e:
                logger.warning(f"Unable to DKIM-Signature header: {e}")
        return signatures
    else:
        raise ValueError("Must be a string or list")


def parse_email(
    data: Union[str, bytes], strip_attachment_payloads: bool = False
) -> dict:
    """
    A simplified email parser

    Args:
        data: RFC 822 message string, or Microsoft .msg bytes
        strip_attachment_payloads: Remove attachment payloads

    Returns: Parsed email data

    .. note::
      Attachment dictionaries with binary payloads contain the value
      ``binary: True`` use ``mailsuite.utils.decode_base64`` to convert the
      payload to bytes.
    """

    def _test_header_value(
        header_name: str, header_value: Union[str, int, float], startswith: bool = False
    ) -> bool:
        header_name = header_name.lower()
        if header_name not in parsed_email:
            return False
        if parsed_email[header_name] is None:
            return False
        if startswith and all(
            [isinstance(header_value, str), isinstance(parsed_email[header_name], str)]
        ):
            return parsed_email[header_name].startswith(header_value)
        return parsed_email[header_name] == header_value

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

    _parsed_email = mailparser.parse_from_string(data_str)
    parsed_email = _parsed_email.mail
    if isinstance(parsed_email, str):
        raise ValueError("Not an email")
    headers_str = re.split(r"(\n|\r\n){2,}", data_str)[0]
    parsed_email["raw_headers"] = headers_str
    headers_str = re.sub(r"(\n|\r\n)\s+", " ", headers_str)
    if "to_domains" in parsed_email and "" in parsed_email["to_domains"]:
        parsed_email["to_domains"].remove("")
    if "subject" in parsed_email:
        headers_str = re.sub(
            r"Subject: .+", f"Subject: {parsed_email['subject']}", headers_str
        )

    if "thread-topic" in parsed_email:
        headers_str = re.sub(
            r"Thread-Topic: .+",
            f"Thread-Topic: {parsed_email['thread-topic']}",
            headers_str,
        )
    parsed_email["headers_string"] = headers_str
    _headers = {}
    _header_matches = header_regex.findall(headers_str)
    for header in _header_matches:
        _headers[header[0].lower()] = header[1]
    for header in address_headers:
        if header not in _headers:
            parsed_email[header] = None
        else:
            parsed_email[header] = parse_email_address(_headers[header])
    for header in addresses_headers:
        if header not in _headers:
            parsed_email[header] = []
        else:
            parsed_email[header] = list(
                map(
                    lambda x: parse_email_address(x),
                    email.utils.getaddresses([_headers[header]]),
                )
            )
    from_domain = None
    if "from" in parsed_email:
        if "domain" in parsed_email["from"]:
            from_domain = parsed_email["from"]["domain"]
        else:
            logger.warning("Message from header could not be parsed")
    if "dkim-signature" in parsed_email:
        if isinstance(parsed_email["dkim-signature"], str):
            try:
                dkim_list = parse_dkim_signature(parsed_email["dkim-signature"])
                parsed_email["dkim-signature"] = dkim_list
            except Exception as e:
                raise ValueError(f"Unable to parse DKIM-Signature header: {e}")
    for header in authentication_results_headers:
        if header in parsed_email and isinstance(parsed_email[header], str):
            authentication_results = parsed_email[header]
            try:
                authentication_results = parse_authentication_results(
                    authentication_results, from_domain=from_domain
                )
                parsed_email[header] = authentication_results
            except Exception as e:
                logger.warning(f"Failed to parse {header} header: {e}")
    if "body" not in parsed_email or parsed_email["body"] is None:
        parsed_email["body"] = ""
        parsed_email["body_markdown"] = ""
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
    if "reply_to" in parsed_email:
        parsed_email["reply-to"] = list(
            map(lambda x: parse_email_address(x), parsed_email["reply_to"])
        )
    else:
        parsed_email["reply-to"] = []

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
                except Exception as e:
                    logger.debug("Unable to decode attachment: {0}".format(e.__str__()))
        if strip_attachment_payloads:
            for attachment in parsed_email["attachments"]:
                if "payload" in attachment:
                    del attachment["payload"]

    if "subject" not in parsed_email:
        parsed_email["subject"] = None

    parsed_email["filename_safe_subject"] = get_filename_safe_string(
        parsed_email["subject"]
    )

    if "body" not in parsed_email:
        parsed_email["body"] = None
        parsed_email["body_markdown"] = None
    auto_reply = all(
        [
            _test_header_value("x-auto-response-suppress", "All"),
            _test_header_value("auto-submitted", "auto_generated"),
        ]
    )
    parsed_email["automatic_reply"] = auto_reply

    return parsed_email


def from_trusted_domain(
    message: Union[str, bytes, dict],
    trusted_domains: Union[list[str], str],
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
         ``Authentication-Results-Original`` headers
        use_authentication_results_original: Use the
         ``Authentication-Results-Original`` header instead of the
         ``Authentication-Results`` header

    Returns:
        Results of the check
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
    if use_authentication_results_original:
        if "authentication-results-original" in parsed_email:
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
            if include_sld:
                if dkim_result == "pass" and sld in trusted_domains:
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
            if include_sld:
                if dmarc_result == "pass" and sld in trusted_domains:
                    return True
        return False
    if isinstance(results, list) and allow_multiple_authentication_results:
        dmarc_result = False
        dmarc = None
        for header in results:
            if "dmarc" in header:
                if dmarc is not None:
                    return False
                dmarc = header["dmarc"]
                dmarc_result = dmarc["result"]
                domain = dmarc["header.from"]
                sld = publicsuffix2.get_sld(domain)
                if dmarc_result == "pass" and domain in trusted_domains:
                    dmarc_result = True
                    return dmarc_result
                if include_sld:
                    if dmarc_result == "pass" and sld in trusted_domains:
                        dmarc_result = True
                        return dmarc_result
    return False


def query_dns(
    domain: str,
    record_type: str,
    cache: Optional[ExpiringDict] = None,
    nameservers: Optional[list[str]] = None,
    timeout: Union[float, int] = 2.0,
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
    cache_key = "{0}_{1}".format(domain, record_type)
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
        resource_records = list(
            map(
                lambda r: r.strings,
                resolver.resolve(domain, record_type, tcp=True, lifetime=timeout),
            )
        )
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records
            if resource_record
        ]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(
            map(
                lambda r: r.to_text().replace('"', "").rstrip("."),
                resolver.resolve(domain, record_type, tcp=True, lifetime=timeout),
            )
        )
    if cache:
        cache[cache_key] = records

    return records


def get_reverse_dns(
    ip_address: str,
    cache: Optional[ExpiringDict] = None,
    nameservers: Optional[list[str]] = None,
    timeout: Union[float, int] = 2.0,
) -> Union[str, None]:
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
    message_to: Optional[list[str]] = None,
    message_cc: Optional[list[str]] = None,
    subject: Optional[str] = None,
    message_headers: Optional[dict] = None,
    attachments: Optional[list[tuple[str, bytes]]] = None,
    plain_message: Optional[str] = None,
    html_message: Optional[str] = None,
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
    if message_cc is not None:
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
        content_disposition = 'attachment; filename="{0}"'.format(filename)
        part["Content-Disposition"] = content_disposition
        msg.attach(part)

    return msg.as_string()
