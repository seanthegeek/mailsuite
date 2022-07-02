import logging
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
from publicsuffix2 import get_public_suffix


logger = logging.getLogger(__name__)

null_file = open(os.devnull, "w")

markdown_maker = html2text.HTML2Text()
markdown_maker.unicode_snob = True
markdown_maker.decode_errors = "replace"
markdown_maker.body_width = 0


class EmailParserError(RuntimeError):
    """Raised when an error parsing the email occurs"""


def decode_base64(data):
    """
    Decodes a base64 string, with padding being optional

    Args:
        data: A base64 encoded string

    Returns:
        bytes: The decoded bytes

    """
    data = bytes(data, encoding="ascii")
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data)


def parse_email_address(original_address):
    if original_address[0] == "":
        display_name = None
    else:
        display_name = original_address[0]
    address = original_address[1]
    address_parts = address.split("@")
    local = None
    domain = None
    base_domain = None
    if len(address_parts) > 1:
        local = address_parts[0].lower()
        domain = address_parts[-1].lower()
        base_domain = get_public_suffix(domain)

    return OrderedDict([("display_name", display_name),
                        ("address", address),
                        ("local", local),
                        ("domain", domain),
                        ("base_domain", base_domain)]
                       )


def get_filename_safe_string(string, max_length=146):
    """
    Converts a string to a string that is safe for a filename
    Args:
        string (str): A string to make safe for a filename
        max_length (int): Truncate strings longer than this length

    Warning:
        Windows has a 260 character length limit on file paths

    Returns:
        str: A string safe for a filename
    """
    invalid_filename_chars = ['\\', '/', ':', '"', '*', '?',
                              '<', '>', '|', '\n', '\r']
    if string is None:
        string = "None"

    for char in invalid_filename_chars:
        string = string.replace(char, "")
    string = string.rstrip(".")

    string = (string[:max_length]) if len(string) > max_length else string

    return string


def is_outlook_msg(content):
    """
    Checks if the given content is an Outlook msg OLE file

    Args:
        content: Content to check

    Returns:
        bool: A flag the indicates if a file is an Outlook MSG file
    """
    return type(content) == bytes and content.startswith(
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")


def convert_outlook_msg(msg_bytes):
    """
    Uses the ``msgconvert`` Perl utility to convert an Outlook MS file to
    standard RFC 822 format

    Args:
        msg_bytes (bytes): the content of the .msg file

    Returns:
        A RFC 822 string
    """
    if not is_outlook_msg(msg_bytes):
        raise ValueError("The supplied bytes are not an Outlook MSG file")
    orig_dir = os.getcwd()
    tmp_dir = tempfile.mkdtemp()
    os.chdir(tmp_dir)
    with open("sample.msg", "wb") as msg_file:
        msg_file.write(msg_bytes)
    try:
        subprocess.check_call(["msgconvert", "sample.msg"],
                              stdout=null_file, stderr=null_file)
        eml_path = "sample.eml"
        with open(eml_path, "rb") as eml_file:
            rfc822 = eml_file.read()
    except FileNotFoundError:
        raise EmailParserError(
            "Failed to convert Outlook MSG: msgconvert utility not found")
    finally:
        os.chdir(orig_dir)
        shutil.rmtree(tmp_dir)

    return rfc822


def parse_authentication_results(authentication_results, from_domain=None):
    """
    Parses and normalizes an Authentication-Results header

    Args:
        authentication_results (str): The value of the header
        from_domain (str): The message From domain

    Returns (dict): A parsed header value
    """
    authentication_results = authentication_results.lower()
    parts = authentication_results.split(";")
    parsed_parts = {}
    for part in parts:
        parsed_part = re.findall(r"([a-z.]+)=([a-z\d.\-_@+]+)", part)
        if len(parsed_part) == 0:
            parsed_parts["mta"] = part
        else:
            parsed_parts[parsed_part[0][0]] = {}
            parsed_parts[parsed_part[0][0]]["result"] = parsed_part[0][1]
            for i in range(1, len(parsed_part)):
                key = parsed_part[i][0]
                value = parsed_part[i][1]
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
        if "header.from" not in dmarc and from_domain is not None:
            dmarc["header.from"] = from_domain
        if "d" in dmarc:
            # Some email providers add the ``d`` value from DKIM
            del dmarc["d"]

    return parsed_parts


def parse_dkim_signature(dkim_signature):
    """
    Parses a DKIM-Signature header value

    Args:
        dkim_signature (str): A DKIM-Signature header value

    Returns  (dict): A parsed DKIM-Signature header value
    """
    parsed_signature = {}
    dkim_signature = re.sub(r"\n\s+", " ", dkim_signature)
    parts = dkim_signature.split(";")
    for part in parts:
        key_value = part.split("=")
        key = key_value[0].strip()
        value = key_value[1].strip()
        parsed_signature[key] = value

    if "h" in parsed_signature:
        parsed_signature["h"] = parsed_signature["h"].split(":")

    return parsed_signature


def parse_email(data, strip_attachment_payloads=False):
    """
    A simplified email parser

    Args:
        data: The RFC 822 message string, or MSG binary
        strip_attachment_payloads (bool): Remove attachment payloads

    Returns (dict): Parsed email data
    """

    if type(data) == bytes:
        if is_outlook_msg(data):
            data = convert_outlook_msg(data)
        data = data.decode("utf-8", errors="replace")
    _parsed_email = mailparser.parse_from_string(data)
    parsed_email = _parsed_email.mail
    headers_str = data.split("\n\n")[0]
    parsed_email["raw_headers"] = headers_str
    headers_str = re.sub(r"\n\s+", " ", headers_str)
    parsed_email["headers_string"] = headers_str
    from_domain = None
    if parsed_email["from"] is not None:
        parsed_email["from"] = parse_email_address(parsed_email["from"][0])
        from_domain = parsed_email["from"]["domain"]
    if "dkim-signature" in parsed_email:
        if type(parsed_email["dkim-signature"]) == str:
            parsed_email["dkim-signature"] = parse_dkim_signature(
                parsed_email["dkim-signature"])
        elif type(parsed_email["dkim-signature"]) == list:
            dkim_list = []
            for sig in parsed_email["dkim-signature"]:
                dkim_list.append(parse_dkim_signature(sig))
            parsed_email["dkim-signature"] = dkim_list
    if "authentication-results" in parsed_email:
        authentication_results = parsed_email["authentication-results"]
        if type(authentication_results) == str:
            authentication_results = re.sub(r"\n\s+", " ",
                                            authentication_results)
            parsed_auth = parse_authentication_results(authentication_results,
                                                       from_domain)
            parsed_email["authentication-results"] = parsed_auth
        elif type(authentication_results) == list:
            auth_list = []
            for result in authentication_results:
                result = re.sub(r"\n\s+", " ", result)

                auth_list.append(parse_authentication_results(result,
                                                              from_domain))
            parsed_email["authentication-results"] = auth_list
    if "authentication-results-original" in parsed_email:
        authentication_results = parsed_email[
            "authentication-results-original"]
        if type(authentication_results) == str:
            authentication_results = re.sub(r"\n\s+", " ",
                                            authentication_results)
            parsed_auth = parse_authentication_results(authentication_results,
                                                       from_domain)
            parsed_email["authentication-results-original"] = parsed_auth
        elif type(authentication_results) == list:
            auth_list = []
            for result in authentication_results:
                result = re.sub(r"\n\s+", " ", result)
                auth_list.append(parse_authentication_results(result,
                                                              from_domain))
            parsed_email["authentication-results-original"] = auth_list
    if "body" not in parsed_email or parsed_email["body"] is None:
        parsed_email["body"] = ""
    parsed_email["raw_body"] = parsed_email["body"]
    parsed_email["text_plain"] = _parsed_email.text_plain.copy()
    parsed_email["text_html"] = _parsed_email.text_html.copy()
    if len(parsed_email["text_plain"]) > 0:
        parsed_email["body"] = "\n\n".join(parsed_email["text_plain"])
        parsed_email["body_markdown"] = "\n\n".join(parsed_email["text_plain"])
    if len(parsed_email["text_html"]) > 0:
        parsed_email["body"] = "\n\n".join(parsed_email["text_html"])
        parsed_email["body_markdown"] = markdown_maker.handle(
            parsed_email["body"])

    if "received" in parsed_email:
        for received in parsed_email["received"]:
            if "date_utc" in received:
                if received["date_utc"] is None:
                    del received["date_utc"]
                else:
                    received["date_utc"] = received["date_utc"].replace("T",
                                                                        " ")

    if "from" not in parsed_email:
        if "From" in parsed_email["headers"]:
            parsed_email["from"] = parsed_email["Headers"]["From"]
        else:
            parsed_email["from"] = None

    if "date" in parsed_email:
        if type(parsed_email["date"] == datetime):
            parsed_email["date"] = parsed_email["date"].replace(
                microsecond=0).isoformat()
        else:
            parsed_email["date"] = parsed_email["date"].replace("T", " ")

    else:
        parsed_email["date"] = None
    if "reply_to" in parsed_email:
        parsed_email["reply_to"] = list(map(lambda x: parse_email_address(x),
                                            parsed_email["reply_to"]))
    else:
        parsed_email["reply_to"] = []

    if "to" in parsed_email:
        parsed_email["to"] = list(map(lambda x: parse_email_address(x),
                                      parsed_email["to"]))
    else:
        parsed_email["to"] = []

    if "cc" in parsed_email:
        parsed_email["cc"] = list(map(lambda x: parse_email_address(x),
                                      parsed_email["cc"]))
    else:
        parsed_email["cc"] = []

    if "bcc" in parsed_email:
        parsed_email["bcc"] = list(map(lambda x: parse_email_address(x),
                                       parsed_email["bcc"]))
    else:
        parsed_email["bcc"] = []

    if "delivered_to" in parsed_email:
        parsed_email["delivered_to"] = list(
            map(lambda x: parse_email_address(x),
                parsed_email["delivered_to"])
        )

    if "attachments" not in parsed_email:
        parsed_email["attachments"] = []
    else:
        for attachment in parsed_email["attachments"]:
            if "payload" in attachment:
                payload = attachment["payload"]
                try:
                    if "content_transfer_encoding" in attachment:
                        if attachment["content_transfer_encoding"] == "base64":
                            payload = decode_base64(payload)
                        else:
                            payload = str.encode(payload)
                    attachment["sha256"] = hashlib.sha256(payload).hexdigest()
                except Exception as e:
                    logger.debug("Unable to decode attachment: {0}".format(
                        e.__str__()
                    ))
        if strip_attachment_payloads:
            for attachment in parsed_email["attachments"]:
                if "payload" in attachment:
                    del attachment["payload"]

    if "subject" not in parsed_email:
        parsed_email["subject"] = None

    parsed_email["filename_safe_subject"] = get_filename_safe_string(
        parsed_email["subject"])

    if "body" not in parsed_email:
        parsed_email["body"] = None
        parsed_email["body_markdown"] = None
    else:
        parsed_email["body_markdown"] = markdown_maker.handle(
            parsed_email["body"])
    return parsed_email


def query_dns(domain, record_type, cache=None, nameservers=None, timeout=2.0):
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        list: A list of answers
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
    if nameservers is None:
        nameservers = ["1.1.1.1", "1.0.0.1",
                       "2606:4700:4700::1111", "2606:4700:4700::1001",
                       ]
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if record_type == "TXT":
        resource_records = list(map(
            lambda r: r.strings,
            resolver.resolve(domain, record_type, tcp=True, lifetime=timeout)))
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records if resource_record]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(map(
            lambda r: r.to_text().replace('"', '').rstrip("."),
            resolver.resolve(domain, record_type, tcp=True, lifetime=timeout)))
    if cache:
        cache[cache_key] = records

    return records


def get_reverse_dns(ip_address, cache=None, nameservers=None, timeout=2.0):
    """
    Resolves an IP address to a hostname using a reverse DNS query

    Args:
        ip_address (str): The IP address to resolve
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS query timeout in seconds

    Returns:
        str: The reverse DNS hostname (if any)
    """
    hostname = None
    try:
        address = str(dns.reversename.from_address(ip_address))
        hostname = query_dns(address, "PTR", cache=cache,
                             nameservers=nameservers,
                             timeout=timeout)[0]

    except dns.exception.DNSException:
        pass

    return hostname


def create_email(message_from, message_to=None, message_cc=None,
                 subject=None, message_headers=None, attachments=None,
                 plain_message=None, html_message=None):
    """
    Creates an RFC 822 email message and returns it as a string

    Args:
        message_from (str): The value of the message from header
        message_to (list): A list of addresses to send mail to
        message_cc (list): A List of addresses to Carbon Copy (CC)
        subject (str): The message subject
        message_headers (dict): Custom message headers
        attachments (list): A list of tuples, containing filenames as bytes
        plain_message (str): The plain text message body
        html_message (str): The HTML message body

    Returns:
        str: A RFC 822 email message
    """
    msg = MIMEMultipart()
    msg['From'] = message_from
    msg['To'] = ", ".join(message_to)
    if message_cc is not None:
        msg['Cc'] = ", ".join(message_cc)
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Subject'] = subject
    if message_headers is not None:
        for header in message_headers:
            msg[header] = message_headers[header]
    if attachments is None:
        attachments = []

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

    return msg.as_string()
