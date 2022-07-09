import logging
from typing import Union
import base64
import binascii
import os
from os import path
from tempfile import mkdtemp
from subprocess import run, PIPE
from shutil import rmtree
from io import IOBase, BytesIO
import zipfile

import yara

import mailsuite.utils

formatter = logging.Formatter(
    fmt='%(levelname)8s:%(filename)s:%(lineno)d:%(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S')
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("mailsuite.scanner")
logger.addHandler(handler)


def _match_to_dict(match: Union[yara.Match,
                                list[yara.Match]]) -> Union[list[dict],
                                                            dict]:
    def match_to_dict_(_match: yara.Match) -> dict:
        return dict(rule=_match.rule,
                    namespace=_match.namespace,
                    tags=_match.tags,
                    meta=_match.meta,
                    strings=_match.strings
                    )

    if isinstance(match, list):
        matches = match.copy()
        for i in range(len(matches)):
            matches[i] = _match_to_dict(matches[i])
        return matches
    elif isinstance(match, yara.Match):
        return match_to_dict_(match)


def _is_pdf(file_bytes: bytes) -> bool:
    return file_bytes.startswith(b"\x25\x50")


def _is_zip(file_bytes: bytes) -> bool:
    return file_bytes.startswith(b"\x50\x4B\03\04")


def _pdf_to_markdown(pdf_bytes: bytes) -> str:
    if not _is_pdf(pdf_bytes):
        raise ValueError("Not a PDF file")
    tmp_dir = mkdtemp()
    sample_path = path.join(tmp_dir, "sample.pdf")
    with open(sample_path, "wb") as sample_file:
        sample_file.write(pdf_bytes)
    try:
        markdown = run(["pdf2text", "sample.pdf", "-"],
                       stdout=PIPE).stdout.decode("utf-8", errors="ignore")
        if markdown is None:
            markdown = ""
        return markdown
    except FileNotFoundError:
        error_msg = "The pdf2text utility could not be found. " \
                    "Please install poppler-utils."
        raise FileNotFoundError(error_msg)
    finally:
        rmtree(tmp_dir)


def _compile_rules(rules: Union[yara.Rules, IOBase, str]) -> yara.Rules:
    if isinstance(rules, yara.Rules):
        return rules
    if isinstance(rules, IOBase):
        rules = rules.read()
    if path.exists(rules):
        if path.isdir(rules):
            rules_str = ""
            for filename in os.listdir():
                file_path = path.join(rules, filename)
                if not path.isdir(file_path):
                    with open(file_path) as rules_file:
                        rules_str += rules_file.read()
            return yara.compile(source=rules_str)
        return yara.compile(filepath=rules)
    return yara.compile(source=rules)


class MailScanner(object):
    def __init__(self, header_rules: Union[str, IOBase, yara.Rules] = None,
                 body_rules: Union[str, IOBase, yara.Rules] = None,
                 header_body_rules: Union[str, IOBase, yara.Rules] = None,
                 attachment_rules: Union[str, IOBase, yara.Rules] = None):
        """
        A YARA scanner for emails

        Args:
            header_rules:Rules that match email headers
            body_rules: Rules that match an email body
            header_body_rules: Rules that match on email
            header and body content
            attachment_rules: Rules that match file
            attachment contents
        """
        self.header_rules = header_rules
        self.body_rules = body_rules
        self.header_body_rules = header_body_rules
        self.attachment_rules = attachment_rules
        if header_rules:
            self.header_rules = _compile_rules(header_rules)
        if body_rules:
            self.body_rules = _compile_rules(body_rules)
        if header_body_rules:
            self.header_body_rules = _compile_rules(header_body_rules)
        if attachment_rules:
            self.attachment_rules = _compile_rules(attachment_rules)

    def scan_email(self, email: Union[str, IOBase, dict],
                   use_raw_headers=False,
                   use_raw_body=False) -> list[yara.Match]:
        """
        Sans an email using YARA rules

        Args:
            email: Email file content, a path to an email \
            file, a file-like object, or output from \
            ``mailsuite.utils.parse_email()``
            use_raw_headers: Scan headers with indentations included
            use_raw_body: Scan the raw email body instead of converting it to \
            Markdown first

        Returns: A list of rule matches
        """
        if isinstance(email, str):
            if path.exists(email):
                with open(email, "rb") as email_file:
                    email = email_file.read()
        if isinstance(email, dict):
            parsed_email = email
        else:
            parsed_email = mailsuite.utils.parse_email(email)
        if use_raw_headers:
            headers = parsed_email["raw_headers"]
        else:
            headers = parsed_email["headers_string"]
        body = ""
        if use_raw_body:
            if len(parsed_email["text_plain"]) > 0:
                body = "\n\n".join(parsed_email["text_plain"])
            if len(parsed_email["text_html"]) > 0:
                body = "\n\n".join(parsed_email["text_html"])
        else:
            body = parsed_email["body_markdown"]
        attachments = parsed_email["attachments"]

        matches = []
        if self.header_rules:
            header_matches = _match_to_dict(self.header_rules.match(
                data=headers))
            for header_match in header_matches:
                header_match["location"] = "headers"
                matches.append(header_match)
        if self.body_rules:
            body_matches = _match_to_dict(self.body_rules.match(
                data=body))
            for body_match in body_matches:
                body_match["location"] = "body"
                matches.append(body_match)
        if self.header_body_rules:
            header_body_matches = _match_to_dict(
                self.header_body_rules.match(data=f"{headers}\n\n{body}"))
            for header_body_match in header_body_matches:
                header_body_match["location"] = "header_body"
                matches.append(header_body_match)
        if self.attachment_rules:
            for attachment in attachments:
                tags = []
                payload = attachment["payload"]
                if "binary" in attachment:
                    if attachment["binary"]:
                        try:
                            payload = base64.b64decode(attachment["payload"])
                        except binascii.Error:
                            pass
                attachment_matches = _match_to_dict(
                    self.attachment_rules.match(data=payload))
                if _is_pdf(payload):
                    try:
                        pdf_markdown = _pdf_to_markdown(payload)
                        attachment_matches += _match_to_dict(
                            self.attachment_rules.match(pdf_markdown))
                        tags.append("pdf2text")
                    except Exception as e:
                        logger.warning("Unable to convert PDF to markdown. "
                                       f"{e} Scanning raw file content only"
                                       ".")
                for match in attachment_matches:
                    filename = attachment["filename"]
                    match["location"] = f"attachment:{filename}"
                    match["tags"] = list(set(match["tags"] + tags))
                    matches.append(match)
                if _is_zip(payload):
                    try:
                        with zipfile.ZipFile(BytesIO(payload)) as zip_file:
                            for name in zip_file.namelist():
                                with zip_file.open(name) as member:
                                    tags = ["zip"]
                                    location = "attachment:{}:{}".format(
                                        attachment["filename"],
                                        name
                                    )
                                    member_content = member.read()
                                    zip_matches = _match_to_dict(
                                        self.attachment_rules.match(
                                            data=member_content))
                                    for match in zip_matches:
                                        match["location"] = location
                                        match["tags"] = list(set(
                                            match["tags"] + tags))
                                        matches.append(match)

                    except Exception as e:
                        logger.warning(f"Unable to read ZIP: {e}")

        return matches
