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
    sample_path = path.join(tmp_dir, "sample.payload")
    with open(sample_path, "wb") as sample_file:
        sample_file.write(pdf_bytes)
    try:
        markdown = run(["pdf2text", "sample.payload", "-"],
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
        self._header_rules = header_rules
        self._body_rules = body_rules
        self._header_body_rules = header_body_rules
        self._attachment_rules = attachment_rules
        if header_rules:
            self._header_rules = _compile_rules(header_rules)
        if body_rules:
            self._body_rules = _compile_rules(body_rules)
        if header_body_rules:
            self._header_body_rules = _compile_rules(header_body_rules)
        if attachment_rules:
            self._attachment_rules = _compile_rules(attachment_rules)

    def _scan_pdf_text(self, payload: Union[bytes, BytesIO]) -> list[dict]:
        if isinstance(payload, BytesIO):
            payload = payload.read()
        if not _is_pdf(payload):
            raise ValueError("Payload is not a PDF file")
        pdf_markdown = _pdf_to_markdown(payload)
        markdown_matches = _match_to_dict(
            self._attachment_rules.match(pdf_markdown))
        for match in markdown_matches:
            tags = match["tags"].copy()
            tags.append("pdf2text")
            match["tags"] = list(set(tags))

        return markdown_matches

    def _scan_zip(self, filename: str, payload: Union[bytes, BytesIO],
                  _current_depth: int = 0, max_depth: int = 4):
        if isinstance(payload, bytes):
            if not _is_zip(payload):
                raise ValueError("Payload is not a ZIP file")
            _current_depth += 1
            zip_matches = []
            payload = BytesIO(payload)
            with zipfile.ZipFile(payload) as zip_file:
                for name in zip_file.namelist():
                    with zip_file.open(name) as member:
                        tags = ["zip"]
                        location = "{}:{}".format(filename, name)
                        member_content = member.read()
                        matches = _match_to_dict(
                            self._attachment_rules.match(
                                data=member_content))
                        for match in matches:
                            if "location" in match:
                                existing_location = match["location"]
                                location = f"{existing_location}:{location}"
                            match["location"] = location
                        zip_matches += matches
                        if _is_pdf(member_content):
                            try:
                                zip_matches += self._scan_pdf_text(
                                    member_content)
                            except Exception as e:
                                logger.warning(
                                    "Unable to convert PDF to markdown. "
                                    f"{e} Scanning raw file content only"
                                    ".")
                        elif _is_zip(member_content):
                            if not _current_depth > max_depth:
                                cd = _current_depth
                                md = max_depth
                                zip_matches += self._scan_zip(name,
                                                              member_content,
                                                              _current_depth=cd,
                                                              max_depth=md)
                        for match in zip_matches:
                            match["tags"] = list(set(match["tags"] + tags))

                        return zip_matches

    def _scan_attachments(self, attachments: Union[list, dict],
                          max_zip_depth: int = 4) -> list[dict]:
        attachment_matches = []
        if isinstance(attachments, dict):
            attachments = [attachments]
        for attachment in attachments:
            filename = attachment["filename"]
            payload = attachment["payload"]
            if "binary" in attachment:
                if attachment["binary"]:
                    try:
                        payload = base64.b64decode(attachment["payload"])
                    except binascii.Error:
                        pass
            attachment_matches += _match_to_dict(
                self._attachment_rules.match(data=payload))
            if _is_pdf(payload):
                try:
                    attachment_matches += self._scan_pdf_text(payload)
                except Exception as e:
                    logger.warning("Unable to convert PDF to markdown. "
                                   f"{e} Scanning raw file content only"
                                   ".")
            elif _is_zip(payload):
                attachment_matches += self._scan_zip(filename, payload,
                                                     max_depth=max_zip_depth)
            for match in attachment_matches:
                base_location = f"attachment:{filename}"
                if "location" in match:
                    og_location = match["location"]
                    match["location"] = f"{base_location}:{og_location}"
                else:
                    match["location"] = base_location

        return attachment_matches

    def scan_email(self, email: Union[str, IOBase, dict],
                   use_raw_headers: bool = False,
                   use_raw_body: bool = False,
                   max_zip_depth: int = 4) -> list[dict]:
        """
        Sans an email using YARA rules

        Args:
            email: Email file content, a path to an email \
            file, a file-like object, or output from \
            ``mailsuite.utils.parse_email()``
            use_raw_headers: Scan headers with indentations included
            use_raw_body: Scan the raw email body instead of converting it to \
            Markdown first
            max_zip_depth: Number of times to recurse into nested ZIP files

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
        if self._header_rules:
            header_matches = _match_to_dict(self._header_rules.match(
                data=headers))
            for header_match in header_matches:
                header_match["location"] = "headers"
                matches.append(header_match)
        if self._body_rules:
            body_matches = _match_to_dict(self._body_rules.match(
                data=body))
            for body_match in body_matches:
                body_match["location"] = "body"
                matches.append(body_match)
        if self._header_body_rules:
            header_body_matches = _match_to_dict(
                self._header_body_rules.match(data=f"{headers}\n\n{body}"))
            for header_body_match in header_body_matches:
                header_body_match["location"] = "header_body"
                matches.append(header_body_match)
        if self._attachment_rules:
            matches += self._scan_attachments(attachments,
                                              max_zip_depth=max_zip_depth)

        return matches
