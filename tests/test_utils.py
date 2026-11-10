"""Tests for mailsuite.utils."""

from __future__ import annotations

import base64
import email
import email.feedparser
import email.utils
import glob
import logging
import os
import random
import shutil
import subprocess
import tempfile
import time
import tracemalloc

import mailparser
import mailparser.exceptions
import pytest

import mailsuite.utils
from mailsuite.utils import (
    MAX_HEADER_FIELD_LENGTH,
    MAX_HEADER_LINES,
    MAX_MIME_PARTS,
    MAX_PART_DEPTH,
    MessageLimitExceeded,
    check_message_limits,
    create_email,
    decode_base64,
    from_trusted_domain,
    get_filename_safe_string,
    is_outlook_msg,
    parse_authentication_results,
    parse_dkim_signature,
    parse_email,
    parse_email_address,
    url_regex,
)


class TestDecodeBase64:
    def test_padded(self):
        assert decode_base64("aGVsbG8=") == b"hello"

    def test_unpadded(self):
        assert decode_base64("aGVsbG8") == b"hello"

    def test_empty(self):
        assert decode_base64("") == b""

    def test_unicode_payload(self):
        encoded = base64.b64encode("héllo".encode()).decode().rstrip("=")
        assert decode_base64(encoded) == "héllo".encode()


class TestGetFilenameSafeString:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("hello world", "hello world"),
            ("a/b\\c:d*e?f<g>h|i", "abcdefghi"),
            ("with\nnewlines\rhere", "withnewlineshere"),
            ('"quoted"', "quoted"),
            ("trailing.", "trailing"),
        ],
    )
    def test_invalid_chars(self, raw, expected):
        assert get_filename_safe_string(raw) == expected

    def test_truncation(self):
        s = "x" * 300
        assert get_filename_safe_string(s, max_length=50) == "x" * 50

    def test_none_becomes_string(self):
        assert get_filename_safe_string(None) == "None"


class TestParseEmailAddress:
    def test_string_with_display_name(self):
        result = parse_email_address("Alice <alice@example.com>")
        assert result["display_name"] == "Alice"
        assert result["address"] == "alice@example.com"
        assert result["local"] == "alice"
        assert result["domain"] == "example.com"
        assert result["sld"] == "example.com"
        assert result["compliant"] is True

    def test_bare_address(self):
        result = parse_email_address("alice@example.com")
        assert result["display_name"] is None
        assert result["address"] == "alice@example.com"
        assert result["domain"] == "example.com"
        assert result["compliant"] is True

    def test_tuple_input(self):
        result = parse_email_address(("Alice", "alice@example.com"))
        assert result["display_name"] == "Alice"
        assert result["domain"] == "example.com"

    def test_subdomain_sld(self):
        result = parse_email_address("user@mail.sub.example.co.uk")
        assert result["domain"] == "mail.sub.example.co.uk"
        assert result["sld"] == "example.co.uk"

    def test_uppercase_normalized(self):
        result = parse_email_address("USER@EXAMPLE.COM")
        assert result["local"] == "user"
        assert result["domain"] == "example.com"

    def test_non_compliant_recovery(self):
        # parseaddr returns ("","") on garbage; we fall back to manual split
        result = parse_email_address("garbage <weird@@example.com>")
        assert result["compliant"] is False or result["address"] != ""

    def test_invalid_type_raises_type_error(self):
        # Neither str nor tuple — must raise a clear TypeError, not UnboundLocalError
        with pytest.raises(TypeError):
            parse_email_address(None)  # type: ignore[arg-type]


class TestIsOutlookMsg:
    def test_recognises_ole_signature(self):
        ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24
        assert is_outlook_msg(ole) is True

    def test_rejects_plain_text(self):
        assert is_outlook_msg(b"From: a@b.c\r\n\r\nbody") is False

    def test_rejects_non_bytes(self):
        assert is_outlook_msg("string-not-bytes") is False  # type: ignore[arg-type]


class TestCreateEmail:
    def test_minimal(self):
        msg = create_email(message_from="a@example.com", message_to=["b@example.org"])
        assert "From: a@example.com" in msg
        assert "To: b@example.org" in msg
        assert "Date: " in msg

    def test_subject_and_bodies(self):
        msg = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            subject="Hi",
            plain_message="plain body",
            html_message="<p>html body</p>",
        )
        assert "Subject: Hi" in msg
        assert "plain body" in msg
        assert "<p>html body</p>" in msg

    def test_cc_recipients(self):
        msg = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            message_cc=["c@example.org", "d@example.org"],
        )
        assert "Cc: c@example.org, d@example.org" in msg

    def test_empty_cc_list_omits_header(self):
        # An empty Cc list must not emit a bare "Cc:" header (matches To).
        msg = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            message_cc=[],
        )
        assert "Cc:" not in msg

    def test_custom_headers(self):
        msg = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            message_headers={"X-Custom": "yes", "List-Unsubscribe": "<mailto:u@x>"},
        )
        assert "X-Custom: yes" in msg
        assert "List-Unsubscribe: <mailto:u@x>" in msg

    def test_attachments(self):
        msg = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            attachments=[("hello.txt", b"hello world")],
        )
        # multipart with the attachment present
        assert "hello.txt" in msg
        assert 'Content-Disposition: attachment; filename="hello.txt"' in msg


class TestParseEmail:
    @pytest.mark.parametrize(
        "sender",
        [
            "Admin <admin@[IPv6:2001:db8::1]>",
            "a@[IPv6:2001:db8::1]",
            '"Alice" <a@example.com> trailing',
            "Alice <a@example.com>",
        ],
    )
    def test_from_is_independent_of_line_endings(self, sender):
        lines = [f"From: {sender}", "Subject: Test", "", "Body", ""]
        crlf = parse_email("\r\n".join(lines))["from"]
        lf = parse_email("\n".join(lines))["from"]

        assert crlf == lf
        assert all("\r" not in crlf[field] for field in ("address", "domain", "sld"))

    def test_basic_message(self, sample_email_str):
        parsed = parse_email(sample_email_str)
        assert parsed["from"]["address"] == "sender@example.com"
        assert parsed["from"]["domain"] == "example.com"
        assert parsed["subject"] == "Hello"
        assert parsed["to"][0]["address"] == "recipient@example.org"
        assert parsed["body"].strip() == "Hello world"
        assert parsed["filename_safe_subject"] == "Hello"
        assert parsed["automatic_reply"] is False

    def test_bytes_input(self, sample_email_str):
        parsed = parse_email(sample_email_str.encode())
        assert parsed["subject"] == "Hello"

    def test_invalid_input_type(self):
        with pytest.raises(TypeError):
            parse_email(12345)  # type: ignore[arg-type]

    def test_non_email_input_raises_value_error(self):
        # mail-parser 4.6.2 returns a header-less dict for unparseable
        # input instead of the input string; both shapes must raise
        # ValueError, not TypeError (#61).
        with pytest.raises(ValueError, match="Not an email"):
            parse_email(b"\x00\x01 not an email")

    def test_missing_from_header_does_not_raise(self, caplog):
        raw = (
            "To: b@example.org\r\n"
            "Subject: No sender\r\n"
            "\r\n"
            "body\r\n"
        )
        with caplog.at_level(logging.WARNING, logger="mailsuite.utils"):
            parsed = parse_email(raw)
        assert parsed["from"] is None
        assert "from header could not be parsed" in caplog.text

    def test_html_body_extracted(self):
        raw = (
            "From: a@example.com\r\n"
            "To: b@example.org\r\n"
            "Subject: HTML test\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<p>Hello <b>world</b></p>\r\n"
        )
        parsed = parse_email(raw)
        assert "Hello" in parsed["body"]
        assert "Hello" in parsed["body_markdown"]

    def _msg_with_headers(self, extra_headers: str) -> str:
        return (
            "From: a@example.com\r\n"
            "To: b@example.org\r\n"
            "Subject: Out of office\r\n"
            f"{extra_headers}"
            "\r\n"
            "I'm away.\r\n"
        )

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            # Exchange / Microsoft 365 Out-of-Office
            ("Auto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\n", True),
            # Gmail vacation responder
            ("Auto-Submitted: auto-replied\r\n", True),
            # Auto-Submitted with a parameter (RFC 3834 syntax)
            ("Auto-Submitted: auto-generated; type=vacation\r\n", True),
            # X-Auto-Response-Suppress alone (Exchange secondary signal)
            ("X-Auto-Response-Suppress: OOF\r\n", True),
            # Explicitly human-submitted
            ("Auto-Submitted: no\r\n", False),
            # No auto-reply headers at all
            ("", False),
        ],
    )
    def test_automatic_reply_detection(self, headers, expected):
        parsed = parse_email(self._msg_with_headers(headers))
        assert parsed["automatic_reply"] is expected

    def test_reply_to_preserved(self):
        raw = (
            "From: Alice <alice@example.com>\r\n"
            "Reply-To: Carol <carol@example.com>, dave@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: Hello\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)
        addresses = {addr["address"] for addr in parsed["reply-to"]}
        assert addresses == {"carol@example.com", "dave@example.com"}

    def test_subject_with_regex_metacharacters(self):
        # A subject containing backslash sequences must not be treated as a
        # regex replacement (previously raised re.error / corrupted the value).
        for subject in (r"Backup \1 done", r"Price \g<0> off", r"100\% \8 \k"):
            raw = (
                "From: a@example.com\r\n"
                "To: b@example.org\r\n"
                f"Subject: {subject}\r\n"
                "\r\n"
                "body\r\n"
            )
            parsed = parse_email(raw)
            assert parsed["subject"] == subject
            assert f"Subject: {subject}" in parsed["headers_string"]


class TestParseAuthenticationResults:
    def test_string_input(self):
        header = (
            "mx.example.com; spf=pass smtp.mailfrom=user@example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        )
        result = parse_authentication_results(header)
        assert isinstance(result, dict)
        assert result["spf"]["result"] == "pass"
        assert result["dkim"]["result"] == "pass"
        assert result["dkim"]["header.d"] == "example.com"
        assert result["dmarc"]["result"] == "pass"

    def test_list_input(self):
        headers = [
            "mx.example.com; spf=pass smtp.mailfrom=user@example.com",
            "mx.example.com; dkim=pass header.d=example.com",
        ]
        results = parse_authentication_results(headers)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_dmarc_header_from_inferred(self):
        header = "mx.example.com; dmarc=pass action=none"
        result = parse_authentication_results(header, from_domain="example.com")
        assert result["dmarc"]["header.from"] == "example.com"
        assert result["dmarc"]["disp"] == "none"

    def test_invalid_input(self):
        with pytest.raises(ValueError):
            parse_authentication_results(123)  # type: ignore[arg-type]


class TestParseDkimSignature:
    def test_string_input(self):
        sig = (
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; "
            "s=ms1; h=From:To:Subject; bh=abc; b=def"
        )
        parsed = parse_dkim_signature(sig)
        assert isinstance(parsed, dict)
        assert parsed["d"] == "example.com"
        assert parsed["s"] == "ms1"
        assert parsed["h"] == ["From", "To", "Subject"]

    def test_list_input(self):
        sigs = [
            "v=1; d=example.com; s=ms1; h=From",
            "v=1; d=example.org; s=ms2; h=From",
        ]
        parsed = parse_dkim_signature(sigs)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_folded_header(self):
        # Headers may be wrapped onto multiple lines
        sig = "v=1; a=rsa-sha256;\r\n  d=example.com; s=ms1"
        parsed = parse_dkim_signature(sig)
        assert isinstance(parsed, dict)
        assert parsed["d"] == "example.com"

    def test_invalid_input(self):
        with pytest.raises(ValueError):
            parse_dkim_signature(123)  # type: ignore[arg-type]


class TestFromTrustedDomain:
    def _msg_with_dmarc_pass(self, domain: str = "example.com") -> str:
        return (
            f"From: a@{domain}\r\n"
            "To: b@example.org\r\n"
            f"Authentication-Results: mx.example.org; dkim=pass header.d={domain}; "
            f"dmarc=pass header.from={domain}\r\n"
            "Subject: hi\r\n\r\nbody\r\n"
        )

    def test_trusted_exact(self):
        msg = self._msg_with_dmarc_pass("example.com")
        assert from_trusted_domain(msg, ["example.com"]) is True

    def test_untrusted(self):
        msg = self._msg_with_dmarc_pass("evil.example")
        assert from_trusted_domain(msg, ["example.com"]) is False

    def test_sld_match(self):
        msg = self._msg_with_dmarc_pass("mail.example.com")
        assert from_trusted_domain(msg, ["example.com"], include_sld=True) is True

    def test_sld_disabled(self):
        msg = self._msg_with_dmarc_pass("mail.example.com")
        assert from_trusted_domain(msg, ["example.com"], include_sld=False) is False

    def test_string_trusted_domains(self):
        msg = self._msg_with_dmarc_pass("example.com")
        assert from_trusted_domain(msg, "example.com") is True

    def test_no_auth_header(self):
        msg = "From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n"
        assert from_trusted_domain(msg, ["example.com"]) is False

    def test_already_parsed_dict(self):
        msg = self._msg_with_dmarc_pass("example.com")
        parsed = parse_email(msg)
        assert from_trusted_domain(parsed, ["example.com"]) is True

    # — DMARC-only dict path (existing tests match via the DKIM branch) —

    def _msg_dmarc_only(self, domain: str = "example.com") -> str:
        return (
            f"From: a@{domain}\r\n"
            "To: b@example.org\r\n"
            f"Authentication-Results: mx.example.org; dmarc=pass header.from={domain}\r\n"
            "Subject: hi\r\n\r\nbody\r\n"
        )

    def test_dmarc_only_trusted(self):
        assert from_trusted_domain(self._msg_dmarc_only("example.com"), ["example.com"]) is True

    def test_dmarc_only_untrusted(self):
        assert from_trusted_domain(self._msg_dmarc_only("evil.example"), ["example.com"]) is False

    def test_dmarc_only_sld(self):
        msg = self._msg_dmarc_only("mail.example.com")
        assert from_trusted_domain(msg, ["example.com"], include_sld=True) is True

    # — multiple Authentication-Results headers —

    def _msg_multi_ar(self, *ar_results: str) -> str:
        headers = "".join(
            f"Authentication-Results: mx.example.org; {r}\r\n" for r in ar_results
        )
        return (
            "From: a@example.com\r\nTo: b@example.org\r\n"
            f"{headers}Subject: hi\r\n\r\nbody\r\n"
        )

    def test_multiple_results_trusted(self):
        # Regression: this used to raise TypeError because parse_email returns
        # raw strings (not dicts) for multiple Authentication-Results headers.
        msg = self._msg_multi_ar(
            "spf=pass smtp.mailfrom=example.com",
            "dmarc=pass header.from=example.com",
        )
        assert (
            from_trusted_domain(
                msg, ["example.com"], allow_multiple_authentication_results=True
            )
            is True
        )

    def test_multiple_results_untrusted(self):
        msg = self._msg_multi_ar(
            "spf=pass smtp.mailfrom=evil.example",
            "dmarc=pass header.from=evil.example",
        )
        assert (
            from_trusted_domain(
                msg, ["example.com"], allow_multiple_authentication_results=True
            )
            is False
        )

    def test_multiple_results_sld(self):
        msg = self._msg_multi_ar(
            "spf=pass smtp.mailfrom=mail.example.com",
            "dmarc=pass header.from=mail.example.com",
        )
        assert (
            from_trusted_domain(
                msg,
                ["example.com"],
                include_sld=True,
                allow_multiple_authentication_results=True,
            )
            is True
        )

    def test_multiple_results_requires_flag(self):
        # Without the opt-in flag, multiple AR headers are not consulted
        msg = self._msg_multi_ar(
            "spf=pass smtp.mailfrom=example.com",
            "dmarc=pass header.from=example.com",
        )
        assert from_trusted_domain(msg, ["example.com"]) is False

    def test_multiple_results_two_dmarc_rejected(self):
        # Two DMARC stamps across the headers is ambiguous and rejected, even
        # though one of them is trusted.
        msg = self._msg_multi_ar(
            "dmarc=pass header.from=other.example",
            "dmarc=pass header.from=example.com",
        )
        assert (
            from_trusted_domain(
                msg, ["example.com"], allow_multiple_authentication_results=True
            )
            is False
        )

    # — Authentication-Results-Original (Proofpoint / Cisco gateways) —

    def _msg_ar_original(self) -> str:
        return (
            "From: a@example.com\r\nTo: b@example.org\r\n"
            "Authentication-Results: mx.example.org; "
            "dmarc=fail header.from=spoof.example\r\n"
            "Authentication-Results-Original: gw.example.org; "
            "dmarc=pass header.from=example.com\r\n"
            "Subject: hi\r\n\r\nbody\r\n"
        )

    def test_authentication_results_original_used(self):
        # With the flag, the -Original header (dmarc=pass example.com) is used
        msg = self._msg_ar_original()
        assert (
            from_trusted_domain(
                msg, ["example.com"], use_authentication_results_original=True
            )
            is True
        )

    def test_authentication_results_original_ignored_by_default(self):
        # Without the flag, the regular header (dmarc=fail spoof.example) is used
        msg = self._msg_ar_original()
        assert from_trusted_domain(msg, ["example.com"]) is False



_HEAD = (
    "From: sender@example.net\r\n"
    "To: dmarc@example.com\r\n"
    "Subject: x\r\n"
    "Date: Thu, 1 Jan 2026 00:00:00 +0000\r\n"
    "MIME-Version: 1.0\r\n"
)


def _multipart(body: str, boundary: str = "L") -> str:
    """A multipart/mixed message whose body is ``body``."""
    content_type = f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n'
    return _HEAD + content_type + "\r\n" + body


def _nested(depth: int, parts: int = 1) -> str:
    """A message nested ``depth`` parts deep, with ``parts`` parts innermost."""
    opening = "".join(
        f"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n"
        for i in range(depth - 2)
    )
    inner = (
        "Content-Type: multipart/mixed; boundary=L\n\n"
        + "--L\n\nx\n" * parts
        + "--L--\n"
    )
    closing = "".join(f"--b{i}--\n" for i in range(depth - 3, -1, -1))
    return _HEAD + opening + inner + closing


def _part_count(message: str) -> int:
    return sum(1 for _ in email.message_from_string(message).walk())


_REFERENCE_MESSAGE = _HEAD + "\r\n" + "a\r\n" * 300_000


def _budget(seconds: float = 2.0) -> float:
    """Return ``seconds``, scaled up on a machine slower than the reference.

    Some timed checks do real work at a limit (20,000,000 boundary tests,
    240 KB of addresses), so their bound must scale with the machine running
    them. The reference is ``_REFERENCE_MESSAGE`` parsed by the email
    package, 0.04 s on the workstation the bounds were written on (Python
    3.12). It is measured just before the timed call, twice, and the slower
    run sets the scale, so a brief fast moment in the reference is not taken
    as the machine's speed; a slowdown during the timed call itself is not
    covered. A faster machine keeps the written bound, and the scale is
    capped at ten, so a stall during the reference cannot hide a regression.
    """
    reference = 0.0
    for _ in range(2):
        start = time.perf_counter()
        email.message_from_string(_REFERENCE_MESSAGE)
        reference = max(reference, time.perf_counter() - start)
    return seconds * min(max(1.0, reference / 0.04), 10.0)


def _rejected_quickly(message: str | bytes, limit: str) -> None:
    budget = _budget()
    start = time.monotonic()
    with pytest.raises(MessageLimitExceeded, match=limit):
        parse_email(message)
    assert time.monotonic() - start < budget


def _parses_quickly(message: str) -> dict:
    budget = _budget()
    start = time.monotonic()
    parsed = parse_email(message)
    assert time.monotonic() - start < budget
    return parsed


class TestCheckMessageLimits:
    """GHSA-748w-c9w9-79xp: bound the structure of a message before parsing."""

    def test_exception_is_value_error(self):
        assert issubclass(MessageLimitExceeded, ValueError)

    def test_simple_message_passes(self, sample_email_str):
        assert check_message_limits(sample_email_str) is None
        assert check_message_limits(sample_email_str.encode()) is None

    def test_bytes_input_is_checked(self):
        message = (_HEAD + "X-A: b\r\n" * 4 + "\r\nbody\r\n").encode()
        with pytest.raises(MessageLimitExceeded, match="max_header_lines"):
            check_message_limits(message, max_header_lines=8)
        check_message_limits(message, max_header_lines=9)

    def test_feed_parser_internals_exist(self):
        # check_message_limits() relies on these private names
        assert callable(getattr(email.feedparser.FeedParser, "_new_message", None))
        assert isinstance(getattr(email.feedparser.FeedParser(), "_msgstack", None), list)
        assert callable(getattr(email.feedparser.FeedParser, "_parse_headers", None))
        buffer = email.feedparser.BufferedSubFile()  # pyright: ignore[reportAttributeAccessIssue]
        assert isinstance(getattr(buffer, "_eofstack", None), list)

    def test_part_count_matches_the_email_package(self):
        """Differential: for random messages the bounded parser counts
        exactly the parts email.message_from_string() builds."""
        lines = [
            "", "", "--A", "--A--", "--B", "--B--", "--A----", "--A ", "--",
            "Content-Type: multipart/mixed; boundary=A",
            "Content-Type: multipart/mixed; boundary=B",
            'Content-Type: multipart/mixed; boundary="A--"',
            "Content-Type: multipart/mixed",
            "Content-Type: message/delivery-status",
            "Content-Type: message/rfc822",
            "Content-Type: multipart/digest; boundary=B",
            "Content-Type: text/plain", "X: y", " cont", "zz", "From x",
        ]
        rng = random.Random(748)
        for _ in range(2_000):
            message = "\n".join(rng.choice(lines) for _ in range(rng.randint(3, 25)))
            parser = mailsuite.utils._BoundedFeedParser(10**9, 10**9, 10**12, 10**9)
            parser.feed(message)
            parser.close()
            assert parser.part_count == _part_count(message), message

    # — parts —

    def test_parts_at_limit_parse(self):
        message = _multipart("--L\r\n\r\nx\r\n" * (MAX_MIME_PARTS - 1) + "--L--\r\n")
        assert _part_count(message) == MAX_MIME_PARTS
        assert parse_email(message)["subject"] == "x"

    def test_parts_over_limit_rejected(self):
        message = _multipart("--L\r\n\r\nx\r\n" * MAX_MIME_PARTS + "--L--\r\n")
        with pytest.raises(
            MessageLimitExceeded, match=rf"max_parts \({MAX_MIME_PARTS}\)"
        ):
            check_message_limits(message)

    def test_delivery_status_blocks_are_parts(self):
        report = _multipart(
            "--L\r\nContent-Type: message/delivery-status\r\n\r\n"
            "Reporting-MTA: dns; mx.example.com\r\n" + "\r\n" * 10 + "--L--\r\n"
        )
        parts = _part_count(report)
        assert parts > 10
        check_message_limits(report, max_parts=parts)
        with pytest.raises(MessageLimitExceeded, match="max_parts"):
            check_message_limits(report, max_parts=parts - 1)
        plain = report.replace("message/delivery-status", "text/plain")
        check_message_limits(plain, max_parts=3)

    def test_delivery_status_blank_lines_rejected_quickly(self):
        """512 KiB of blank lines in a message/delivery-status part took
        3.7 s in parse_email on 2.3.4 (Python 3.12), one Message per line."""
        for blank in ("\n", "\r"):
            _rejected_quickly(
                _HEAD
                + "Content-Type: message/delivery-status\r\n\r\n"
                + blank * (512 * 1024),
                "max_parts",
            )

    def test_swallowed_closing_delimiter(self):
        """After a boundary line the email package skips a closing delimiter
        that follows it and keeps reading parts; a scanner that closed the
        multipart there let 4 MB of delivery-status blank lines through
        (31.7 s)."""
        message = (
            _HEAD + "Content-Type: multipart/mixed; boundary=B\n\n--B\n--B--\n"
            "Content-Type: message/delivery-status\n\n" + "\n" * 2_000_000
        )
        _rejected_quickly(message, "max_parts")
        nested = _HEAD + "Content-Type: multipart/mixed; boundary=B\n\n--B\n--B--\n"
        _rejected_quickly(nested + _nested(900, 100_000)[len(_HEAD) :], "max_depth")

    def test_boundary_of_two_open_multiparts(self):
        """A line that is the boundary of two open multiparts (``X--`` and
        ``X`` on ``--X--``) belongs to the outermost one."""
        message = (
            _HEAD + 'Content-Type: multipart/mixed; boundary="X--"\n\n--X--\n'
            'Content-Type: multipart/mixed; boundary="X"\n\n'
            "--X\nContent-Type: text/plain\n\nhi\n--X--\n"
            "Content-Type: message/delivery-status\n\nReporting-MTA: dns; mx\n"
            + "\n" * 2_000_000
        )
        _rejected_quickly(message, "max_parts")

    def test_closed_or_undeclared_boundary_does_not_end_delivery_status(self):
        head = _HEAD + 'Content-Type: multipart/report; boundary="B"\r\n\r\n'
        delivery_status = (
            "--B\r\nContent-Type: message/delivery-status\r\n\r\n"
            "Reporting-MTA: dns; mx\r\n\r\n--X\r\n"
        )
        closed = (
            '--B\r\nContent-Type: multipart/alternative; boundary="X"\r\n\r\n'
            "--X\r\nContent-Type: text/plain\r\n\r\nhi\r\n--X--\r\n"
        )
        undeclared = '--B\r\nzz\r\nContent-Type: multipart/mixed; boundary="X"\r\n\r\n'
        for first_part in (closed, undeclared):
            _rejected_quickly(
                head + first_part + delivery_status + "\r\n" * 1_500_000, "max_parts"
            )

    def test_delivery_status_block_declaring_a_multipart(self):
        block = 'Content-Type: multipart/mixed; boundary="Q"\r\n' + (
            "--Q\r\nContent-Type: text/plain\r\nx\r\n" * 33_000 + "--Q--\r\n"
        )
        _rejected_quickly(
            _HEAD + "Content-Type: message/delivery-status\r\n\r\n" + block, "max_parts"
        )

    def test_epilogue_parsed_again_by_mail_parser(self):
        """mail-parser parses the top-level epilogue again when a part has
        no start boundary; 4 MB of delivery-status blank lines there took
        17.6 s."""

        def message(blanks: int) -> str:
            return (
                _HEAD + "Content-Type: multipart/mixed; boundary=B\n\n"
                "--B\nContent-Type: multipart/mixed; boundary=Z\n\nno start here\n"
                "--B--\n--B\nContent-Type: message/delivery-status\n\n"
                + "\n" * blanks
                + "x: y\n--B--\n"
            )

        assert _part_count(message(20)) < 10
        check_message_limits(message(20))
        with pytest.raises(MessageLimitExceeded, match="max_parts"):
            check_message_limits(message(20), max_parts=10)
        _rejected_quickly(message(2_000_000), "max_parts")

    def test_epilogue_not_parsed_again_without_a_closing_delimiter(self):
        missing_start = (
            "--B\nContent-Type: multipart/mixed; boundary=Z\n\nno start here\n"
        )
        blanks = "Content-Type: message/delivery-status\n\n" + "\n" * 20
        top = _HEAD + "Content-Type: multipart/mixed; boundary=B\n\n"
        for message in (
            top + missing_start,  # the top level never closes: no epilogue
            top + "no parts at all\n",  # an empty epilogue
            top + missing_start + "--B--\n" + blanks,  # no --B in the epilogue
            top + missing_start + "--B--\n--B\n" + blanks,  # no --B-- after it
        ):
            check_message_limits(message, max_parts=10)

    # — depth —

    def test_depth_at_limit_parses(self):
        message = _nested(MAX_PART_DEPTH)
        assert parse_email(message)["subject"] == "x"

    def test_depth_over_limit_rejected(self):
        with pytest.raises(
            MessageLimitExceeded, match=rf"max_depth \({MAX_PART_DEPTH}\)"
        ):
            check_message_limits(_nested(MAX_PART_DEPTH + 1))

    def test_embedded_messages_count_toward_depth(self):
        message = _HEAD + "Content-Type: message/rfc822\r\n\r\n" * 5 + "From: a@b\r\n\r\nx\r\n"
        check_message_limits(message, max_depth=6)
        with pytest.raises(MessageLimitExceeded, match="max_depth"):
            check_message_limits(message, max_depth=5)

    def test_nested_multiparts_rejected_quickly(self):
        """900 nested multiparts around 30,000 parts took 5.5 s in
        parse_email on 2.3.4 (Python 3.12)."""
        _rejected_quickly(_nested(901, parts=30_000), "max_depth")

    # — address headers mail-parser parses —

    def test_address_header_chars_at_and_over_limit(self):
        to = "To: " + ", ".join(f"u{i}@example.com" for i in range(500)) + "\r\n"
        cc = "Cc: " + ", ".join(f"c{i}@example.com" for i in range(500)) + "\r\n"
        message = _HEAD + to + cc + "Resent-To: r@example.com\r\n\r\nbody\r\n"
        names = {"from", "reply-to", "to", "cc", "bcc", "delivered-to", "sender"}
        assert mailsuite.utils._address_header_names == names
        parser = email.message_from_string(message)
        chars = sum(
            len(value) for name, value in parser.raw_items() if name.lower() in names
        )
        check_message_limits(message, max_address_header_chars=chars)
        with pytest.raises(MessageLimitExceeded, match="max_address_header_chars"):
            check_message_limits(message, max_address_header_chars=chars - 1)
        parsed = parse_email(message)
        assert len(parsed["to"]) == 500 and len(parsed["cc"]) == 500

    def test_address_headers_counted_in_every_part_and_only_those(self):
        flood = ";" * 60_000
        not_counted = _HEAD + "".join(f"Return-Path: {flood}\r\n" for _ in range(8))
        check_message_limits(not_counted + "\r\nbody\r\n")
        embedded = "".join(f"To: {flood}\r\n" for _ in range(5))
        message = _HEAD + "Content-Type: message/rfc822\r\n\r\n" + embedded + "\r\nx\r\n"
        with pytest.raises(MessageLimitExceeded, match="max_address_header_chars"):
            check_message_limits(message)

    def test_malformed_address_flood_rejected_quickly(self):
        """64 To fields of 64,000 ``;`` (4.1 MB) cost mail-parser 10.9 s and
        1.83 GB, one diagnostic per malformed item."""
        fields = "".join("To: " + ";" * 64_000 + "\r\n" for _ in range(64))
        _rejected_quickly("From: a@b\r\n" + fields + "\r\nbody\r\n", "max_address")

    # — boundary tests —

    def test_boundary_tests_at_and_over_limit(self):
        message = _nested(4, parts=20)
        parser = mailsuite.utils._BoundedFeedParser(10**9, 10**9, 10**12, 10**9)
        parser.feed(message)
        parser.close()
        tests = parser._input.test_count
        assert tests > 20
        check_message_limits(message, max_boundary_tests=tests)
        with pytest.raises(MessageLimitExceeded, match="max_boundary_tests"):
            check_message_limits(message, max_boundary_tests=tests - 1)

    def test_deep_nesting_around_many_lines_rejected_quickly(self):
        """The parser tests every line against each open boundary: 99
        nested multiparts around 4 MB of two-byte lines took 4.8 s in the
        email package alone."""
        opening = "".join(
            f"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n" for i in range(99)
        )
        message = _HEAD + opening + "Content-Type: text/plain\n\n" + "a\n" * 2_097_152
        _rejected_quickly(message, "max_boundary_tests")

    # — header fields —

    def test_header_field_at_limit_passes(self):
        line = "X-Long: " + "a" * (MAX_HEADER_FIELD_LENGTH - 7) + "\r\n"
        check_message_limits(_HEAD + line + "\r\nbody\r\n")

    def test_header_field_over_limit_rejected(self):
        line = "X-Long: " + "a" * (MAX_HEADER_FIELD_LENGTH - 6) + "\r\n"
        with pytest.raises(
            MessageLimitExceeded,
            match=rf"max_header_field_length \({MAX_HEADER_FIELD_LENGTH}\)",
        ):
            check_message_limits(_HEAD + line + "\r\nbody\r\n")

    def test_folded_header_field_counts_continuation_lines(self):
        folded = "To: a@x" + ",\r\n a@x" * 5
        raw_length = len(folded) - len("To: ") + len("To:")
        check_message_limits(folded + "\r\n\r\nbody", max_header_field_length=raw_length)
        with pytest.raises(MessageLimitExceeded, match="max_header_field_length"):
            check_message_limits(
                folded + "\r\n\r\nbody", max_header_field_length=raw_length - 1
            )

    def test_header_fields_at_limit_parse(self):
        flood = "X-A: b\r\n" * (MAX_HEADER_LINES - 5)
        assert parse_email(_HEAD + flood + "\r\nbody\r\n")["subject"] == "x"

    def test_header_fields_over_limit_rejected(self):
        flood = "X-A: b\r\n" * (MAX_HEADER_LINES - 4)
        with pytest.raises(
            MessageLimitExceeded, match=rf"max_header_lines \({MAX_HEADER_LINES}\)"
        ):
            check_message_limits(_HEAD + flood + "\r\nbody\r\n")

    def test_header_fields_of_every_part_are_counted(self):
        message = _multipart("--L\r\n" + "X-A: b\r\n" * 10 + "\r\nx\r\n--L--\r\n")
        check_message_limits(message, max_header_lines=16)
        with pytest.raises(MessageLimitExceeded, match="max_header_lines"):
            check_message_limits(message, max_header_lines=15)

    def test_header_lines_kept_as_defects_are_counted(self):
        """4 MB of ``:x`` lines, which the parser keeps as defects rather
        than fields, passed an earlier check and cost 3.07 s and 523 MB."""
        for line in (":x", "From x", " x"):
            message = _HEAD + f"{line}\r\n" * 10 + "\r\nbody\r\n"
            check_message_limits(message, max_header_lines=15)
            with pytest.raises(MessageLimitExceeded, match="max_header_lines"):
                check_message_limits(message, max_header_lines=14)
        for line in (":x", "From x"):
            flood = _HEAD + f"{line}\r\n" * (4 * 1024 * 1024 // (len(line) + 2))
            _rejected_quickly(flood + "\r\nbody\r\n", "max_header_lines")

    def test_header_flood_rejected_quickly(self):
        """A 4 MiB header flood took 1.1 s in parse_email on 2.3.4 (Python 3.12)."""
        _rejected_quickly(
            _HEAD + "X-A: b\r\n" * (4 * 1024 * 1024 // 8) + "\r\nbody\r\n",
            "max_header_lines",
        )

    def test_lines_parse_email_reads_as_header_text(self):
        """parse_email() reads everything before the first blank line as the
        header block; a To: group there that the email package does not
        take as a field took 46-50 s on 2.3.4 and is now not read as To."""
        group = "g:" + ",".join("a@x" for _ in range(250_000)) + ";"
        for message in (
            _HEAD + f"x y To: {group}\r\n\r\nbody\r\n",
            f" To: {group}\r\n" + _HEAD + "\r\nbody\r\n",
            _HEAD + f"(c) To: {group}\r\n\r\nbody\r\n",
        ):
            parsed = _parses_quickly(message)
            assert [to["address"] for to in parsed["to"]] == ["dmarc@example.com"]
        # Unfolded by parse_email() but not by the email package
        message = _HEAD.replace("To: dmarc@example.com", f"To: a@x\r\n\x0b{group}")
        _rejected_quickly(message, "to header exceeds max_header_field_length")

    def test_whitespace_lines_continue_a_field(self):
        chunk = "X: " + ",".join(["a@x"] * 15_000) + "\n \n"
        message = "Subject: s\nTo: g:\n \n" + chunk * 20 + "Z: z\n\nbody\n"
        _rejected_quickly(message, "max_header_field_length")

    def test_cr_only_message_with_long_address_header(self):
        line = "X-A: " + ",".join(["a@x"] * 14) + "\r"
        # parse_email() reads the rest of the message as the From value
        message = "From: a@b\rTo: g:\r" + line * 20_000 + "\rbody\r"
        check_message_limits(message)
        _rejected_quickly(message, "from header exceeds max_header_field_length")
        assert parse_email("Subject: s\rTo: c@d.com\r\rhello\r")["subject"] == "s"

    def test_subject_is_replaced_once_in_the_header_text(self):
        """Every ``Subject:`` in the header text was replaced with the full
        subject: 60 KB of subject and 4,000 more ``Subject: a`` lines took
        490 MB, 30,000 raised MemoryError."""
        subject = "s" * 60_000
        message = (
            _HEAD.replace("Subject: x", f"Subject: {subject}")
            + "zz\r\n"
            + "Subject: a\r\n" * 30_000
            + "\r\nbody\r\n"
        )
        topics = "".join(f"Thread-Topic: t{i}\r\n" for i in range(30_000))
        for text in (message, _HEAD + topics + "\r\nbody\r\n"):
            tracemalloc.start()
            try:
                parsed = _parses_quickly(text)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            assert peak < 100 * 1024 * 1024
        assert parsed["headers_string"].count("Thread-Topic: t0") == 1
        assert "Thread-Topic: t1\r\n" in parsed["headers_string"]
        assert parsed["headers_string"].count("Thread-Topic: ") == 30_000
        parsed = parse_email(message)
        assert parsed["subject"] == subject
        assert parsed["headers_string"].count(subject) == 1

    def test_only_the_subject_field_is_replaced(self):
        message = (
            "From: a@example.com\r\nTo: b@example.org\r\n"
            "X-Original-Subject: old\r\nSubject: =?utf-8?q?new?=\r\n\r\nbody\r\n"
        )
        lines = parse_email(message)["headers_string"].split("\r\n")
        assert lines[-2:] == ["X-Original-Subject: old", "Subject: new"]

    def test_repeated_subject_uses_the_first(self):
        message = (
            "From: a@example.com\r\nSubject: one\r\nSubject: two\r\n"
            "Thread-Topic: t1\r\nThread-Topic: t2\r\n\r\nbody\r\n"
        )
        parsed = parse_email(message)
        assert parsed["subject"] == "one"
        assert parsed["filename_safe_subject"] == "one"
        assert parsed["thread-topic"] == "t1"

    def test_subject_field_name_in_any_case(self):
        for field in (
            "subject: =?utf-8?q?new?=",
            "Subject:=?utf-8?q?new?=",
            "Subject:\t=?utf-8?q?new?=",
        ):
            message = f"From: a@example.com\r\n{field}\r\nX-A: b\r\n\r\nbody\r\n"
            lines = parse_email(message)["headers_string"].split("\r\n")
            assert lines[1:] == ["Subject: new", "X-A: b"], field

    def test_subject_keeps_its_terminator_and_the_next_line(self):
        message = (
            "From: a@example.com\r\nSubject: =?utf-8?q?a=0Db?=\r\n"
            "To: b@example.org\r\n\r\nbody\r\n"
        )
        parsed = parse_email(message)
        assert "\r\nSubject: a b\r\nTo: b@example.org" in parsed["headers_string"]
        assert "\r" not in parsed["headers_string"].split("\r\n")[1]
        assert [to["address"] for to in parsed["to"]] == ["b@example.org"]

    def test_decoded_line_break_does_not_add_a_header(self):
        """An encoded word decoding to a line break wrote a header of the
        sender's choosing into the header text parse_email() reads back."""
        for name in ("Subject", "Thread-Topic"):
            message = (
                "From: a@example.com\r\nTo: real@example.org\r\n"
                f"{name}: =?utf-8?q?hi=0ATo:_evil@attacker.example=0D=0AX:_y?=\r\n"
                "\r\nbody\r\n"
            )
            parsed = parse_email(message)
            assert [to["address"] for to in parsed["to"]] == ["real@example.org"]
            lines = parsed["headers_string"].splitlines()
            assert not any(line.startswith("To: evil") for line in lines)
        folded = "From: a@example.com\r\nSubject: one\r\n two\r\n\r\nbody\r\n"
        lines = parse_email(folded)["headers_string"].split("\r\n")
        assert lines[-1].startswith("Subject: one") and lines[-1].endswith("two")

    def test_deeply_nested_comment_in_address(self):
        value = "(" * 900 + ")" * 900 + "a@x"
        message = f"From: a@b\nTo: {value}\nSubject: s\n\nbody\n"
        with pytest.raises(MessageLimitExceeded, match="nested too deeply"):
            parse_email(message)

    def test_sample_messages_parse(self):
        # parsedmarc's samples/ directory, for one
        samples = os.environ.get("MAILSUITE_SAMPLE_DIR")
        if not samples:
            pytest.skip("MAILSUITE_SAMPLE_DIR is not set")
        paths = glob.glob(os.path.join(samples, "**", "*.eml"), recursive=True)
        assert paths
        for path in paths:
            with open(path, "rb") as sample:
                assert isinstance(parse_email(sample.read()), dict), path

    def test_digest_and_delivery_status_report_parse(self):
        digest = "".join(
            f"--D\r\n\r\nFrom: u{i}@x\r\nSubject: m{i}\r\n\r\nbody {i}\r\n\r\n"
            for i in range(50)
        )
        message = _HEAD + 'Content-Type: multipart/digest; boundary="D"\r\n\r\n'
        assert parse_email(message + digest + "--D--\r\n")["subject"] == "x"
        report = _multipart(
            "--L\r\nContent-Type: text/plain\r\n\r\nfailed\r\n"
            "--L\r\nContent-Type: message/delivery-status\r\n\r\n"
            "Reporting-MTA: dns; mx\r\n\r\nFinal-Recipient: rfc822; x@y\r\n"
            "Action: failed\r\nStatus: 5.1.1\r\n\r\n--L--\r\n"
        )
        assert parse_email(report)["subject"] == "x"

    def test_long_body_lines_pass(self):
        html = "<html><head><style>body{margin:0}</style></head><body>" + (
            "<div class='c'>x</div>" * 8_000
        )
        records = ",".join(f'{{"id":{i},"v":"0.5"}}' for i in range(6_000))
        json_line = f"[{records}]"
        for content_type, body in (
            ("text/html", html),
            ("text/plain", json_line),
            ("text/plain", "PGh0bWw+" * 30_000),
        ):
            assert len(body) > MAX_HEADER_FIELD_LENGTH
            message = _HEAD + f"Content-Type: {content_type}\r\n\r\n{body}\r\n"
            check_message_limits(message)
            assert parse_email(message)["raw_body"].strip() == body

    def test_60_kib_header_line_parses(self):
        value = "a" * (60 * 1024)
        parsed = parse_email(_HEAD + f"X-Long: {value}\r\n\r\nbody\r\n")
        assert parsed["x-long"] == value

    def test_header_like_body_lines_are_not_counted(self):
        cron = "".join(
            f"2026-01-01T00:00:{i % 60:02d}Z host: event {i}\r\n"
            for i in range(MAX_HEADER_LINES + 50_000)
        )
        quoted_printable = "".join(
            f"Line{i}: value=3D{i}=\r\n" for i in range(MAX_HEADER_LINES + 10_000)
        )
        for headers, body in (
            ("", cron),
            ("Content-Transfer-Encoding: quoted-printable\r\n", quoted_printable),
        ):
            message = _HEAD + headers + "\r\n" + body
            check_message_limits(message)
            assert parse_email(message)["subject"] == "x"

    def test_text_body_with_many_blank_lines_parses(self):
        body = "".join(f"a,b,c,{i}\r\n\r\n" for i in range(110_000))
        message = _HEAD + "\r\n" + body
        check_message_limits(message)
        assert parse_email(message)["subject"] == "x"

    def test_signature_and_comment_lines_parse(self):
        body = "-- \r\n-- SQL comment\r\n" * 5_500
        message = _HEAD + "\r\n" + body
        check_message_limits(message)
        assert parse_email(message)["subject"] == "x"

    def test_address_groups_without_commas_parse_quickly(self):
        """A group of 16,000 members took 0.15 s to parse however they are
        separated, so seven address headers of such groups cost seconds."""
        for members in (
            " ".join("a@x" for _ in range(15_000)),
            "".join("<a@x>" for _ in range(12_000)),
            ",".join("a" for _ in range(30_000)),
        ):
            group = f"g:{members};"
            names = ("From", "Sender", "Delivered-To", "To", "Cc", "Bcc", "Reply-To")
            # Seven such headers exceed max_address_header_chars; four fit
            headers = "".join(f"{name}: {group}\r\n" for name in names)
            _rejected_quickly("Subject: s\r\n" + headers + "\r\nb\r\n", "max_address")
            headers = "".join(f"{name}: {group}\r\n" for name in names[3:])
            _parses_quickly("Subject: s\r\n" + headers + "\r\nbody\r\n")

    def test_long_groups_lose_group_syntax_and_parse_under_bound(self):
        """Seven headers each of these three groups took 5.0 s to parse
        with their group syntax kept."""
        budget = _budget(2.5)
        start = time.monotonic()
        for members in (
            " ".join("a@x" for _ in range(15_000)),
            "".join("<a@x>" for _ in range(12_000)),
            ",".join("a" for _ in range(30_000)),
        ):
            value, literals = mailsuite.utils._without_address_groups(f"g:{members};")
            assert literals == {}
            assert ":" not in value and ";" not in value
            for _ in range(7):
                email.utils.getaddresses([value])
        assert time.monotonic() - start < budget

    def test_group_hidden_after_a_route_address_parses_quickly(self):
        # email.utils ends a route address one character after its address,
        # so the group here is outside any angle brackets to it
        group = '<a@x" g:' + ",".join("a@x" for _ in range(15_000)) + ";"
        budget = _budget()
        start = time.monotonic()
        parse_email(f"From: a@x\r\nTo: {group}\r\nSubject: s\r\n\r\nbody\r\n")
        assert time.monotonic() - start < budget

    def test_long_address_list_keeps_every_address(self):
        names = ", ".join(f'"Last{i}, First" <u{i}@example.com>' for i in range(1_001))
        parsed = parse_email(f"From: a@x\r\nTo: {names}\r\nSubject: s\r\n\r\nb\r\n")
        assert len(parsed["to"]) == 1_001
        assert parsed["to"][1_000]["display_name"] == "Last1000, First"
        assert parsed["to"][1_000]["address"] == "u1000@example.com"

    def test_long_group_is_read_as_its_members(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = f'Team: "A; B" <a@example.com>, (c;) b@example.com; {padding}'
        assert len(value) > mailsuite.utils._ADDRESS_GROUP_PARSE_LIMIT
        parsed = parse_email(f"From: a@x\r\nTo: {value}\r\nSubject: s\r\n\r\nb\r\n")
        addresses = [address["address"] for address in parsed["to"]]
        assert addresses[:3] == ["a@example.com", "b@example.com", "u0@example.com"]
        assert parsed["to"][0]["display_name"] == "A; B"
        assert len(addresses) == 602

    def test_group_syntax_inside_quotes_and_comments_is_text(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = (
            'G: "x\\" y; z" <a@example.com>;, (c (d; e) f) b@example.com, H:;, '
            + padding
        )
        stripped, literals = mailsuite.utils._without_address_groups(value)
        assert literals == {}
        assert stripped.startswith(
            ' "x\\" y; z" <a@example.com>, (c (d; e) f) b@example.com,, u0@'
        )
        addresses = email.utils.getaddresses([stripped])
        assert addresses[:2] == [
            ('x" y; z', "a@example.com"),
            ("c d; e f", "b@example.com"),
        ]

    def test_long_value_keeps_domain_literals(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = f"Admin <admin@[IPv6:2001:db8::1]>, {padding}, x@[192.0.2.1]"
        assert len(value) > mailsuite.utils._ADDRESS_GROUP_PARSE_LIMIT
        stripped, literals = mailsuite.utils._without_address_groups(value)
        assert list(literals.values()) == ["[IPv6:2001:db8::1]"]
        assert ":" not in stripped
        assert "x@[192.0.2.1]" in stripped
        parsed = parse_email(f"From: a@x\r\nTo: {value}\r\nSubject: s\r\n\r\nb\r\n")
        addresses = [address["address"] for address in parsed["to"]]
        # Each item parses as email.utils parses it alone (its strict mode
        # gives a domain literal no address), and every other one survives
        for item, address in zip(
            ("Admin <admin@[IPv6:2001:db8::1]>", "x@[192.0.2.1]"),
            (addresses[0], addresses[-1]),
            strict=True,
        ):
            assert address == email.utils.getaddresses([item])[0][1]
        assert addresses[1:-1] == [f"u{i}@example.com" for i in range(600)]

    def test_long_and_short_from_with_a_literal_parse_alike(self):
        short = "Admin <admin@[IPv6:2001:db8::1]>"
        long = "Admin" + " " * 9_000 + " <admin@[IPv6:2001:db8::1]>"
        results = [
            parse_email(f"From: {value}\r\nTo: a@x\r\nSubject: s\r\n\r\nb\r\n")["from"]
            for value in (short, long)
        ]
        assert results[0] == results[1]
        assert results[0]["display_name"] == "Admin"
        assert results[0]["compliant"] is False
        # No @ to split on: no local part or domain either way
        results = [
            parse_email(f"From: {value}\r\nTo: a@x\r\nSubject: s\r\n\r\nb\r\n")["from"]
            for value in ("x [IPv6:1::2]", "x" + " " * 9_000 + " [IPv6:1::2]")
        ]
        for result in results:
            assert result["local"] is None and result["domain"] is None
            assert result["address"].strip().endswith(" [IPv6:1::2]")
        assert results[0]["display_name"] == "x [IPv6:1::2]"
        assert results[1]["display_name"].endswith(" [IPv6:1::2]")

    def test_literal_holding_an_at_sign_parses_alike(self, monkeypatch):
        # The long path forced on the same text, so only the literal swap
        # and restore can make a difference
        for value in (
            "x@[a@b:c]",
            "Admin <x@[a@b:c]>",
            "Admin <x@[IPv6:1::2]>",
            "X <A@[a@B:c]>",
        ):
            short = parse_email_address(value)
            monkeypatch.setattr(mailsuite.utils, "_ADDRESS_GROUP_PARSE_LIMIT", 0)
            stripped, literals = mailsuite.utils._without_address_groups(value)
            monkeypatch.undo()
            assert literals, value
            long = mailsuite.utils._address_with_literals(
                parse_email_address(stripped), literals
            )
            assert dict(long) == dict(short), value
        assert short["local"] == "a"

    def test_literal_holds_no_bracket(self):
        """A literal class allowing ``[`` made 65,000 ``[`` in each of four
        address headers take 27.1 s; one allowing ``]`` merged literals."""
        run = "[" * 65_000
        headers = "".join(f"{name}: {run}\r\n" for name in ("To", "Cc", "Bcc", "Reply-To"))
        _parses_quickly("From: a@x\r\nSubject: s\r\n" + headers + "\r\nbody\r\n")
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = f"a@[x:y],b@[c:d], {padding}"
        stripped, literals = mailsuite.utils._without_address_groups(value)
        assert sorted(literals.values()) == ["[c:d]", "[x:y]"]
        assert len(email.utils.getaddresses([stripped])) == 602
        _, literals = mailsuite.utils._without_address_groups(
            f"a@[x:y],b@c.example], {padding}"
        )
        assert list(literals.values()) == ["[x:y]"]

    def test_literal_does_not_span_quotes_comments_or_angles(self):
        # Shapes where a literal allowed to hold one of these characters
        # would swallow a quoted string, a comment or an angle address
        for item in (
            ':[\\[:.""]',
            '<[]\\[ :@b ][a:b]b',
            "x@y.example][,.((:](<[a:b]@ ",
            ")aa[a:b][>>b.:a]",
            "a[<][a:b][,\\[\\:a]]",
        ):
            value = item + " " * 9_000
            stripped, literals = mailsuite.utils._without_address_groups(value)
            for literal in literals.values():
                assert not set(literal) & set('"()<>\\ \t'), (item, literal)
            assert ":" not in stripped
            parse_email(f"From: {value}\r\nTo: a@x\r\nSubject: s\r\n\r\nb\r\n")

    def test_general_address_literals_are_kept(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        for literal in ("a@[x:a_b]", "a@[IPv6:1::2%eth0]"):
            value = f"{literal}, {padding}"
            stripped, literals = mailsuite.utils._without_address_groups(value)
            assert list(literals.values()) == [literal[2:]]
            assert ":" not in stripped
            parsed = parse_email(f"From: a@x\r\nTo: {value}\r\nSubject: s\r\n\r\nb\r\n")
            assert len(parsed["to"]) == 601, literal
            assert parsed["to"][600]["address"] == "u599@example.com"

    def test_domain_literals_round_trip_to_their_own_values(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = f"a@[IPv6:1::2], b@[IPv6:3::4], c@[nocolon], {padding}"
        stripped, literals = mailsuite.utils._without_address_groups(value)
        assert sorted(literals.values()) == ["[IPv6:1::2]", "[IPv6:3::4]"]
        assert "c@[nocolon]" in stripped
        first, second = literals
        assert mailsuite.utils._with_literals(
            (f"x {first}", f"a@{second}"), literals
        ) == ("x [IPv6:1::2]", "a@[IPv6:3::4]")

    def test_placeholder_token_differs_per_call(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        value = f"a@[IPv6:1::2], {padding}"
        _, first = mailsuite.utils._without_address_groups(value)
        _, second = mailsuite.utils._without_address_groups(value)
        assert set(first).isdisjoint(second)
        # A sender who learned an earlier call's placeholder cannot use it
        forged = next(iter(first))
        assert mailsuite.utils._with_literals((forged, "x"), second) == (forged, "x")

    def test_placeholder_written_by_the_sender_is_left_alone(self):
        padding = ", ".join(f"u{i}@example.com" for i in range(600))
        forged = "[ms-0123456789abcdef-7]"
        value = f'"{forged}" <v@example.com>, a@[IPv6:1::2], {padding}'
        parsed = parse_email(f"From: a@x\r\nTo: {value}\r\nSubject: s\r\n\r\nb\r\n")
        assert parsed["to"][0]["display_name"] == forged
        assert parsed["to"][0]["address"] == "v@example.com"
        _, literals = mailsuite.utils._without_address_groups(value)
        guessed = next(iter(literals)).rsplit("-", 1)[0] + "-5]"
        assert mailsuite.utils._with_literals((guessed, forged), literals) == (
            guessed,
            forged,
        )

    def test_short_address_values_are_parsed_unchanged(self):
        for value in (
            "a@example.com, b@example.org",
            '"Support: Help" <s@example.com>',
            "Team: a@example.com, b@example.org;",
            "(note: x) a@example.com",
            "<a:b@example.com>",
        ):
            parsed = parse_email(f"From: a@x\r\nTo: {value}\r\nSubject: s\r\n\r\nb\r\n")
            expected = [
                parse_email_address(address)
                for address in email.utils.getaddresses([value])
            ]
            assert parsed["to"] == expected, value

    def test_address_header_found_only_at_line_start(self):
        # A header-block line that does not start a field is not a field
        parsed = parse_email(
            "From: a@example.com\r\nx y Cc: c@example.org\r\nSubject: hi\r\n"
            "\r\nbody\r\n"
        )
        assert parsed["cc"] == []

    def test_multipart_report_with_embedded_message_parses(self):
        message = (
            "From: reporter@example.org\r\n"
            "To: dmarc@example.com\r\n"
            "Subject: Report\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/report; report-type=feedback-report;\r\n"
            ' boundary="outer"\r\n'
            "\r\n"
            "--outer\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "A message failed DMARC.\r\n"
            "--outer\r\n"
            "Content-Type: message/feedback-report\r\n"
            "\r\n"
            "Feedback-Type: auth-failure\r\n"
            "Version: 1\r\n"
            "Auth-Failure: dmarc\r\n"
            "\r\n"
            "--outer\r\n"
            "Content-Type: message/rfc822\r\n"
            "\r\n"
            "From: someone@example.com\r\n"
            "To: user@example.org\r\n"
            "Subject: Original\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/alternative; boundary="inner"\r\n'
            "\r\n"
            "--inner\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "hello\r\n"
            "--inner\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<p>hello</p>\r\n"
            "--inner--\r\n"
            "--outer--\r\n"
        )
        check_message_limits(message, max_parts=8, max_depth=4)
        with pytest.raises(MessageLimitExceeded, match="max_parts"):
            check_message_limits(message, max_parts=7)
        with pytest.raises(MessageLimitExceeded, match="max_depth"):
            check_message_limits(message, max_depth=3)
        parsed = parse_email(message)
        assert parsed["subject"] == "Report"
        assert parsed["text_plain"][0].strip() == "A message failed DMARC."
        assert parsed["text_html"] == ["<p>hello</p>"]

    def test_message_with_attachment_parses(self):
        message = create_email(
            message_from="a@example.com",
            message_to=["b@example.org"],
            subject="Attached",
            plain_message="see attached",
            attachments=[("data.bin", bytes(range(256)) * 1024)],
        )
        parsed = parse_email(message)
        assert parsed["subject"] == "Attached"
        assert parsed["attachments"][0]["filename"] == "data.bin"

    def test_outlook_msg_is_checked_after_conversion(self, monkeypatch, sample_email_str):
        ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
        monkeypatch.setattr(
            mailsuite.utils, "convert_outlook_msg", lambda _data: sample_email_str
        )
        assert parse_email(ole)["subject"] == "Hello"
        flood = _HEAD + "X-A: b\r\n" * MAX_HEADER_LINES + "\r\nbody\r\n"
        monkeypatch.setattr(mailsuite.utils, "convert_outlook_msg", lambda _data: flood)
        with pytest.raises(MessageLimitExceeded, match="max_header_lines"):
            parse_email(ole)

    def test_large_address_group_rejected_quickly(self):
        """A To: group of 250,000 members (1 MB) took 44.3 s in parse_email
        on 2.3.4 (Python 3.12), nearly all of it parsing the group whole."""
        # Unfolded, and folded after every member
        for separator, limit in (
            (",", "max_header_field_length"),
            (",\r\n ", "max_header_lines"),
        ):
            group = "g:" + separator.join("a@x" for _ in range(250_000))
            _rejected_quickly(
                f"From: a@b\r\nTo: {group};\r\nSubject: s\r\n\r\nbody\r\n", limit
            )


class TestUrlRegex:
    """GHSA-748w-c9w9-79xp: body URL extraction is linear in the body."""

    def test_long_run_of_letters_is_linear(self):
        """findall() on 80,000 letters took 5.1 s on 2.3.4 (100,000: about
        8 s): the scheme group was retried from every offset inside the run."""
        budget = _budget()
        start = time.monotonic()
        assert url_regex.findall("x" * 100_000) == []
        assert time.monotonic() - start < budget

    def test_long_body_line_parses_quickly(self):
        """A 114 KB JSON body line took 10.7 s in parse_email on 2.3.4."""
        body = '{"a":"' + "x" * 114_000 + '"}'
        budget = _budget()
        start = time.monotonic()
        parsed = parse_email(f"From: a@b.example\r\nSubject: x\r\n\r\n{body}\r\n")
        assert parsed["body_urls"] == []
        assert time.monotonic() - start < budget

    def test_urls_after_any_prefix_are_found(self):
        for text, url in (
            ("http://a.example/p", "http://a.example/p"),
            ("see (https://a.example/x)", "https://a.example/x"),
            ("<http://a.example/y>", "http://a.example/y"),
            ('"https://a.example/q"', "https://a.example/q"),
            ("1http://a.example/d", "http://a.example/d"),
            ("_http://a.example/u", "http://a.example/u"),
            ("foohttp://a.example/f", "foohttp://a.example/f"),
        ):
            parsed = parse_email(f"From: a@b.example\r\nSubject: x\r\n\r\n{text}\r\n")
            assert parsed["body_urls"] == [url], text


class TestParseEmailEdgeCases:
    """Messages with a body but no text part, and a mail-parser failure."""

    _HEADERS = "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n"

    def test_single_part_non_text_body(self):
        """A one-part message whose body is not text or HTML still gets a
        body_markdown equal to its body."""
        message = (
            self._HEADERS
            + "Content-Type: application/octet-stream\r\n"
            + "Content-Transfer-Encoding: 8bit\r\n\r\n"
            + "caf\u00e9"
        )
        parsed = parse_email(message)
        assert parsed["body"] == "caf\u00e9"
        assert parsed["body_markdown"] == parsed["body"]
        assert parsed["body_urls"] == []

    def test_attachment_only_message(self):
        """A message with no text or HTML part has body_markdown equal to its
        body."""
        message = (
            self._HEADERS
            + "Content-Type: image/png\r\n\r\n"
            + "AAEC\r\n"
        )
        parsed = parse_email(message)
        assert parsed["text_plain"] == []
        assert parsed["text_html"] == []
        assert parsed["body_markdown"] == parsed["body"]

    def test_message_without_body_has_empty_markdown(self):
        """Pins the existing no-body result, which the body_markdown
        initialisation must not change."""
        parsed = parse_email(self._HEADERS + "\r\n")
        assert parsed["body"] == ""
        assert parsed["body_markdown"] == ""

    def test_mail_parser_error_becomes_value_error(self, monkeypatch):
        """A mail-parser error is raised as a ValueError chained to it."""

        def fail(_data):
            raise mailparser.exceptions.MailParserRecursionError("too deep")

        monkeypatch.setattr(mailparser, "parse_from_string", fail)
        with pytest.raises(ValueError, match="mail-parser could not parse") as info:
            parse_email(self._HEADERS + "\r\nbody\r\n")
        assert isinstance(info.value.__cause__, mailparser.exceptions.MailParserError)


class TestConvertOutlookMsgFailure:
    """Every way msgconvert can fail surfaces as EmailParserError."""

    _OLE = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64

    def _run(self, monkeypatch, tmp_path, check_call, match):
        """Run parse_email with check_call patched; check the cleanup."""
        created = []
        real_mkdtemp = tempfile.mkdtemp

        def mkdtemp():
            created.append(real_mkdtemp(dir=tmp_path))
            return created[-1]

        monkeypatch.setattr(subprocess, "check_call", check_call)
        monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
        before = os.getcwd()
        with pytest.raises(mailsuite.utils.EmailParserError, match=match) as info:
            parse_email(self._OLE)
        assert os.getcwd() == before
        assert len(created) == 1
        assert not os.path.exists(created[0])
        return info.value

    def test_nonzero_exit_status(self, monkeypatch, tmp_path):
        """A non-zero exit gives the exit status, chained to the cause."""

        def fail(*_args, **_kwargs):
            raise subprocess.CalledProcessError(1, "msgconvert")

        error = self._run(monkeypatch, tmp_path, fail, r"msgconvert failed.*status 1")
        assert isinstance(error.__cause__, subprocess.CalledProcessError)
        # No file name or command line in the message.
        assert "sample.msg" not in str(error)

    def test_not_runnable(self, monkeypatch, tmp_path):
        """A present but non-executable tool names the error class."""

        def fail(*_args, **_kwargs):
            raise PermissionError(13, "Permission denied")

        error = self._run(
            monkeypatch, tmp_path, fail, r"could not be run: PermissionError"
        )
        assert isinstance(error.__cause__, PermissionError)

    def test_not_installed(self, monkeypatch, tmp_path):
        """A missing tool reports that the utility was not found."""

        def fail(*_args, **_kwargs):
            raise FileNotFoundError(2, "No such file")

        self._run(monkeypatch, tmp_path, fail, "utility not found")

    def test_exit_zero_without_output(self, monkeypatch, tmp_path):
        """A tool that exits 0 and writes no file is not 'not found'."""

        def succeed(*_args, **_kwargs):
            return 0

        error = self._run(monkeypatch, tmp_path, succeed, "produced no output")
        assert "not found" not in str(error)

    def test_temp_directory_already_removed(self, monkeypatch, tmp_path):
        """A failing cleanup does not replace the EmailParserError."""

        def fail(*_args, **_kwargs):
            shutil.rmtree(os.getcwd())
            raise subprocess.CalledProcessError(1, "msgconvert")

        monkeypatch.setattr(subprocess, "check_call", fail)
        before = os.getcwd()
        with pytest.raises(mailsuite.utils.EmailParserError, match="status 1"):
            parse_email(self._OLE)
        assert os.getcwd() == before

    def test_output_decoded_as_utf8_with_replacement(self, monkeypatch):
        """A non-UTF-8 byte in the output becomes U+FFFD, as for bytes input."""

        def write_output(*_args, **_kwargs):
            with open("sample.eml", "wb") as eml_file:
                eml_file.write(b"From: a@example.com\r\nSubject: caf\xe9\r\n\r\nhi\r\n")

        monkeypatch.setattr(subprocess, "check_call", write_output)
        parsed = parse_email(self._OLE)
        assert parsed["subject"] == "caf\ufffd"

    def test_output_unreadable(self, monkeypatch):
        """An output path that cannot be read as a file names the error class."""

        def make_directory(*_args, **_kwargs):
            os.mkdir("sample.eml")

        monkeypatch.setattr(subprocess, "check_call", make_directory)
        with pytest.raises(
            mailsuite.utils.EmailParserError,
            match=r"could not read msgconvert output: IsADirectoryError",
        ):
            parse_email(self._OLE)

    def test_restoring_working_directory_fails(self, monkeypatch, caplog):
        """A failed chdir back is logged and the EmailParserError still comes out."""
        original = os.getcwd()
        real_chdir = os.chdir

        def chdir(path):
            if path == original:
                raise OSError("gone")
            real_chdir(path)

        def fail(*_args, **_kwargs):
            raise subprocess.CalledProcessError(1, "msgconvert")

        monkeypatch.setattr(subprocess, "check_call", fail)
        monkeypatch.setattr(os, "chdir", chdir)
        try:
            with (
                caplog.at_level(logging.WARNING, logger="mailsuite.utils"),
                pytest.raises(mailsuite.utils.EmailParserError, match="status 1"),
            ):
                parse_email(self._OLE)
        finally:
            real_chdir(original)
        assert "Could not restore the working directory" in caplog.text
