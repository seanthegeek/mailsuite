"""Tests for mailsuite.utils."""

from __future__ import annotations

import base64

import pytest

from mailsuite.utils import (
    create_email,
    decode_base64,
    get_filename_safe_string,
    is_outlook_msg,
    parse_authentication_results,
    parse_dkim_signature,
    parse_email,
    parse_email_address,
    from_trusted_domain,
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

    def test_automatic_reply_detection(self):
        raw = (
            "From: a@example.com\r\n"
            "To: b@example.org\r\n"
            "Subject: Out of office\r\n"
            "X-Auto-Response-Suppress: All\r\n"
            "Auto-Submitted: auto_generated\r\n"
            "\r\n"
            "I'm away.\r\n"
        )
        parsed = parse_email(raw)
        assert parsed["automatic_reply"] is True


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
