"""Tests for mailsuite.dkim."""

from __future__ import annotations

import dkim as _dkim
import pytest

from mailsuite.dkim import (
    DEFAULT_SIGNED_HEADERS,
    DKIMError,
    generate_dkim_keypair,
    generate_dkim_private_key,
    generate_dkim_txt_record,
    get_dkim_public_key,
    sign_email,
    verify_email,
)


class TestKeyGeneration:
    def test_generate_private_key_default(self):
        pem = generate_dkim_private_key()
        assert pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert "END PRIVATE KEY" in pem

    def test_generate_private_key_custom_size(self):
        pem = generate_dkim_private_key(key_size=1024)
        assert pem.startswith("-----BEGIN PRIVATE KEY-----")

    def test_reject_undersize_key(self):
        with pytest.raises(ValueError, match="at least 1024"):
            generate_dkim_private_key(key_size=512)

    def test_keypair_pair(self, dkim_keypair):
        priv, pub = dkim_keypair
        assert priv.startswith("-----BEGIN PRIVATE KEY-----")
        # public key is base64 SubjectPublicKeyInfo (no PEM markers)
        assert "BEGIN" not in pub
        assert len(pub) > 100

    def test_get_public_key_str_input(self, dkim_keypair):
        priv, pub = dkim_keypair
        assert get_dkim_public_key(priv) == pub

    def test_get_public_key_bytes_input(self, dkim_keypair):
        priv, pub = dkim_keypair
        assert get_dkim_public_key(priv.encode()) == pub

    def test_get_public_key_bytearray_input(self, dkim_keypair):
        priv, pub = dkim_keypair
        assert get_dkim_public_key(bytearray(priv.encode())) == pub

    def test_get_public_key_invalid_pem(self):
        with pytest.raises(DKIMError, match="Failed to load private key"):
            get_dkim_public_key("not a key")


class TestTxtRecord:
    def test_record_value_only(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(pub)
        assert record.startswith("v=DKIM1")
        assert "k=rsa" in record
        assert f"p={pub}" in record

    def test_record_with_domain(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(pub, selector="ms1", domain="example.com")
        assert record.startswith("ms1._domainkey.example.com.")
        assert "IN" in record
        assert "TXT" in record
        assert "v=DKIM1" in record

    def test_record_strips_trailing_dot_in_domain(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(pub, selector="ms1", domain="example.com.")
        assert "example.com." in record
        assert "example.com.." not in record

    def test_record_from_pem_private_key(self, dkim_keypair):
        priv, pub = dkim_keypair
        record = generate_dkim_txt_record(priv)
        assert f"p={pub}" in record

    def test_record_from_pem_public_key(self, dkim_keypair):
        from cryptography.hazmat.primitives import serialization

        priv, pub = dkim_keypair
        key = serialization.load_pem_private_key(priv.encode(), password=None)
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        record = generate_dkim_txt_record(pub_pem)
        assert f"p={pub}" in record

    def test_record_with_flags_and_note(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(pub, flags="y", note="test mode")
        assert "t=y" in record
        assert "n=test mode" in record

    def test_record_strips_whitespace_from_b64(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(f"  {pub[:40]}\n{pub[40:]}  ")
        assert " " not in record.split("p=", 1)[1]

    def test_record_bytes_input(self, dkim_keypair):
        _, pub = dkim_keypair
        record = generate_dkim_txt_record(pub.encode())
        assert "v=DKIM1" in record

    def test_record_invalid_pem_public_key(self):
        with pytest.raises(DKIMError, match="Failed to load public key"):
            generate_dkim_txt_record(
                "-----BEGIN PUBLIC KEY-----\nnotreal\n-----END PUBLIC KEY-----"
            )


class TestSignEmail:
    def _dns_func_for(self, pub: str):
        record = generate_dkim_txt_record(pub).encode()

        def fake(name, timeout=5):
            return record

        return fake

    def test_sign_str_input(self, dkim_keypair, sample_email_str):
        priv, _ = dkim_keypair
        signed = sign_email(sample_email_str, "ms1", "example.com", priv)
        assert isinstance(signed, str)
        assert signed.startswith("DKIM-Signature: ")

    def test_sign_bytes_input(self, dkim_keypair, sample_email_str):
        priv, _ = dkim_keypair
        signed = sign_email(sample_email_str.encode(), "ms1", "example.com", priv)
        assert isinstance(signed, bytes)
        assert signed.startswith(b"DKIM-Signature: ")

    def test_sign_bytes_private_key(self, dkim_keypair, sample_email_str):
        priv, _ = dkim_keypair
        signed = sign_email(sample_email_str, "ms1", "example.com", priv.encode())
        assert signed.startswith("DKIM-Signature: ")

    def test_signed_message_verifies(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed = sign_email(sample_email_str, "ms1", "example.com", priv)
        assert _dkim.verify(signed.encode(), dnsfunc=self._dns_func_for(pub)) is True

    def test_additional_headers(self, dkim_keypair):
        priv, pub = dkim_keypair
        msg = (
            "From: a@example.com\r\n"
            "To: b@example.org\r\n"
            "Subject: x\r\n"
            "X-Custom: yes\r\n"
            "\r\n"
            "body\r\n"
        )
        signed = sign_email(
            msg, "ms1", "example.com", priv, additional_headers=["X-Custom", "X-Missing"]
        )
        # verify still passes
        assert _dkim.verify(signed.encode(), dnsfunc=self._dns_func_for(pub)) is True
        # x-custom appears in the h= tag of the signature
        sig_line = signed.split("\r\n\r\n", 1)[0].split("DKIM-Signature: ", 1)[1]
        assert "x-custom" in sig_line.lower()

    def test_no_from_header_raises(self, dkim_keypair):
        priv, _ = dkim_keypair
        with pytest.raises(DKIMError, match="From header"):
            sign_email("Subject: x\r\n\r\nbody\r\n", "ms1", "example.com", priv)

    def test_explicit_identity(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed = sign_email(
            sample_email_str, "ms1", "example.com", priv, identity="@example.com"
        )
        assert _dkim.verify(signed.encode(), dnsfunc=self._dns_func_for(pub)) is True

    def test_dkim_exception_wrapped(self, dkim_keypair, sample_email_str):
        # Identity that doesn't end with the domain → ParameterError → DKIMError
        priv, _ = dkim_keypair
        with pytest.raises(DKIMError):
            sign_email(
                sample_email_str,
                "ms1",
                "example.com",
                priv,
                identity="@other.example",
            )

    def test_default_signed_headers_are_oversigned(self):
        # From/To/Cc/Subject appear twice for oversigning
        for name in ("From", "To", "Cc", "Subject"):
            assert DEFAULT_SIGNED_HEADERS.count(name) == 2


class TestVerifyEmail:
    def _signed_with(self, priv: str, msg: str, **kwargs) -> str:
        return sign_email(msg, "ms1", "example.com", priv, **kwargs)

    def _dns_func_for(self, pub: str):
        record = generate_dkim_txt_record(pub).encode()

        def fake(name, timeout=5):
            return record

        return fake

    def test_valid_signature(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed = self._signed_with(priv, sample_email_str)
        result = verify_email(signed, dns_func=self._dns_func_for(pub))
        assert result["valid"] is True
        assert len(result["signatures"]) == 1
        sig = result["signatures"][0]
        assert sig["domain"] == "example.com"
        assert sig["selector"] == "ms1"
        assert sig["valid"] is True
        assert sig["error"] is None

    def test_bytes_input(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed = self._signed_with(priv, sample_email_str)
        result = verify_email(signed.encode(), dns_func=self._dns_func_for(pub))
        assert result["valid"] is True

    def test_wrong_dns_key(self, dkim_keypair, sample_email_str):
        priv, _ = self._noop_keys(dkim_keypair)
        _, wrong_pub = generate_dkim_keypair(2048)
        signed = self._signed_with(priv, sample_email_str)
        result = verify_email(signed, dns_func=self._dns_func_for(wrong_pub))
        assert result["valid"] is False
        assert result["signatures"][0]["error"] is not None

    def test_tampered_body(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed = self._signed_with(priv, sample_email_str)
        tampered = signed.replace("Hello world", "Goodbye world")
        result = verify_email(tampered, dns_func=self._dns_func_for(pub))
        assert result["valid"] is False
        assert "body hash mismatch" in result["signatures"][0]["error"]

    def test_no_signatures(self, dkim_keypair, sample_email_str):
        _, pub = dkim_keypair
        result = verify_email(sample_email_str, dns_func=self._dns_func_for(pub))
        assert result["valid"] is False
        assert result["signatures"] == []

    def test_multiple_signatures_all_valid(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        signed_once = self._signed_with(priv, sample_email_str)
        signed_twice = sign_email(signed_once, "ms2", "example.com", priv)
        result = verify_email(signed_twice, dns_func=self._dns_func_for(pub))
        assert result["valid"] is True
        assert len(result["signatures"]) == 2

    def test_multiple_signatures_mixed(self, dkim_keypair, sample_email_str):
        priv, pub = dkim_keypair
        priv2, pub2 = generate_dkim_keypair(2048)
        signed_once = self._signed_with(priv, sample_email_str)
        signed_twice = sign_email(signed_once, "ms2", "example.com", priv)

        record_pub = generate_dkim_txt_record(pub).encode()
        record_pub2 = generate_dkim_txt_record(pub2).encode()

        def selective_dns(name, timeout=5):
            if name.startswith(b"ms2."):
                return record_pub2
            return record_pub

        result = verify_email(signed_twice, dns_func=selective_dns)
        # ms1 valid, ms2 invalid → at least one valid → overall True
        assert result["valid"] is True
        valid = [s for s in result["signatures"] if s["valid"]]
        invalid = [s for s in result["signatures"] if not s["valid"]]
        assert len(valid) == 1 and len(invalid) == 1

    def test_malformed_signature_header(self, dkim_keypair):
        # A DKIM-Signature header that fails parse_tag_value gets caught and
        # reported as an error rather than raising.
        msg = (
            "From: a@example.com\r\n"
            "To: b@example.org\r\n"
            "DKIM-Signature: this is not a real DKIM-Signature value\r\n"
            "Subject: x\r\n"
            "\r\n"
            "body\r\n"
        )
        result = verify_email(msg, dns_func=lambda *a, **k: b"")
        assert result["valid"] is False
        assert len(result["signatures"]) == 1

    @staticmethod
    def _noop_keys(keypair):
        return keypair
