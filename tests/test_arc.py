"""Tests for mailsuite.arc."""

from __future__ import annotations

import pytest

from mailsuite.arc import ARCError, seal_email, verify_arc_chain
from mailsuite.dkim import generate_dkim_keypair, generate_dkim_txt_record


def _dns_func_for(pub: str):
    """A fake DNS resolver returning a DKIM TXT record for ``pub``."""
    record = generate_dkim_txt_record(pub).encode()

    def fake(name, timeout=5):
        return record

    return fake


def _message_with_ar(authserv_id: str) -> str:
    """A minimal message carrying an Authentication-Results from ``authserv_id``."""
    return (
        f"Authentication-Results: {authserv_id}; "
        "spf=pass smtp.mailfrom=sender@example.org; "
        "dkim=pass header.d=example.org; dmarc=pass\r\n"
        "From: Sender <sender@example.org>\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Hello\r\n"
        "Date: Fri, 22 May 2026 12:00:00 +0000\r\n"
        "Message-ID: <test@example.org>\r\n"
        "\r\n"
        "Hello world\r\n"
    )


class TestSealEmail:
    def test_seal_str_input(self, dkim_keypair):
        priv, _ = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"), "sel", "example.com", priv, "example.com"
        )
        assert isinstance(sealed, str)
        assert sealed.startswith("ARC-Seal: ")
        assert "ARC-Message-Signature: " in sealed
        assert "ARC-Authentication-Results: " in sealed

    def test_seal_bytes_input(self, dkim_keypair):
        priv, _ = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com").encode(),
            "sel",
            "example.com",
            priv,
            "example.com",
        )
        assert isinstance(sealed, bytes)
        assert sealed.startswith(b"ARC-Seal: ")

    def test_seal_bytes_private_key(self, dkim_keypair):
        priv, _ = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"),
            "sel",
            "example.com",
            priv.encode(),
            "example.com",
        )
        assert sealed.startswith("ARC-Seal: ")

    def test_seal_with_timestamp(self, dkim_keypair):
        priv, _ = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"),
            "sel",
            "example.com",
            priv,
            "example.com",
            timestamp=1700000000,
        )
        assert "t=1700000000" in sealed

    def test_seal_with_explicit_signed_headers(self, dkim_keypair):
        priv, pub = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"),
            "sel",
            "example.com",
            priv,
            "example.com",
            signed_headers=["From", "To", "Subject", "Date", "Message-ID"],
        )
        result = verify_arc_chain(sealed, dns_func=_dns_func_for(pub))
        assert result["valid"] is True

    def test_seal_no_matching_ar_raises(self, dkim_keypair):
        priv, _ = dkim_keypair
        # authserv_id does not match the message's Authentication-Results
        with pytest.raises(ARCError, match="No ARC set produced"):
            seal_email(
                _message_with_ar("other.example"),
                "sel",
                "example.com",
                priv,
                "example.com",
            )

    def test_seal_no_ar_header_raises(self, dkim_keypair):
        priv, _ = dkim_keypair
        msg = (
            "From: a@example.org\r\n"
            "To: b@example.com\r\n"
            "Subject: x\r\n"
            "\r\n"
            "body\r\n"
        )
        with pytest.raises(ARCError, match="No ARC set produced"):
            seal_email(msg, "sel", "example.com", priv, "example.com")

    def test_seal_from_must_be_signed(self, dkim_keypair):
        priv, _ = dkim_keypair
        with pytest.raises(ARCError, match="From"):
            seal_email(
                _message_with_ar("example.com"),
                "sel",
                "example.com",
                priv,
                "example.com",
                signed_headers=["To", "Subject"],
            )


class TestVerifyArcChain:
    def test_sealed_message_verifies(self, dkim_keypair):
        priv, pub = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"), "sel", "example.com", priv, "example.com"
        )
        result = verify_arc_chain(sealed, dns_func=_dns_func_for(pub))
        assert result["valid"] is True
        assert result["cv"] == "pass"
        assert result["reason"] == "success"
        assert len(result["instances"]) == 1
        inst = result["instances"][0]
        assert inst["instance"] == 1
        assert inst["ams_domain"] == "example.com"
        assert inst["ams_selector"] == "sel"
        assert inst["ams_valid"] is True
        assert inst["as_domain"] == "example.com"
        assert inst["as_selector"] == "sel"
        assert inst["as_valid"] is True
        # The first instance must report cv=none (no prior chain)
        assert inst["cv"] == "none"

    def test_bytes_input(self, dkim_keypair):
        priv, pub = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"), "sel", "example.com", priv, "example.com"
        )
        result = verify_arc_chain(sealed.encode(), dns_func=_dns_func_for(pub))
        assert result["valid"] is True

    def test_not_arc_signed(self, dkim_keypair):
        _, pub = dkim_keypair
        result = verify_arc_chain(
            _message_with_ar("example.com"), dns_func=_dns_func_for(pub)
        )
        assert result["valid"] is False
        assert result["cv"] == "none"
        assert result["instances"] == []
        assert "not ARC signed" in result["reason"]

    def test_tampered_body_fails(self, dkim_keypair):
        priv, pub = dkim_keypair
        sealed = seal_email(
            _message_with_ar("example.com"), "sel", "example.com", priv, "example.com"
        )
        tampered = sealed.replace("Hello world", "Goodbye world")
        result = verify_arc_chain(tampered, dns_func=_dns_func_for(pub))
        assert result["valid"] is False
        assert result["cv"] == "fail"
        assert result["instances"][0]["ams_valid"] is False

    def test_wrong_dns_key_fails(self, dkim_keypair):
        priv, _ = dkim_keypair
        _, wrong_pub = generate_dkim_keypair(2048)
        sealed = seal_email(
            _message_with_ar("example.com"), "sel", "example.com", priv, "example.com"
        )
        result = verify_arc_chain(sealed, dns_func=_dns_func_for(wrong_pub))
        assert result["valid"] is False
        assert result["cv"] == "fail"

    def test_two_hop_chain_verifies(self, dkim_keypair):
        priv, pub = dkim_keypair

        # Hop 1 seals the originating message (instance 1).
        hop1 = seal_email(
            _message_with_ar("hop1.example"),
            "s1",
            "hop1.example",
            priv,
            "hop1.example",
        )

        # Hop 2 records its own Authentication-Results — including the arc=pass
        # it obtained by validating hop 1's chain — then seals (instance 2).
        hop2_ar = (
            "Authentication-Results: hop2.example; arc=pass; "
            "dkim=pass header.d=example.org\r\n"
        )
        hop2_input = hop2_ar + hop1
        hop2 = seal_email(
            hop2_input, "s2", "hop2.example", priv, "hop2.example"
        )

        result = verify_arc_chain(hop2, dns_func=_dns_func_for(pub))
        assert result["valid"] is True
        assert result["cv"] == "pass"
        assert len(result["instances"]) == 2
        # instances are returned in ascending order
        assert [i["instance"] for i in result["instances"]] == [1, 2]
        assert result["instances"][0]["as_domain"] == "hop1.example"
        assert result["instances"][1]["as_domain"] == "hop2.example"
        # second hop seals over a passing chain
        assert result["instances"][1]["cv"] == "pass"

    def test_terminated_chain_reports_fail(self, dkim_keypair):
        # A hop that records arc=fail seals an instance with cv=fail, which
        # terminates the chain. dkimpy signals this with a ``None`` cv;
        # verify_arc_chain normalises it to "fail".
        priv, pub = dkim_keypair
        hop1 = seal_email(
            _message_with_ar("hop1.example"),
            "s1",
            "hop1.example",
            priv,
            "hop1.example",
        )
        hop2_ar = (
            "Authentication-Results: hop2.example; arc=fail; "
            "dkim=pass header.d=example.org\r\n"
        )
        hop2 = seal_email(
            hop2_ar + hop1, "s2", "hop2.example", priv, "hop2.example"
        )
        result = verify_arc_chain(hop2, dns_func=_dns_func_for(pub))
        assert result["valid"] is False
        assert result["cv"] == "fail"
        assert "terminated" in result["reason"]
        assert result["instances"][1]["cv"] == "fail"

    def test_arc_error_is_runtime_error(self):
        assert issubclass(ARCError, RuntimeError)
