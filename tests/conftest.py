"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from mailsuite.dkim import generate_dkim_keypair


@pytest.fixture(scope="session")
def dkim_keypair() -> tuple[str, str]:
    """A 2048-bit RSA DKIM keypair shared across tests for speed."""
    return generate_dkim_keypair(key_size=2048)


@pytest.fixture
def sample_email_str() -> str:
    """A minimal RFC 822 message used by signing/parsing tests."""
    return (
        "From: Sender <sender@example.com>\r\n"
        "To: recipient@example.org\r\n"
        "Subject: Hello\r\n"
        "Date: Mon, 27 Apr 2026 12:00:00 +0000\r\n"
        "Message-ID: <test@example.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello world\r\n"
    )
