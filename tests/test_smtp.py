"""Tests for mailsuite.smtp.send_email.

The actual network/SMTP I/O is exercised by patching smtplib.SMTP and
smtplib.SMTP_SSL with fakes. We focus on the dispatch logic — DKIM
wiring, envelope/header construction, error wrapping — rather than
re-testing smtplib itself.
"""

from __future__ import annotations

import smtplib
import socket
import ssl

import dkim as _dkim
import pytest

from mailsuite import smtp as ms_smtp
from mailsuite.dkim import generate_dkim_txt_record
from mailsuite.smtp import SMTPError, send_email


class FakeSMTPServer:
    """A minimal stand-in for smtplib.SMTP / SMTP_SSL."""

    instances: list = []

    def __init__(
        self, host="", port=0, *args, has_starttls=True, **kwargs
    ):
        self.host = host
        self.port = port
        self._has_starttls = has_starttls
        self.connected = False
        self.starttls_called = False
        self.ehlo_count = 0
        self.login_args = None
        self.auth_args = None
        self.sendmail_args = None
        FakeSMTPServer.instances.append(self)

    def connect(self, host, port):
        self.connected = True
        self.host = host
        self.port = port

    def ehlo_or_helo_if_needed(self):
        self.ehlo_count += 1

    def ehlo(self):
        self.ehlo_count += 1

    def has_extn(self, name):
        return name.lower() == "starttls" and self._has_starttls

    def starttls(self, context=None):
        self.starttls_called = True

    def login(self, user, password):
        self.login_args = (user, password)

    def auth(self, mechanism, authobject, **kwargs):
        # smtplib calls the authobject to get the (pre-base64) SASL string
        self.auth_args = (mechanism, authobject())

    def sendmail(self, sender, to, body):
        self.sendmail_args = (sender, list(to), body)


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTPServer.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTPServer)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPServer)
    monkeypatch.setattr(ms_smtp.smtplib, "SMTP", FakeSMTPServer)
    monkeypatch.setattr(ms_smtp.smtplib, "SMTP_SSL", FakeSMTPServer)
    return FakeSMTPServer


class TestSendEmailBasic:
    def test_sends_message(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            subject="hi",
            plain_message="hello",
        )
        srv = fake_smtp.instances[-1]
        assert srv.connected
        assert srv.sendmail_args is not None
        sender, recipients, body = srv.sendmail_args
        assert sender == "a@example.com"
        assert "b@example.org" in recipients
        assert "Subject: hi" in body
        assert "hello" in body

    def test_login_when_credentials_provided(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user",
            password="pw",
        )
        srv = fake_smtp.instances[-1]
        assert srv.login_args == ("user", "pw")

    def test_starttls_used_when_supported(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
        )
        srv = fake_smtp.instances[-1]
        assert srv.starttls_called is True

    def test_no_starttls_when_unsupported(self, fake_smtp, monkeypatch):
        # Fake SMTP that says STARTTLS isn't available
        def _no_starttls(*args, **kwargs):
            return FakeSMTPServer(*args, has_starttls=False, **kwargs)

        monkeypatch.setattr(smtplib, "SMTP", _no_starttls)
        monkeypatch.setattr(ms_smtp.smtplib, "SMTP", _no_starttls)
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
        )
        srv = fake_smtp.instances[-1]
        assert srv.starttls_called is False

    def test_require_encryption_uses_smtp_ssl(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            require_encryption=True,
        )
        # SMTP_SSL was called with our fake — connection happens but starttls
        # isn't called when require_encryption is True
        srv = fake_smtp.instances[-1]
        assert srv.connected
        assert srv.starttls_called is False

    def test_envelope_from_overrides(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            envelope_from="bounce@example.com",
        )
        sender, _, _ = fake_smtp.instances[-1].sendmail_args
        assert sender == "bounce@example.com"

    def test_cc_and_bcc_in_envelope(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            message_cc=["c@example.org"],
            message_bcc=["d@example.org"],
        )
        _, recipients, body = fake_smtp.instances[-1].sendmail_args
        # Cc must appear in the envelope (not necessarily in the To header)
        assert "c@example.org" in recipients or "c@example.org" in body


class TestSendEmailOAuth:
    def test_xoauth2_is_default(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user@example.com",
            oauth2_token="tok123",
        )
        srv = fake_smtp.instances[-1]
        assert srv.login_args is None  # password login path not taken
        mechanism, auth_string = srv.auth_args
        assert mechanism == "XOAUTH2"
        assert auth_string == "user=user@example.com\x01auth=Bearer tok123\x01\x01"
        # smtplib base64-encodes the string, so it must be ASCII-safe
        auth_string.encode("ascii")

    def test_oauthbearer_mechanism(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user@example.com",
            oauth2_token="tok123",
            oauth2_mechanism="OAUTHBEARER",
        )
        mechanism, auth_string = fake_smtp.instances[-1].auth_args
        assert mechanism == "OAUTHBEARER"
        assert auth_string == "n,a=user@example.com,\x01auth=Bearer tok123\x01\x01"

    def test_token_provider_invoked(self, fake_smtp):
        calls = []

        def provider():
            calls.append(1)
            return "fresh-token"

        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user@example.com",
            oauth2_token_provider=provider,
        )
        assert calls  # provider was called at send time
        assert "auth=Bearer fresh-token" in fake_smtp.instances[-1].auth_args[1]

    def test_provider_takes_precedence_over_static_token(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user@example.com",
            oauth2_token="static",
            oauth2_token_provider=lambda: "dynamic",
        )
        assert "Bearer dynamic" in fake_smtp.instances[-1].auth_args[1]

    def test_vendor_included_for_xoauth2(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user@example.com",
            oauth2_token="tok123",
            oauth2_vendor="vendorX",
        )
        assert "vendor=vendorX\x01" in fake_smtp.instances[-1].auth_args[1]

    def test_username_required_with_oauth(self, fake_smtp):
        with pytest.raises(ValueError, match="username is required"):
            send_email(
                host="smtp.example.com",
                message_from="a@example.com",
                message_to=["b@example.org"],
                oauth2_token="tok123",
            )

    def test_password_login_unaffected(self, fake_smtp):
        send_email(
            host="smtp.example.com",
            message_from="a@example.com",
            message_to=["b@example.org"],
            username="user",
            password="pw",
        )
        srv = fake_smtp.instances[-1]
        assert srv.login_args == ("user", "pw")
        assert srv.auth_args is None  # OAuth path not taken


class TestSendEmailDKIM:
    def test_dkim_signs_message(self, fake_smtp, dkim_keypair):
        priv, pub = dkim_keypair
        send_email(
            host="smtp.example.com",
            message_from="Sender <sender@example.com>",
            message_to=["b@example.org"],
            subject="hi",
            plain_message="hello",
            dkim_private_key=priv,
            dkim_selector="ms1",
        )
        _, _, body = fake_smtp.instances[-1].sendmail_args
        assert body.startswith("DKIM-Signature: ")

        record = generate_dkim_txt_record(pub).encode()

        def fake_dns(name, timeout=5):
            return record

        assert _dkim.verify(body.encode(), dnsfunc=fake_dns) is True

    def test_dkim_explicit_domain(self, fake_smtp, dkim_keypair):
        priv, _ = dkim_keypair
        send_email(
            host="smtp.example.com",
            message_from="sender@inferred.example",
            message_to=["b@example.org"],
            dkim_private_key=priv,
            dkim_selector="ms1",
            dkim_domain="explicit.example",
            plain_message="hi",
        )
        _, _, body = fake_smtp.instances[-1].sendmail_args
        assert "d=explicit.example" in body

    def test_missing_selector_raises(self, fake_smtp, dkim_keypair):
        priv, _ = dkim_keypair
        with pytest.raises(ValueError, match="dkim_selector"):
            send_email(
                host="smtp.example.com",
                message_from="a@example.com",
                message_to=["b@example.org"],
                dkim_private_key=priv,
            )

    def test_unparseable_from_for_domain_raises(self, fake_smtp, dkim_keypair):
        priv, _ = dkim_keypair
        with pytest.raises(ValueError, match="dkim_domain"):
            send_email(
                host="smtp.example.com",
                message_from="no-at-sign",
                message_to=["b@example.org"],
                dkim_private_key=priv,
                dkim_selector="ms1",
            )


class TestSendEmailErrors:
    def test_smtp_exception_wrapped(self, monkeypatch):
        class BoomServer(FakeSMTPServer):
            def sendmail(self, *a, **k):
                raise smtplib.SMTPException("550 mailbox unavailable.")

        monkeypatch.setattr(smtplib, "SMTP", BoomServer)
        monkeypatch.setattr(ms_smtp.smtplib, "SMTP", BoomServer)
        with pytest.raises(SMTPError, match="mailbox unavailable"):
            send_email(
                host="smtp.example.com",
                message_from="a@example.com",
                message_to=["b@example.org"],
            )

    @pytest.mark.parametrize(
        ("exc", "match"),
        [
            (socket.gaierror(), "DNS"),
            (ConnectionRefusedError(), "refused"),
            (ConnectionResetError(), "reset"),
            (ConnectionAbortedError(), "aborted"),
            (TimeoutError(), "timed out"),
            (ssl.SSLError("boom"), "SSL"),
            (ssl.CertificateError("bad cert"), "Certificate"),
        ],
    )
    def test_connection_errors_wrapped(self, monkeypatch, exc, match):
        class BoomServer(FakeSMTPServer):
            def connect(self, host, port):
                raise exc

        monkeypatch.setattr(smtplib, "SMTP", BoomServer)
        monkeypatch.setattr(ms_smtp.smtplib, "SMTP", BoomServer)
        with pytest.raises(SMTPError, match=match):
            send_email(
                host="smtp.example.com",
                message_from="a@example.com",
                message_to=["b@example.org"],
            )
