"""Docker-based integration tests for the IMAP IDLE watch loop.

These exercise ``mailsuite.imap.IMAPClient``'s IDLE watch against a real IMAP
server (GreenMail) running in Docker — the behaviour that the mocked unit
tests can't cover: live IDLE notifications and reconnect-during-IDLE.

They are **opt-in**: skipped unless Docker is available *and*
``MAILSUITE_DOCKER_TESTS=1`` is set, so the normal suite (and CI, which has no
Docker) doesn't pull/start a container. Run them with::

    MAILSUITE_DOCKER_TESTS=1 pytest tests/test_imap_idle_integration.py
"""

from __future__ import annotations

import os
import smtplib
import socket
import subprocess
import threading
import time
import uuid
from email.message import EmailMessage

import imapclient
import pytest

from mailsuite.imap import IMAPClient

IMAGE = "greenmail/standalone:2.1.4"
USER = "test@localhost"
PASSWORD = "pass"


def _docker_available() -> bool:
    if not os.environ.get("MAILSUITE_DOCKER_TESTS"):
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=15,
        )
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="requires Docker and MAILSUITE_DOCKER_TESTS=1",
)


def _host_port(name: str, container_port: str) -> int:
    """Return the host port Docker mapped to ``container_port`` for ``name``."""
    out = subprocess.run(
        ["docker", "port", name, container_port],
        capture_output=True, text=True, check=True,
    ).stdout.strip().splitlines()[0]
    return int(out.rsplit(":", 1)[1])


@pytest.fixture(scope="module")
def greenmail():
    """Start a GreenMail container; yield (host, imap_port, smtp_port)."""
    name = f"ms-idle-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "-d", "--name", name,
            # Let Docker assign free host ports (avoids a pick-then-bind race).
            "-p", "3143", "-p", "3025",
            # Bind 0.0.0.0 inside the container so the port-forward reaches it
            # (GreenMail otherwise binds 127.0.0.1).
            "-e", "GREENMAIL_OPTS=-Dgreenmail.setup.test.all "
                  "-Dgreenmail.hostname=0.0.0.0 -Dgreenmail.auth.disabled",
            IMAGE,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                imap_port = _host_port(name, "3143")
                smtp_port = _host_port(name, "3025")
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        deadline = time.monotonic() + 60
        while True:
            try:
                c = imapclient.IMAPClient("127.0.0.1", port=imap_port, ssl=False)
                c.login(USER, PASSWORD)
                c.logout()
                break
            except Exception:
                if time.monotonic() > deadline:
                    logs = subprocess.run(
                        ["docker", "logs", name],
                        capture_output=True, text=True,
                    ).stderr
                    raise RuntimeError(f"GreenMail not ready:\n{logs[-2000:]}")
                time.sleep(1)
        yield "127.0.0.1", imap_port, smtp_port
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def _deliver(smtp_port: int, subject: str) -> None:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = USER
    msg["Subject"] = subject
    msg.set_content("body")
    with smtplib.SMTP("127.0.0.1", smtp_port) as s:
        s.send_message(msg)


def _clear_mailbox(imap_port: int) -> None:
    """Empty INBOX so tests start from a known count (the fixture is shared)."""
    c = imapclient.IMAPClient("127.0.0.1", port=imap_port, ssl=False)
    try:
        c.login(USER, PASSWORD)
        c.select_folder("INBOX")
        uids = c.search(["ALL"])
        if uids:
            c.delete_messages(uids)
            c.expunge()
    finally:
        c.logout()


def _wait_until(predicate, timeout=20.0, interval=0.25) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _start_watch(host, port, observations, stash, stop_at, errors=None):
    """Run an IDLE watch in a thread; the callback records the INBOX message
    count and stops the watch once it reaches ``stop_at``."""
    def cb(client):
        stash["client"] = client
        n = None
        for _ in range(5):  # tolerate transient search races around IDLE
            try:
                n = len(client.search(["ALL"]))
                break
            except Exception:
                time.sleep(0.2)
        if n is None:
            return
        observations.append(n)
        if n >= stop_at:
            raise KeyboardInterrupt  # cleanly breaks the IDLE loop

    def run():
        try:
            IMAPClient(
                host=host, port=port, ssl=False,
                username=USER, password=PASSWORD,
                idle_callback=cb, idle_timeout=2, max_retries=5,
            )
        except KeyboardInterrupt:
            pass
        except BaseException as exc:  # surface real failures via `errors`
            if errors is not None:
                errors.append(repr(exc))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_idle_detects_new_mail(greenmail):
    host, imap_port, smtp_port = greenmail
    _clear_mailbox(imap_port)
    observations, stash = [], {}
    t = _start_watch(host, imap_port, observations, stash, stop_at=1)
    assert _wait_until(lambda: "client" in stash), "watch never connected"
    _deliver(smtp_port, "hello")
    assert _wait_until(lambda: any(n >= 1 for n in observations)), (
        f"new mail not detected over IDLE; observations={observations}"
    )
    t.join(timeout=5)


def test_reconnect_during_idle_recovers_without_recursion(greenmail, monkeypatch):
    host, imap_port, smtp_port = greenmail
    _clear_mailbox(imap_port)
    observations, stash, errors = [], {}, []

    # Count entries into _start_idle and reconnects: a reconnect must re-arm the
    # existing loop, not start a nested one (the pre-fix bug entered _start_idle
    # again on every reconnect).
    entries, resets = [], []
    original_idle = IMAPClient._start_idle
    original_reset = IMAPClient.reset_connection

    def counting(self, idle_callback, idle_timeout=30):
        entries.append(1)
        return original_idle(self, idle_callback, idle_timeout=idle_timeout)

    def reset_spy(self):
        resets.append(1)
        return original_reset(self)

    monkeypatch.setattr(IMAPClient, "_start_idle", counting)
    monkeypatch.setattr(IMAPClient, "reset_connection", reset_spy)

    # Start the watch on an empty mailbox; it stops once it sees one message,
    # which is delivered only AFTER the reconnect — so detecting it proves the
    # loop re-armed on the reconnected connection.
    t = _start_watch(host, imap_port, observations, stash, stop_at=1, errors=errors)
    assert _wait_until(lambda: "client" in stash), "watch never connected"
    time.sleep(2)  # let the IDLE session settle before dropping it

    # Force a connection drop mid-IDLE to trigger reset_connection.
    stash["client"].socket().shutdown(socket.SHUT_RDWR)
    assert _wait_until(lambda: len(resets) >= 1, timeout=30), (
        "drop did not trigger a reconnect"
    )

    _deliver(smtp_port, "after-reconnect")
    assert _wait_until(
        lambda: any(n >= 1 for n in observations), timeout=30
    ), f"message after reconnect not detected; observations={observations}, errors={errors}"

    t.join(timeout=5)
    assert not t.is_alive(), "watch thread did not stop"
    assert errors == [], f"watch raised during reconnect: {errors}"
    # The reconnect re-armed the existing loop rather than nesting a new one.
    assert len(entries) == 1, f"_start_idle re-entered (recursion): {len(entries)}x"
