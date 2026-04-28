# AGENTS.md

Conventions and tooling notes for AI coding agents working on `mailsuite`.

## What this project is

A Python library for sending, receiving, parsing, signing, and verifying
email. Modules:

- `mailsuite.imap` — `IMAPClient` subclass with retry/IDLE handling and
  workarounds for Gmail / Microsoft 365 / Exchange / Dovecot / DavMail quirks
- `mailsuite.smtp` — `send_email()` with optional DKIM signing
- `mailsuite.utils` — RFC 822 parsing, address parsing,
  `Authentication-Results` / `DKIM-Signature` parsing, trusted-domain checks
- `mailsuite.dkim` — DKIM keypair generation, TXT record building, signing,
  signature verification
- `mailsuite.mailbox` — provider-agnostic mailbox abstraction
  (`MailboxConnection` ABC) with backends:
  - `IMAPConnection`, `MaildirConnection` (always available)
  - `MSGraphConnection` (requires `mailsuite[msgraph]`)
  - `GmailConnection` (requires `mailsuite[gmail]`)

## Install for development

```bash
pip install -e ".[msgraph,gmail]"
pip install pytest pytest-cov ruff pyright
```

## Tooling

- **Lint**: `ruff check mailsuite tests`
- **Type-check**: `PYRIGHT_PYTHON_FORCE_VERSION=latest pyright mailsuite`.
  Always force the latest pyright. Pylance bundles a newer typeshed than
  older pyright CLI versions; they disagree on `bytes`-shaped APIs (which
  newer typeshed widens to `Buffer = bytes | bytearray | memoryview`). Code
  that pyright 1.1.408 calls clean can flag in the IDE.
- **Tests**: `pytest` (config in `pyproject.toml`). `pytest --cov=mailsuite`
  for coverage.
- **CI**: `.github/workflows/ci.yml` runs ruff + pyright + pytest matrix
  across Python 3.9, 3.10, 3.11, 3.12, 3.13 on every PR.

## Code conventions

- Targets Python ≥ 3.9. Use `Optional[X]`, `List[X]`, `Union[X, Y]` (not
  `X | Y`) so type hints work on the oldest supported runtime.
  `from __future__ import annotations` is OK in new modules.
- Module-level loggers: `logger = logging.getLogger(__name__)`.
- Domain errors subclass `RuntimeError` (`SMTPError`, `DKIMError`,
  `MaxRetriesExceeded`).
- For functions that accept `Union[str, bytes]` and pass into `bytes`-typed
  external APIs (`cryptography`, the Graph SDK, etc.): coerce explicitly via
  `bytes(value)` rather than relying on isinstance narrowing. Pylance widens
  many of these to `Buffer`, and explicit coercion avoids spurious narrowing
  complaints. Same pattern in `dkim.py` and `mailbox/graph.py`.

## Backwards-compatibility work

When changes are purely for compat (matching a previous version, parsedmarc's
historic API, etc.), keep them to **the minimum required to close the gap**.
Don't add adjacent helpers, retry knobs, or precomputed fields the original
lacked. Inline > extract; helpers earn their keep when called more than once.
PR #22 history is the worst-case example to avoid re-creating.

## Optional extras (cloud backends)

`MSGraphConnection` and `GmailConnection` are loaded lazily through PEP 562
`__getattr__` on `mailsuite.mailbox`. Importing the package never requires
the extras; first reference to the class triggers the submodule import,
which raises a friendly `ImportError` pointing at the right
`pip install mailsuite[...]` command if the extra is missing.

When adding new cloud backends, follow the same pattern: unconditional
imports at module top in a `try/except ImportError` that re-raises with a
friendly message, plus a lazy `__getattr__` entry in
`mailsuite/mailbox/__init__.py`.

## Tests

- Tests live in `tests/`, one file per module (`test_<module>.py`).
- IMAP, Graph, and Gmail backends are tested with mocked clients constructed
  via `Class.__new__(Class)` so we bypass network/auth setup.
- Maildir tests use a real filesystem via the `tmp_path` fixture.
- Cloud-backend test files start with
  `pytest.importorskip("msgraph")` / `pytest.importorskip("googleapiclient")`
  so they skip cleanly when the extras aren't installed.

## Releasing

- Version lives in `mailsuite/__init__.py` as `__version__`. Hatch reads from
  there.
- Changelog: new section at the top of `CHANGELOG.md`. Don't bump the version
  until the maintainer is ready to release — fold new entries into the
  unreleased section.

## Git / PRs

- Branches: `feat/...`, `fix/...`, `docs/...`.
- PR titles ≤ ~70 chars; detail in body.
- Commits authored by Claude include
  `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
