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

## Working with vendor SDKs

When the question is "does the SDK do X?" or "what does the SDK return for
Y?", **read the SDK source**. Don't guess, don't rely on a prior port's
behavior, don't trust an LLM summary. Vendor SDKs change shape between
versions and the installed version is the only contract that matters.

In order of preference:

1. The **installed SDK source** in `venv/lib/python.../site-packages/`.
   `grep` and `inspect.getsource` answer most questions in seconds.
2. The vendor's **official documentation** (Microsoft Learn, Google API
   reference, etc.) for HTTP-level contracts the SDK wraps — error codes,
   filter syntax, pagination semantics.
3. The SDK's **GitHub issues** for known bugs and maintainer-recommended
   patterns. Be wary of community workarounds in stale threads.

Don't use parsedmarc, third-party blogs, or "what the original code did"
as primary evidence. They're useful as "where to look next," not as a
source of truth.

### Lessons learned (Microsoft Graph SDK — `msgraph-sdk-python`)

- **Retries are built-in.** `kiota_http`'s `RetryHandler` is part of the
  default middleware pipeline (`max_retries=3`, exponential backoff on
  `{429, 503, 504}`). Don't add an application-level retry layer; it's
  redundant and competes with the SDK's behavior.
- **Sync wrapper requires a persistent event loop.** The SDK is
  async-only. `GraphRequestAdapter` holds a single `httpx.AsyncClient`
  whose connection pool binds to the loop on first request — closing
  that loop (e.g. via `asyncio.run` per call) invalidates the pool and
  the next call surfaces as `RuntimeError: Event loop is closed`. Keep
  one loop alive across calls (see `mailbox/graph.py:_run`). Microsoft
  publishes no official sync-wrapper recipe; this is the
  community-converged shape (see msgraph-sdk-python issues #366, #787,
  #798).
- **HTTP error detection: use `response_status_code`.** `ODataError`
  inherits from `kiota_abstractions.api_error.APIError` and the
  `response_status_code` attribute is set explicitly before raising
  (see `kiota_http/httpx_request_adapter.py:throw_failed_responses`).
  Check that, not the exception's string representation —
  string-matching is fragile to error-message localization and SDK
  changes.
- **OData `$filter` strings need manual escaping.** The SDK provides no
  helper. Per the [Graph query parameters
  docs](https://learn.microsoft.com/en-us/graph/query-parameters),
  single quotes inside string literals must be doubled (`'` → `''`).
  Always escape user-supplied values before substituting into a
  filter expression.
- **The `with_url(next_link).get()` pattern follows OData pagination.**
  Generated request builders expose `with_url(raw_url)` for following
  `@odata.nextLink`. Kiota's `PageIterator` is an alternative but not
  required.

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
