# mailsuite

[![PyPI](https://img.shields.io/pypi/v/mailsuite)](https://pypi.org/project/mailsuite/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mailsuite?color=blue)](https://pypistats.org/packages/mailsuite)

A Python package for retrieving, parsing, and sending emails.

## Features

- Simplified IMAP client
  - Retrieve email from any folder
  - Create new folders
  - Move messages to other folders
  - Delete messages
  - Monitor folders for new messages using the IMAP ``IDLE`` command
  - Always use ``/`` as the folder hierarchy separator, and convert to the
    server's hierarchy separator in the background
  - Always remove folder name characters that conflict with the server's
    hierarchy separators
  - Prepend the namespace to the folder path when required
  - Automatically reconnect when needed
  - Work around quirks in Gmail, Microsoft 365, Exchange, Dovecot, and
    DavMail
- Consistent email parsing
  - SHA256 hashes of attachments
  - Parsed ``Authentication-Results`` and ``DKIM-Signature`` headers
  - Parse Microsoft Outlook ``.msg`` files using `msgconvert`
- Simplified email creation and sending
  - Easily add attachments, plain text, and HTML
  - Uses opportunistic encryption (``STARTTLS``) with SMTP by default
- DKIM signing and verification
  - Generate RSA keypairs and the matching DNS TXT record
  - Sign outbound mail with a sensible default header set (with `From`,
    `To`, `Cc`, `Subject` oversigned)
  - Verify one or many `DKIM-Signature` headers on a received message
- Provider-agnostic mailbox abstraction (`mailsuite.mailbox`)
  - Single `MailboxConnection` interface for IMAP, Microsoft Graph,
    Gmail, and on-disk Maildir
  - Unified `send_message()` on backends that support sending (Microsoft
    Graph, Gmail) — IMAP and Maildir users send through
    `mailsuite.smtp.send_email`

## Installation

Base install (IMAP, SMTP, DKIM, Maildir, parsing):

```bash
pip install mailsuite
```

The Microsoft Graph and Gmail backends are optional extras — the cloud
SDKs aren't pulled in unless you ask for them:

```bash
pip install "mailsuite[msgraph]"   # Microsoft Graph (msgraph-sdk + azure-identity)
pip install "mailsuite[gmail]"     # Gmail (google-api-python-client + google-auth-oauthlib)
pip install "mailsuite[all]"       # both
```

Importing `mailsuite.mailbox` never requires the extras. Referencing
`MSGraphConnection` or `GmailConnection` without the matching extra
installed raises an `ImportError` pointing at the right install command.

## Microsoft Graph notes

`MSGraphConnection` defaults to the worldwide cloud
(`https://graph.microsoft.com`). To target a sovereign cloud or any
other Graph endpoint, pass `graph_url`:

```python
MSGraphConnection(..., graph_url="https://graph.microsoft.us")
```

The `azure-identity` token cache lives under `name="mailsuite"` by
default. Applications migrating from a previous installation that used a
different cache name can pass it through `token_cache_name=` so existing
cached `AuthenticationRecord`s and tokens continue to work — for
example, `token_cache_name="parsedmarc"` keeps users authenticated
across the migration.
