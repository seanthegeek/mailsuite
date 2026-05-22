# mailsuite

[![PyPI](https://img.shields.io/pypi/v/mailsuite)](https://pypi.org/project/mailsuite/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mailsuite?color=blue)](https://pypistats.org/packages/mailsuite)

A Python package for retrieving, parsing, and sending emails.

## Features

- Provider-agnostic mailbox abstraction (`mailsuite.mailbox`)
  - Single `MailboxConnection` interface for IMAP, Microsoft Graph, Gmail,
    and on-disk Maildir
  - Fetch message identifiers from any folder, retrieve their raw RFC 822
    content, and move or delete messages
  - Folder management across every backend — create, rename, move, merge,
    delete, and existence checks, with consistent `FolderExistsError` /
    `FolderNotFoundError` semantics
  - Watch a folder for new messages — the IMAP `IDLE` command (with periodic
    session refresh) on the IMAP backend, polling on the cloud backends
  - Unified `send_message()` on backends that support sending (Microsoft
    Graph, Gmail) — IMAP and Maildir users send through
    `mailsuite.smtp.send_email`
  - OAuth2 (XOAUTH2 / OAUTHBEARER) login for IMAP, reconnecting automatically
    after dropped connections and timeouts
  - Always uses `/` as the folder hierarchy separator, converting to the
    server's separator and prepending its namespace automatically, and
    stripping folder-name characters that collide with the separator
  - Works around backend quirks across Gmail, Microsoft 365, Exchange,
    Dovecot, and DavMail, including:
    - Gmail / Google Workspace returning an empty `IDLE` response
    - Random Microsoft 365 / Exchange `BAD` / "unexpected response" errors
    - Nonstandard hierarchy separators and namespaces
- Consistent email parsing
  - SHA256 hashes of attachments
  - Parsed `Authentication-Results` and `DKIM-Signature` headers
  - Parse Microsoft Outlook `.msg` files using `msgconvert`
- Simplified email creation and sending
  - Easily add attachments, plain text, and HTML
  - Uses opportunistic encryption (`STARTTLS`) with SMTP by default
- DKIM signing and verification
  - Generate RSA keypairs and the matching DNS TXT record
  - Sign outbound mail with a sensible default header set (with `From`,
    `To`, `Cc`, `Subject` oversigned)
  - Verify one or many `DKIM-Signature` headers on a received message
- ARC (Authenticated Received Chain) sealing and verification
  - Seal forwarded mail with an ARC set, extending an existing chain
  - Verify the ARC chain on a received message and read its `cv` result

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

### Microsoft Graph permissions

Grant the appropriate Microsoft Graph **API permissions** on the app
registration based on which `MSGraphConnection` operations you need.
Combine permissions across rows when you need multiple capabilities —
e.g., to both read and send mail in a delegated flow against your own
mailbox, grant `Mail.ReadWrite` and `Mail.Send`.

| Use case | Delegated (own mailbox) | Delegated (shared mailbox) | App-only |
| --- | --- | --- | --- |
| Read messages only (`fetch_message`, `fetch_messages`) | `Mail.Read` | `Mail.Read.Shared` | `Mail.Read` |
| Read + modify (mark read, delete, move, create folder) | `Mail.ReadWrite` | `Mail.ReadWrite.Shared` | `Mail.ReadWrite` |
| Send mail (`send_message`) | `Mail.Send` | `Mail.Send.Shared` | `Mail.Send` |

Delegated flows (`DeviceCode`, `UsernamePassword`) targeting a shared
mailbox — i.e. when the `mailbox` argument differs from `username` —
use the `.Shared` variants. App-only flows (`ClientAssertion`, `ClientSecret`,
`Certificate`) do not need the `.Shared` variants since application
permissions span every mailbox in the tenant (unless restricted by an
[Application Access Policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access)).

For delegated flows, `MSGraphConnection` requests `Mail.ReadWrite` (or
`Mail.ReadWrite.Shared`) at authenticate time, so even read-only
callers must consent to at least `Mail.ReadWrite`. App-only flows
authenticate with `https://graph.microsoft.com/.default`, which grants
whichever permissions the app registration has consented.
