# mailsuite

[![PyPI](https://img.shields.io/pypi/v/mailsuite)](https://github.com/seanthegeek/mailsuite/)
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
  - Can parse Microsoft Outlook ``.msg`` files
- Simplified email creation and sending
  - Easily add attachments, plain text, and HTML
  - Uses opportunistic encryption (``STARTTLS``) with SMTP by default

## Email samples and Outlook clients

### Microsoft Outlook for Windows

If you save an email to a file using Microsoft Outlook on Windows, it will
save the file in a proprietary Microsoft OLE format with a `.msg` extension.
There are tools like `msgconvert` that make an attempt to convert a `.msg`
file to a standard RFC 822 `.eml` file, and `mailsuite` will attempt to use
this tool when encountering a `.msg` file if it is installed on the system.
However, anomalies are introduced during conversion that make the results
unsuitable for forensic analysis.

Instead of using `msgconvert`, use one of these other Outlook clients.

### Microsoft Outlook for macOS

Drag the email from the inbox or other folder and drop it on the desktop.
Attached emails can be saved to a file like any other attachment.

### Outlook Web Access (OWA)

1. Create a new email and leave it open a separate window.
2. Drag from the inbox or other folder and drop it in the message of the draft.
3. Download the attachment that was created in step 2

Emails that are already attached to an email can be downloaded from OWA like
any other attachment.