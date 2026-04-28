"""Provider-agnostic mailbox abstractions

Lifted from parsedmarc so any application can read/manage mail across IMAP,
Microsoft Graph, Gmail, or a local Maildir behind a single interface.
"""

from mailsuite.mailbox.base import MailboxConnection
from mailsuite.mailbox.imap import IMAPConnection
from mailsuite.mailbox.maildir import MaildirConnection

__all__ = [
    "MailboxConnection",
    "IMAPConnection",
    "MaildirConnection",
]
