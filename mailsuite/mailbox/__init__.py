"""Provider-agnostic mailbox abstractions

Lifted from parsedmarc so any application can read/manage mail across IMAP,
Microsoft Graph, Gmail, or a local Maildir behind a single interface.

The ``MSGraphConnection`` and ``GmailConnection`` backends require optional
extras (``mailsuite[msgraph]`` and ``mailsuite[gmail]``). They are loaded
lazily — importing this package never requires those extras to be installed,
but referencing the class will surface a clear error if they aren't.
"""

from typing import TYPE_CHECKING

from mailsuite.mailbox.base import MailboxConnection
from mailsuite.mailbox.imap import IMAPConnection
from mailsuite.mailbox.maildir import MaildirConnection

if TYPE_CHECKING:
    from mailsuite.mailbox.gmail import GmailConnection
    from mailsuite.mailbox.graph import MSGraphConnection

__all__ = [
    "MailboxConnection",
    "IMAPConnection",
    "MaildirConnection",
    "MSGraphConnection",
    "GmailConnection",
]


def __getattr__(name: str):
    if name == "MSGraphConnection":
        from mailsuite.mailbox.graph import MSGraphConnection

        return MSGraphConnection
    if name == "GmailConnection":
        from mailsuite.mailbox.gmail import GmailConnection

        return GmailConnection
    raise AttributeError(f"module 'mailsuite.mailbox' has no attribute {name!r}")
