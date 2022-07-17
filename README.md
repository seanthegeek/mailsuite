# mailsuite

![PyPI](https://img.shields.io/pypi/v/mailsuite)
![PyPI - Downloads](https://img.shields.io/pypi/dm/mailsuite?color=blue)

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

### Working with .msg files

If you would like to be able to parse Microsoft Outlook `.msg`
emails, you'll need to install the `Email::Outlook::Message` Perl module, which
includes the `msgconvert` utility that is used to convert `.msg` files into the
standard RFC 822 format. Ubuntu and Debian make this easy because they have a
package for it, `libemail-outlook-message-perl`. On 
Fedora/RHEL/CentOS based distributions and macOS, you'll need to install
[Perlbrew][perlbrew].

Perlbrew installs a local copy of Perl within the user's home directory,
similar to how Homebrew works (which is why the initial installation can take
a while). That way, you don't need to use `sudo` to  install Perl modules, and 
risk breaking your system's Perl installation in the process.

Once Perlbrew is installed, use `cpan` to install `Email::Outlook::Message`.

[perlbrew]: https://perlbrew.pl/