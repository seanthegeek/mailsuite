1.3.0
-----

- Set a configurable default IMAP timeout of 30 seconds
- Set a configurable maximum of 4 IMAP timeout retry attempts

1.2.1
-----

- Fix IMAP hierarchy separator parsing

1.2.0
-----

- Add support for sending emails with custom message headers
- Add ``parsedmarc.utils.create_email`` function

1.1.1
-----

- Fix error when sending email with no attachments
- Correct ``mailsuite.__version__``

1.1.0
-----

- Always use ``/`` as the folder hierarchy separator, and convert to the
  server's hierarchy separator in the background
- Always remove folder name characters that conflict with the server's
  hierarchy separators
- Prepend the namespace to the folder path when required

1.0.0
-----

- Initial release
