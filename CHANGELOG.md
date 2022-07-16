Changelog
=========

1.8.1
-----

- Fix error when calling `utils.from_trusted_domain()`
- Fix outdated package version number
- Accept a file path as possible input for the `data` argument in `utils.parse_email()`


1.8.0
-----

- Parse `Authentication-Results` and `DKIM-Signature` headers
- Add `utils.from_trusted_domain()`
- Parsed header keys and values are now stored at the root of the parsed email dictionary, instead of in a `headers` dictionary 
- Add `raw_headers` to parsed email output

7.1.3
-----

- Fix `publicsuffix2` warning

1.7.2
-----

- Properly hash binary attachments

1.7.1
-----

- Fix `headers_string` value in parsed emails

1.7.0
-----

- Use `STARTTLS` in `IMAPClient` before login if the server supports it (PR #2)
- Properly handle cases where the IMAP separator is `None` (PR #4)
- Retry operations when disconnected from the server (PR #5)
- Add support for certificate authentication in IMAP (PR # 7)
- Changes to email parsing
  - Every header is now included as its own dictionary entry
  - Remove redundant `headers` subdictionary
  - Parse and normalize `Authentication-Results`, `Authentication-Results-Original`. amd `DKIM-Signature` headers
  - `headers_str` now contains the full headers with indentations removed
  - `raw_headers` includes the full headers without any modifications
  - Add `base_domain` entry to `parse_email_address()` output
- Remove `six` requirement
- Set required `mail-parser` version to `>=1.14.0`
- Set required `dnspython` version to `>=2.0.0`

1.6.0
-----

- Remove copies of email headers from the root of the returned dictionary (still available under `headers`
- Store the HTML body in body in `body`, or the text body if an HTML body does not exist
- Store all body parts as a string in `raw_body`
- Only run `html2text` on HTML bodies
- Disable wrapping on markdown to make searching strings with Yara or other tools easier

1.5.4
-----

- Improve `get_filename_safe_string()`

1.5.3
------

- Fix version numbering

1.5.2
-----

- Pin some dependency versions to avoid conflicts

  - `six==1.13.0`
  - `mail-parser==3.11.0`

1.5.1
-----

- Require `mail-parser>=3.11.0` ro avoid dependency problems

1.5.0
-----

- Add `body_markdown` to `parse_email()` results

1.4.0
-----

- Add `headers_string` to parsed output

1.3.1
-----

- Do not remove leading `/` from folder names

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
- Add `parsedmarc.utils.create_email` function

1.1.1
-----

- Fix error when sending email with no attachments
- Correct `mailsuite.__version__`

1.1.0
-----

- Always use `/` as the folder hierarchy separator, and convert to the
  server's hierarchy separator in the background
- Always remove folder name characters that conflict with the server's
  hierarchy separators
- Prepend the namespace to the folder path when required

1.0.0
-----

- Initial release
