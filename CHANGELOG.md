Changelog
=========

1.9.14
------

- Email parsing improvements
  - Parse out email addresses in the `Delivered-To` header
  - Rename `reply_to` key to `reply-to`
    - Replaces formatting provided by `mailparser` with parsed out email addresses that match the rest of the output

1.9.13
------

- Normalize the case of a header name when testing header values.

1.9.12
------

- Ignore all `dmarc` `Authentication-Results` if multiple `dmarc` results are found

1.9.11
------

- Strip leading and trailing spaces from `DKIM-Signature` header `h=` list items

1.9.10
------

- Fix parsing of `Authentication-Results` and `DKIM-Signature` headers when Windows line breaks (`\r\n`) are used

1.9.9
-----

- Fix header and body separation when Windows line breaks (`\r\n`) are used

1.9.8
-----

- Fix parsing of email addresses in message `From` headers with encoded display names.

1.9.7
-----

- Fix regression causing noisy `mailparser` log messages to reappear
- Rename `urls` list to `body_urls`

1.9.6
-----

- Add `urls` list to parsed `utils.parse_email()` results

1.9.5
-----

- In `utils.from_trusted_domain()`,  if `use_authentication_results_original` is `True`, but the `Authentication-Results-Original` header does not exist, fall back to checking the `Authentication-Results` header

1.9.4
-----

- Add `automatic_reply` flag to parsed emails

1.9.3
-----

- Fix crash when parsing some `DKIM-Signature` headers
- Fix `from_trusted_domain()` DMARC check
- Don't convert plain text email bodies to markdown
- Always include `body_markdown` in parsed results
- Decode utf-8 encoded `Subject` and `Thread-Topic` headers in `headers_str`
- Silence noisy `mailparser` log output

1.9.2
-----

- Remove some documentation from `README.md`, so the PyPI listing won't have outdated info
- Add `Issues` and `Changelog` URLs to the PyPI listing

1.9.1
-----

- Add warnings about `msgconvert` not being suitable for forensics

1.9.0
-----

- Fix multiple bugs in `mailsuite.utils.from_trusted_domain()`
- By default, `mailsuite.utils.from_trusted_domain()` will now return `True` if the SLD or FQDN of an authenticated domain is in `trusted_domains`
- Convert documentation to markdown
- Convert build backend from `setuptools` to `hatch`

1.8.2
-----

- Raise `ValueError` when trying to parse something that isn't an email

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
- Disable wrapping on markdown to make searching strings with YARA or other tools easier

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
