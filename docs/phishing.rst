Automating phishing report inbox triage
=======================================

Through a combination authentication header parsing and YARA rules,
``mailsuite`` can be used to create customized automation for triaging
phishing reports from users.

Best practice
-------------

It is **strongly recommended** to develop, store, and maintain YARA rules,
trusted domain lists, and sample emails in a private Git repository, for a
number of reasons.

- Version control tracks who made what change when, with easy rollback
- Automations can (and should) pull a fresh copy of the repository
  before scanning
- CI/CD workflows can run tests against a collection of emails samples before
  allowing the rules into production

Check if an email is trusted
----------------------------

Use the ``from_trusted_domain()`` function in ``mailsuite.utils`` to check
results of DKIM and/or DMARC in the ``Authentication-Results`` header
against a list of trusted domains.

The ``Authentication-Results`` header is added by the receiving mail server
as a way of logging the results of authentication checks that prove that
the domain in the message ``From`` header was not spoofed. Most email services
— including Microsoft 365 and Gmail — use a single ``Authentication-Results``
header to log the results of all authentication checks. By default
``from_trusted_domain()`` will always return ``False`` if multiple
``Authentication-Results`` headers are found in an email. This is done to
avoid false positives when an attacker adds their own
``Authentication-Results`` header to an email before it reaches the destination
mail server.

Some mail services (e.g., Proton Mail) use a separate
``Authentication-Results`` header for each authentication check. If your mail
service does this, set the ``allow_multiple_authentication_results``
parameter to ``True``. This wall allow multiple headers, but will return
``False`` if multiple DKIM results are found, to avoid malicious results.

.. warning ::
  Authentication results are not verified by this function, so only use it on
  emails that have been received by trusted mail servers, and not on
  third-party emails.

.. warning::
  Only set ``allow_multiple_authentication_results`` to ``True`` if the
  receiving mail service splits the results of each authentication method
  in separate ``Authentication-Results`` headers **and always** includes DKIM
  results, even when a DKIM signature is not present.

For additional security, check the content of emails in addition to checking
authentication results. This adds another layer of defense when phishing emails
are sent by a trusted sender. `YARA rules`_ provide a flexable method of
checking the contents of email headers, body, and attachment content against
known malicious and trusted patterns.

For example, the following YARA rule could be used to ensure that all URLs
in an email body match the domain of a vendor.

.. code-block::

  rule all_urls_example_vendor : urls {
  // YARA rules can include C-style comments like this one

  /*
  The " : urls" after the rule name sets an optional namespace
  that can be useful for organizing rules.
  The default namespace is "default".

  The meta section contains arbitrary key-value pairs that are
  included in matches. That way the scanner has more context about
  the meaning of the rule.
  */

  meta:
      author = "Sean Whalen"
      date = "2022-07-13"
      category = "safe"
      description = "All URLs are for the example.com domain"

  /*
  The strings section defines the patterns that can be used in the rule.
  These can be strings, byte patterns, or even regular expressions!
  */

  strings:
      // Match ASCII and wide strings and ignore the case
      $http = "http" ascii wide nocase
      $example_url = "https://example.com" ascii wide nocase

  condition:
      // The total number of URLs must match the number of example.com URls
      #http == #example
  }

The ``MailScanner`` class in the ``mailsuite.scanner`` module provides a YARA
scanner specifically designed for scanning emails. ``libyara`` is built by the
upstream ``yara`` package that is installed as a dependency of ``mailsuite``,
so no additional installation is needed.

When creating an instance of ``MailScanner``, provide paths to ``.yar`` files
That contain rules for different parts of an email. Don't worry if you don't
have rules for each part yet you can use empty files.

- ``header_rules`` - Rules that apply to email header content only
- ``header_body_rules`` - Rules that apply to email header **and/or** body
  content
- ``body_rules`` - rules that apply to email body content only
- ``attachment_rules`` - Rules that apply to email attachment content only

.. note::
  Use the `include`_ directive in include rules from other files. That way,
  rules can be divided into separate files as you see fit, then include those
  files in the files you pass to ``MailScanner``.

To scan an email, pass the output from ``utils.parse_email()`` to
``MailScanner.scan_email()``,  which will return a list of match dictionaries.
Each match dictionary contains the following key-value pairs:

- ``name`` - The name of the rule
- ``namespace`` - The namespace
- ``meta`` - A dictionary of key-value pairs from the rule's meta section
- ``tags`` - A list of the rule's tags
- ``strings`` - A list of identified strings or patterns that match the rule

  0. The location offset of the identified string/pattern in the input
  1. The variable name of the string/pattern in the rule
  2. The matching string/pattern content

- ``location`` - The part of the email where the match was found

  - ``header``
  - ``body``
  - ``header_body``
  - ``attachment:filename``
  - ``attachment:example.zip:evil.js``
  - ``attachment:first.zip:nested.zip:evil.js``
  - ``attachment:evil.eml:attachment:example.zip:evil.js``

Check if an email is malicious
------------------------------

Impersonating a top executive is a classic social engineering technique. Even
if a target organisation has fully implemented DMARC to prevent domain
spoofing, people can still be impersonated in the display name of the
message ``From`` header, or in the email body. A YARA rule can check for this.
`Regular Expressions`_ (regex) are handy, because one string can match a wide
variety of name variations.

Most organisations add something to the beginning of an email subject or body
to let the user know that the email came from an external, untrusted source.
This can be leveraged in a YARA rule to identify external emails that include
the name of an executive or board member in the email headers or body. You can
also add patterns to make exceptions to the rule. This is useful for dealing
with false positives. An exemption to a malicious rule **does not** mean that
the content is safe — it only means that the rule cannot be used for that
content.

.. note::
  If an external email tag is not in use, an alternative approach is using the
  previously mentioned ``from_trusted_domain()`` function in Python when an
  analyzing an email.

.. code-block::

  rule exec_impersonation {
      meta:
          author = "Sean Whalen"
          date = "2022-07-14"
          category = "social engineering"
          description = "Impersonation of key employees of Planet Express in an external email"

      /*
      /(Hubert|Prof\.?(essor)?) (Hubert )?Farnsworth/

      Hubert Farnsworth
      Professor Farnsworth
      Prof. Farnsworth
      Prof Farnsworth
      Professor Hubert Farnsworth
      Prof. Hubert Farnsworth
      Prof Hubert Farnsworth

      /Phil(ip)? (J\.? )?Fry/

      Philip Fry
      Philip J. Fry
      Philip J Fry
      Phil Fry
      Phil J. Fry
      Phil J Fry
      */

      strings:
          $external = "[EXT]" ascii wide nocase
          $s1 = /(Hubert|Prof\.?(essor)?) (Hubert )?Farnsworth/ ascii wide nocase
          $s2 = "Hermes Conrad" ascii wide nocase
          $s3 = "Turanga Leela" ascii wide nocase
          $s4 = "Amy Wong" ascii wide nocase
          $s5 = /Phil(ip)? (J\.? )?Fry/
          $except_slug = "Brain Slug Fundraiser" ascii wide

      condition:
          $external and any of ($s*) and not any of ($except_*)
    }

This was a very simple, practical example. YARA was developed to identify and
classify malware, so it is capable of much more complex pattern matching.
That the time to read over YARA's documentation and other resources.

Check if an email is junk
-------------------------

Users will often send marketing (i.e., junk) mail to a phishing report inbox,
which can be a significant contributor to alert fatigue for those who are
triaging the inbox. YARA rules can help reduce this noise.

Start by looking through junk emails that have been reported. Make note of
words or phrases that are common across different marketing campaigns,
businesses, and industries. Some common examples include:

- discount
- trial
- coupon
- webinar
- subscribe
- ROI
- development
- offer
- price
- cost

Then

.. _YARA rules: https://yara.readthedocs.io/en/stable/writingrules.html
.. _include: https://yara.readthedocs.io/en/stable/writingrules.html#including-files
.. _Regular Expressions: https://yara.readthedocs.io/en/stable/writingrules.html#regular-expressions