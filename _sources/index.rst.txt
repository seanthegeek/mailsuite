=========
mailsuite
=========

A Python package to simplify receiving, parsing, and sending email

Features
--------

- Receive emails via IMAP

  - Retrieve email from any folder
  - Create new folders
  - Move messages to other folders
  - Delete messages
  - Monitor folders for new messages
  - Automatically reconnect when needed
  - Work around quirks in Gmail/G-suite, Office 365, Exchange, and Dovcot

- Consistent email parsing
- Simplified email sending via SMTP

  - Uses opportunistic encryption (``STARTTLS``) by default
  - Easily add attachments, plain text, and HTML

API
---

.. automodule:: mailsuite
   :members:

Indices and tables
------------------

* :ref:`genindex`
