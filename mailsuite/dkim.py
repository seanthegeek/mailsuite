"""DKIM key management and email signing utilities"""

import base64
import email
import logging
from typing import Callable, Optional, Tuple, Union

import dkim as _dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DEFAULT_SIGNED_HEADERS = [
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "From",
    "To",
    "Cc",
    "Subject",
]


class DKIMError(RuntimeError):
    """Raised when a DKIM error occurs"""


def generate_dkim_private_key(key_size: int = 2048) -> str:
    """
    Generates a new RSA private key suitable for DKIM signing

    Args:
        key_size: The RSA key size in bits (1024 minimum, 2048 recommended)

    Returns: A PEM-encoded private key string
    """
    if key_size < 1024:
        raise ValueError("key_size must be at least 1024")
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


def get_dkim_public_key(private_key: Union[str, bytes]) -> str:
    """
    Derives the DKIM public key from a private key

    Args:
        private_key: A PEM-encoded RSA private key (PKCS#1 or PKCS#8)

    Returns: A base64-encoded ``SubjectPublicKeyInfo`` value (suitable for the
        ``p=`` tag of a DKIM TXT record)
    """
    if isinstance(private_key, str):
        key_bytes = private_key.encode("ascii")
    else:
        key_bytes = bytes(private_key)
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as e:
        raise DKIMError(f"Failed to load private key: {e}")
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def generate_dkim_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Generates a DKIM RSA keypair

    Args:
        key_size: The RSA key size in bits (1024 minimum, 2048 recommended)

    Returns: A tuple of ``(private_key_pem, public_key_b64)``
    """
    private_key = generate_dkim_private_key(key_size=key_size)
    public_key = get_dkim_public_key(private_key)
    return private_key, public_key


def generate_dkim_txt_record(
    public_key: Union[str, bytes],
    selector: str = "default",
    domain: Optional[str] = None,
    flags: Optional[str] = None,
    note: Optional[str] = None,
) -> str:
    """
    Generates a DKIM TXT record

    Args:
        public_key: A base64-encoded public key, or a PEM-encoded private or
            public key (the base64 is extracted automatically)
        selector: The DKIM selector
        domain: An optional domain. When provided, the return value includes
            the full DNS owner name (``selector._domainkey.domain``) so it
            shows exactly where the record must be placed.
        flags: An optional value for the ``t=`` flags tag (e.g. ``"y"`` for
            testing mode)
        note: An optional value for the ``n=`` notes tag

    Returns:
        When ``domain`` is given, the full DNS record (owner name, class,
        type, and quoted value) as a single line. Otherwise, just the record
        value (``v=DKIM1; ...``).
    """
    if isinstance(public_key, str):
        key_str: str = public_key.strip()
    else:
        key_str = bytes(public_key).decode("ascii").strip()

    key_b64: str
    if "BEGIN" in key_str and "PRIVATE KEY" in key_str:
        key_b64 = get_dkim_public_key(key_str)
    elif "BEGIN" in key_str and "PUBLIC KEY" in key_str:
        try:
            pub = serialization.load_pem_public_key(key_str.encode("ascii"))
        except Exception as e:
            raise DKIMError(f"Failed to load public key: {e}")
        der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_b64 = base64.b64encode(der).decode("ascii")
    else:
        key_b64 = "".join(key_str.split())

    tags = ["v=DKIM1", "k=rsa"]
    if flags:
        tags.append(f"t={flags}")
    if note:
        tags.append(f"n={note}")
    tags.append(f"p={key_b64}")
    record_value = "; ".join(tags)

    if domain:
        owner = f"{selector}._domainkey.{domain.rstrip('.')}."
        return f'{owner}\tIN\tTXT\t"{record_value}"'
    return record_value


def sign_email(
    message: Union[str, bytes],
    selector: str,
    domain: str,
    private_key: Union[str, bytes],
    additional_headers: Optional[list[str]] = None,
    canonicalize: Tuple[bytes, bytes] = (b"relaxed", b"relaxed"),
    identity: Optional[str] = None,
) -> Union[str, bytes]:
    """
    DKIM-signs an email and returns the signed RFC 822 message

    The default set of headers signed includes ``From``, ``To``, ``Cc``,
    ``Reply-To``, ``Subject``, ``Date``, ``Message-ID``, ``In-Reply-To``,
    ``References``, ``MIME-Version``, ``Content-Type``,
    ``Content-Transfer-Encoding``, ``List-Unsubscribe``, and
    ``List-Unsubscribe-Post`` — with ``From``, ``To``, ``Cc``, and ``Subject``
    oversigned (signed twice) to prevent header addition attacks. Headers
    that are not present in the message are skipped.

    Args:
        message: An RFC 822 message
        selector: The DKIM selector
        domain: The signing domain
        private_key: A PEM-encoded RSA private key
        additional_headers: Additional header names to sign. Headers not
            present in the message are skipped.
        canonicalize: A tuple of (header, body) canonicalization algorithms.
            Defaults to ``(b"relaxed", b"relaxed")``.
        identity: An optional ``i=`` value (defaults to ``@`` + ``domain``)

    Returns: The signed RFC 822 message. The return type matches the input
        type — ``str`` in, ``str`` out; ``bytes`` in, ``bytes`` out.
    """
    if isinstance(message, str):
        message_bytes: bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    if isinstance(private_key, str):
        private_key_bytes: bytes = private_key.encode("ascii")
    else:
        private_key_bytes = bytes(private_key)

    selector_bytes = selector.encode("ascii")
    domain_bytes = domain.encode("ascii")

    headers_to_sign = list(DEFAULT_SIGNED_HEADERS)
    if additional_headers:
        headers_to_sign.extend(additional_headers)

    parsed = email.message_from_bytes(message_bytes)
    present = {key.lower() for key in parsed.keys()}

    include = [
        header.encode("ascii")
        for header in headers_to_sign
        if header.lower() in present
    ]

    if not any(h.lower() == b"from" for h in include):
        raise DKIMError("Cannot DKIM-sign a message without a From header")

    sign_kwargs = {"canonicalize": canonicalize, "include_headers": include}
    if identity is not None:
        sign_kwargs["identity"] = identity.encode("utf-8")

    try:
        signature = _dkim.sign(
            message_bytes,
            selector_bytes,
            domain_bytes,
            private_key_bytes,
            **sign_kwargs,
        )
    except _dkim.DKIMException as e:
        raise DKIMError(str(e))

    signed = signature + message_bytes
    if isinstance(message, str):
        return signed.decode("utf-8", errors="replace")
    return signed


def verify_email(
    message: Union[str, bytes],
    timeout: float = 5.0,
    minkey: int = 1024,
    dns_func: Optional[Callable[[str], bytes]] = None,
) -> dict:
    """
    Verifies the DKIM signature(s) on an RFC 822 message

    Each ``DKIM-Signature`` header in the message is verified independently
    via DNS. The result reports per-signature outcomes plus an overall
    ``valid`` flag (``True`` when at least one signature verifies).

    Args:
        message: An RFC 822 message
        timeout: DNS lookup timeout in seconds
        minkey: The minimum acceptable RSA key size in bits
        dns_func: An optional function taking a DNS name and returning the
            raw TXT record value as bytes. Useful for testing or for using
            a custom resolver. Defaults to dkimpy's built-in resolver.

    Returns: A dict with the following keys:

        - ``valid`` (``bool``): ``True`` if at least one signature verified
        - ``signatures`` (``list``): per-signature results, each a dict with:

          - ``domain`` (``str``): the ``d=`` signing domain
          - ``selector`` (``str``): the ``s=`` selector
          - ``valid`` (``bool``): whether this signature verified
          - ``error`` (``str`` or ``None``): error message when ``valid`` is \
            ``False``, otherwise ``None``
    """
    if isinstance(message, str):
        message_bytes: bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    verifier = _dkim.DKIM(message_bytes, minkey=minkey, timeout=int(timeout))
    sig_headers = [
        (name, value)
        for name, value in verifier.headers
        if name.lower() == b"dkim-signature"
    ]

    signatures: list[dict] = []
    overall_valid = False

    for idx, (_, raw_value) in enumerate(sig_headers):
        sig_info: dict = {
            "domain": None,
            "selector": None,
            "valid": False,
            "error": None,
        }
        try:
            parsed = _dkim.parse_tag_value(raw_value)
            if b"d" in parsed:
                sig_info["domain"] = parsed[b"d"].decode("ascii", errors="replace")
            if b"s" in parsed:
                sig_info["selector"] = parsed[b"s"].decode("ascii", errors="replace")
        except _dkim.InvalidTagValueList as e:
            sig_info["error"] = f"Malformed DKIM-Signature header: {e}"
            signatures.append(sig_info)
            continue

        try:
            ok = (
                verifier.verify(idx=idx, dnsfunc=dns_func)
                if dns_func is not None
                else verifier.verify(idx=idx)
            )
            sig_info["valid"] = bool(ok)
            if not ok:
                sig_info["error"] = "Signature did not verify"
        except _dkim.DKIMException as e:
            sig_info["error"] = str(e)
        except Exception as e:
            sig_info["error"] = f"Verification error: {e}"

        if sig_info["valid"]:
            overall_valid = True
        signatures.append(sig_info)

    return {"valid": overall_valid, "signatures": signatures}
