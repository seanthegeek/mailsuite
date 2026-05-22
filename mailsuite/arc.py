"""Authenticated Received Chain (ARC) sealing and verification (RFC 8617)

ARC lets a sequence of intermediaries (mailing lists, forwarders, gateways)
record the email authentication results they observed, so that a later
receiver can trust those results even when SPF/DKIM/DMARC break in transit.
Each hop adds an *ARC set* of three header fields keyed by an instance
number (``i=``):

* ``ARC-Authentication-Results`` (AAR) — a snapshot of the
  ``Authentication-Results`` this hop produced.
* ``ARC-Message-Signature`` (AMS) — a DKIM-like signature over the message
  as this hop saw it.
* ``ARC-Seal`` (AS) — a signature over the ARC header fields, binding the
  chain together and recording its cumulative validity (``cv=``).

This module wraps ``dkimpy``'s ARC implementation behind an API shaped
like :mod:`mailsuite.dkim`.
"""

import logging
from typing import Any, Callable, List, Optional, Union

import dkim as _dkim

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ARCError(RuntimeError):
    """Raised when an ARC error occurs"""


def seal_email(
    message: Union[str, bytes],
    selector: str,
    domain: str,
    private_key: Union[str, bytes],
    authserv_id: str,
    signed_headers: Optional[List[str]] = None,
    timestamp: Optional[int] = None,
) -> Union[str, bytes]:
    """
    Adds an ARC set (seal) to an email and returns the sealed RFC 822 message

    The new ARC set is prepended to the message. If the message already
    carries one or more ARC sets, this adds the next instance and extends
    the chain.

    The message **must** contain an ``Authentication-Results`` header whose
    authserv-id equals ``authserv_id`` — that is the authentication this hop
    is attesting to, and it is copied into the ``ARC-Authentication-Results``
    header. Per RFC 8617 the chain is sealed only when such results exist. If
    none match — or, when extending an existing chain, the matching results
    record no prior ARC result (``arc=``) to continue from — no ARC set is
    produced and :class:`ARCError` is raised.

    Args:
        message: An RFC 822 message
        selector: The DKIM selector for the sealing domain
        domain: The sealing (ADMD) domain
        private_key: A PEM-encoded RSA private key
        authserv_id: The authentication-service identifier of this hop (the
            authserv-id used in its ``Authentication-Results`` headers, often
            the receiving host's name). Only ``Authentication-Results``
            headers carrying this id are folded into the seal.
        signed_headers: Header names the ``ARC-Message-Signature`` should
            cover. Defaults to dkimpy's recommended set — the headers present
            in the message that it lists as SHOULD-sign (``From``, ``To``,
            ``Cc``, ``Subject``, ``Date``, ``Message-ID``, the ``List-*``
            headers, etc.), with ``From`` oversigned. ``From`` must be
            included.
        timestamp: The ``t=`` value (epoch seconds) stamped into the AMS and
            AS. Defaults to the current time.

    Returns: The sealed RFC 822 message. The return type matches the input
        type — ``str`` in, ``str`` out; ``bytes`` in, ``bytes`` out.

    Raises:
        ARCError: If the message has no matching ``Authentication-Results``
            header (nothing to seal), an existing chain cannot be continued,
            or the inputs are otherwise malformed (e.g. ``From`` is not
            signed).
    """
    if isinstance(message, str):
        message_bytes: bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    if isinstance(private_key, str):
        private_key_bytes: bytes = private_key.encode("ascii")
    else:
        private_key_bytes = bytes(private_key)

    sign_kwargs = {"timestamp": timestamp, "logger": logger}
    if signed_headers is not None:
        sign_kwargs["include_headers"] = [
            header.encode("ascii") for header in signed_headers
        ]

    try:
        arc_set = _dkim.arc_sign(
            message_bytes,
            selector.encode("ascii"),
            domain.encode("ascii"),
            private_key_bytes,
            authserv_id.encode("ascii"),
            **sign_kwargs,
        )
    except _dkim.DKIMException as e:
        raise ARCError(str(e))

    if not arc_set:
        raise ARCError(
            f"No ARC set produced: no Authentication-Results header for "
            f"authserv_id {authserv_id!r} was found, or the existing chain "
            f"is terminated"
        )

    sealed = b"".join(arc_set) + message_bytes
    if isinstance(message, str):
        return sealed.decode("utf-8", errors="replace")
    return sealed


def verify_arc_chain(
    message: Union[str, bytes],
    minkey: int = 1024,
    dns_func: Optional[Callable[[str], bytes]] = None,
) -> dict:
    """
    Verifies the ARC chain on an RFC 822 message

    The chain validation value (``cv``) summarises the whole chain:

    * ``"pass"`` — every ARC set verified and the chain is intact.
    * ``"none"`` — the message is not ARC sealed.
    * ``"fail"`` — the chain is broken (a signature did not verify, a seal
      reported failure, or an instance reported an invalid status).

    Per RFC 8617 the most recent ``ARC-Message-Signature`` must validate and
    every ``ARC-Seal`` in the chain must validate for a ``"pass"``.

    Args:
        message: An RFC 822 message
        minkey: The minimum acceptable RSA key size in bits
        dns_func: An optional function taking a DNS name and returning the
            raw TXT record value as bytes. Useful for testing or for using a
            custom resolver. Defaults to dkimpy's built-in resolver.

    Returns: A dict with the following keys:

        - ``valid`` (``bool``): ``True`` only when ``cv`` is ``"pass"``
        - ``cv`` (``str``): the chain validation value (``"pass"``,
          ``"fail"``, or ``"none"``)
        - ``reason`` (``str``): a human-readable explanation of the result
        - ``instances`` (``list``): per-ARC-set results in ascending
          instance order, each a dict with:

          - ``instance`` (``int``): the ``i=`` instance number
          - ``ams_domain`` (``str``): the AMS ``d=`` signing domain
          - ``ams_selector`` (``str``): the AMS ``s=`` selector
          - ``ams_valid`` (``bool``): whether the AMS verified
          - ``as_domain`` (``str``): the AS ``d=`` signing domain
          - ``as_selector`` (``str``): the AS ``s=`` selector
          - ``as_valid`` (``bool``): whether the AS verified
          - ``cv`` (``str``): the ``cv=`` value recorded in this AS
    """
    if isinstance(message, str):
        message_bytes: bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    verify_kwargs = {"minkey": minkey, "logger": logger}
    if dns_func is not None:
        verify_kwargs["dnsfunc"] = dns_func
    cv, results, reason = _dkim.arc_verify(message_bytes, **verify_kwargs)

    def _decode(value: Any) -> Any:
        if isinstance(value, bytes):
            return value.decode("ascii", errors="replace")
        return value

    # arc_verify returns CV_Pass/CV_Fail/CV_None (bytes), or Python ``None``
    # when a seal reported failure and terminated the chain — treat that as a
    # failed chain.
    cv_value = "fail" if cv is None else _decode(cv)

    instances = [
        {
            "instance": result.get("instance"),
            "ams_domain": _decode(result.get("ams-domain")),
            "ams_selector": _decode(result.get("ams-selector")),
            "ams_valid": bool(result.get("ams-valid")),
            "as_domain": _decode(result.get("as-domain")),
            "as_selector": _decode(result.get("as-selector")),
            "as_valid": bool(result.get("as-valid")),
            "cv": _decode(result.get("cv")),
        }
        for result in sorted(results, key=lambda r: r.get("instance", 0))
    ]

    return {
        "valid": cv_value == "pass",
        "cv": cv_value,
        "reason": reason,
        "instances": instances,
    }
