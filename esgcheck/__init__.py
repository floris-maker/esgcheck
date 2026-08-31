"""esgcheck - detect which Email Security Gateway a domain sits behind.

Public API:

    >>> from esgcheck import check
    >>> check("john@acme.com").esg          # does a live DNS MX lookup
    'Proofpoint'

    >>> from esgcheck import check_mx
    >>> check_mx("john@acme.com", ["us-smtp-inbound-1.mimecast.com"]).esg
    'Mimecast'
"""

from .detect import detect, Result

__version__ = "0.1.0"
__all__ = ["check", "check_mx", "extract_domain", "detect", "Result", "DNSLookupError"]


class DNSLookupError(Exception):
    """Raised when MX records cannot be resolved due to a DNS/resolver failure."""


def extract_domain(email_or_domain: str) -> str:
    """Extract and normalize the domain from an email address or bare domain.

    Raises ``ValueError`` for empty or clearly-invalid input.
    """
    if email_or_domain is None:
        raise ValueError("no input given")
    value = email_or_domain.strip().lower()
    if not value:
        raise ValueError("empty input")

    if "@" in value:
        value = value.rsplit("@", 1)[1]

    if not value or "." not in value or " " in value:
        raise ValueError(f"not a valid email or domain: {email_or_domain!r}")

    return value


def check_mx(email_or_domain: str, mx_records: list[str]) -> Result:
    """Classify using already-resolved ``mx_records`` (no network I/O)."""
    domain = extract_domain(email_or_domain)
    return detect(domain, mx_records)


def check(email_or_domain: str, timeout: float = 5.0) -> Result:
    """Resolve the domain's MX records over DNS and classify it.

    Raises ``ValueError`` for bad input and ``DNSLookupError`` on resolver
    failure. A domain with no MX records is not an error - it returns a
    ``no_mx`` result.
    """
    from .dns_lookup import resolve_mx

    domain = extract_domain(email_or_domain)
    mx_records = resolve_mx(domain, timeout=timeout)
    return detect(domain, mx_records)
