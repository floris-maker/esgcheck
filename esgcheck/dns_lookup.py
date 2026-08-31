"""Thin wrapper around dnspython for resolving a domain's MX records."""

from __future__ import annotations


def resolve_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """Return the MX hostnames for ``domain``, sorted by preference.

    Returns an empty list when the domain has no MX records (NXDOMAIN or
    NoAnswer). Raises :class:`esgcheck.DNSLookupError` on resolver failures
    such as timeouts.
    """
    import dns.resolver  # imported lazily so the package imports without dnspython
    from dns.exception import DNSException

    from . import DNSLookupError

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except DNSException as exc:
        raise DNSLookupError(f"could not resolve MX for {domain!r}: {exc}") from exc

    records = sorted(answers, key=lambda r: r.preference)
    return [str(r.exchange).rstrip(".") for r in records]
