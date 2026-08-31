"""MX resolution over dnspython, with a public-resolver fallback for resiliency."""

from __future__ import annotations

# Public resolvers to fall back to when the system resolver is unavailable or
# times out (Cloudflare, then Google).
PUBLIC_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]


def _format_exchange(record) -> str:
    """MX exchange hostname without a trailing dot, but keep a lone '.' (null MX)."""
    exchange = str(record.exchange).strip()
    return "." if exchange == "." else exchange.rstrip(".")


def _default_resolvers(timeout: float):
    """The system resolver first, then a resolver pinned to public nameservers."""
    import dns.resolver

    system = dns.resolver.Resolver()
    system.lifetime = timeout
    system.timeout = timeout

    public = dns.resolver.Resolver(configure=False)
    public.nameservers = list(PUBLIC_NAMESERVERS)
    public.lifetime = timeout
    public.timeout = timeout

    return [system, public]


def resolve_mx(domain: str, timeout: float = 5.0, resolvers=None) -> list[str]:
    """Return the MX hostnames for ``domain``, sorted by preference.

    Tries each resolver in turn: a definitive answer (records, or a domain with
    no MX) is returned immediately, while a transient failure (timeout, no
    reachable nameserver) falls through to the next resolver. Returns an empty
    list when the domain has no MX records. Raises
    :class:`esgcheck.DNSLookupError` only when every resolver fails.
    """
    import dns.resolver
    from dns.exception import DNSException

    from . import DNSLookupError

    if resolvers is None:
        resolvers = _default_resolvers(timeout)

    last_error: Exception | None = None
    for resolver in resolvers:
        try:
            answers = resolver.resolve(domain, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []  # definitive: no such domain / no MX record -> not an error
        except (dns.resolver.NoNameservers, DNSException) as exc:
            last_error = exc  # transient: try the next resolver
            continue
        records = sorted(answers, key=lambda r: r.preference)
        return [_format_exchange(r) for r in records]

    raise DNSLookupError(f"could not resolve MX for {domain!r}: {last_error}")
