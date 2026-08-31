"""Pure detection logic: turn a domain + its MX records into a verdict.

This module does no network I/O so it can be tested with injected MX data.
"""

from dataclasses import dataclass

from .providers import PROVIDERS, SECURITY_GATEWAY, NATIVE_PROVIDER

NO_MX = "no_mx"
UNKNOWN = "unknown"


@dataclass
class Result:
    """The outcome of an ESG check for a single domain."""

    domain: str
    esg: str | None
    category: str
    uses_esg: bool
    mx_records: list[str]
    matched_mx: str | None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "esg": self.esg,
            "category": self.category,
            "uses_esg": self.uses_esg,
            "mx_records": self.mx_records,
            "matched_mx": self.matched_mx,
        }


def _normalize(hostname: str) -> str:
    """Lowercase and drop any trailing dot from an MX hostname."""
    return hostname.strip().rstrip(".").lower()


def _matches(hostname: str, pattern: str) -> bool:
    """True if ``hostname`` is, or is a subdomain of, ``pattern``.

    Matching respects DNS-label boundaries so ``notpphosted.com`` does not
    match the ``pphosted.com`` rule.
    """
    return hostname == pattern or hostname.endswith("." + pattern)


def _identify(hostname: str):
    """Return the (name, category) of the first provider matching ``hostname``."""
    for provider in PROVIDERS:
        for pattern in provider["patterns"]:
            if _matches(hostname, pattern):
                return provider["name"], provider["category"]
    return None


def detect(domain: str, mx_records: list[str]) -> Result:
    """Classify ``domain`` from its ``mx_records`` (list of MX hostnames)."""
    normalized = [_normalize(mx) for mx in mx_records if mx and mx.strip()]

    if not normalized:
        return Result(domain, None, NO_MX, False, [], None)

    # Collect every provider match, keeping MX order. Prefer a security gateway
    # over a native provider when a domain routes through both.
    gateway_hit = None
    native_hit = None
    for original, host in zip(mx_records, normalized):
        found = _identify(host)
        if not found:
            continue
        name, category = found
        if category == SECURITY_GATEWAY and gateway_hit is None:
            gateway_hit = (name, category, original)
        elif category == NATIVE_PROVIDER and native_hit is None:
            native_hit = (name, category, original)

    hit = gateway_hit or native_hit
    if hit is None:
        return Result(domain, None, UNKNOWN, False, mx_records, None)

    name, category, matched_mx = hit
    return Result(
        domain=domain,
        esg=name,
        category=category,
        uses_esg=(category == SECURITY_GATEWAY),
        mx_records=mx_records,
        matched_mx=matched_mx,
    )
