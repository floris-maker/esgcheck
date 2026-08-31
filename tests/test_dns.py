"""Tests for DNS resolution resiliency, using injected fake resolvers (no network)."""

import dns.exception
import dns.resolver
import pytest

from esgcheck import DNSLookupError
from esgcheck.dns_lookup import resolve_mx


class FakeAnswer:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = exchange


class FakeResolver:
    """Returns a list of answers, or raises, when .resolve() is called."""

    def __init__(self, result):
        self.result = result
        self.calls = 0

    def resolve(self, domain, rdtype):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_falls_back_to_second_resolver_on_timeout():
    r1 = FakeResolver(dns.exception.Timeout())
    r2 = FakeResolver([FakeAnswer(20, "b.mimecast.com."), FakeAnswer(10, "a.mimecast.com.")])
    out = resolve_mx("x.com", resolvers=[r1, r2])
    assert out == ["a.mimecast.com", "b.mimecast.com"]  # sorted by preference, dot stripped
    assert r1.calls == 1 and r2.calls == 1


def test_raises_dnslookuperror_when_all_resolvers_fail():
    r1 = FakeResolver(dns.exception.Timeout())
    r2 = FakeResolver(dns.resolver.NoNameservers())
    with pytest.raises(DNSLookupError):
        resolve_mx("x.com", resolvers=[r1, r2])


def test_no_answer_is_empty_not_error_and_does_not_fall_back():
    r1 = FakeResolver(dns.resolver.NoAnswer())
    r2 = FakeResolver([FakeAnswer(10, "should.not.be.used.com.")])
    assert resolve_mx("x.com", resolvers=[r1, r2]) == []
    assert r2.calls == 0  # NoAnswer is definitive; second resolver not tried


def test_null_mx_exchange_preserved_as_dot():
    r = FakeResolver([FakeAnswer(0, ".")])
    assert resolve_mx("x.com", resolvers=[r]) == ["."]
