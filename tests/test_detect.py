"""Tests for the pure detection and input-parsing logic (no network)."""

import pytest

from esgcheck import check_mx, extract_domain
from esgcheck.detect import detect


# --- extract_domain ---------------------------------------------------------

def test_extract_domain_from_email():
    assert extract_domain("john@acme.com") == "acme.com"


def test_extract_domain_from_bare_domain():
    assert extract_domain("acme.com") == "acme.com"


def test_extract_domain_lowercases():
    assert extract_domain("John@ACME.COM") == "acme.com"


def test_extract_domain_strips_whitespace():
    assert extract_domain("  john@acme.com  ") == "acme.com"


def test_extract_domain_rejects_empty():
    with pytest.raises(ValueError):
        extract_domain("   ")


def test_extract_domain_rejects_no_domain():
    with pytest.raises(ValueError):
        extract_domain("john@")


def test_extract_domain_rejects_garbage():
    with pytest.raises(ValueError):
        extract_domain("not an email or domain")


# --- detect: third-party security gateways ----------------------------------

def test_detect_proofpoint():
    r = detect("acme.com", ["mx1-us1.ppe-hosted.com", "mx2.acme.com.pphosted.com"])
    assert r.esg == "Proofpoint"
    assert r.category == "security_gateway"
    assert r.uses_esg is True
    assert r.matched_mx == "mx1-us1.ppe-hosted.com"


def test_detect_mimecast():
    r = detect("acme.com", ["us-smtp-inbound-1.mimecast.com"])
    assert r.esg == "Mimecast"
    assert r.category == "security_gateway"
    assert r.uses_esg is True


def test_detect_barracuda():
    r = detect("acme.com", ["mx.acme.com.ess.barracudanetworks.com"])
    assert r.esg == "Barracuda"
    assert r.category == "security_gateway"


def test_detect_cisco_ironport():
    r = detect("acme.com", ["mx1.iphmx.com", "mx2.iphmx.com"])
    assert r.esg == "Cisco Secure Email"
    assert r.category == "security_gateway"


# --- detect: native providers -----------------------------------------------

def test_detect_microsoft365_is_native_not_esg():
    r = detect("bigco.com", ["bigco-com.mail.protection.outlook.com"])
    assert r.esg == "Microsoft 365 (EOP)"
    assert r.category == "native_provider"
    assert r.uses_esg is False


def test_detect_google_workspace_is_native():
    r = detect("startup.io", ["aspmx.l.google.com", "alt1.aspmx.l.google.com"])
    assert r.esg == "Google Workspace"
    assert r.category == "native_provider"
    assert r.uses_esg is False


def test_detect_zoho_is_native():
    r = detect("shop.com", ["mx.zoho.com", "mx2.zoho.com"])
    assert r.esg == "Zoho"
    assert r.category == "native_provider"


def test_detect_microsoft_new_mx_suffix():
    # Microsoft is rolling out *.mx.microsoft alongside mail.protection.outlook.com.
    r = detect("siemens.com", ["siemens-com.h-v1.mx.microsoft"])
    assert r.esg == "Microsoft 365 (EOP)"
    assert r.category == "native_provider"


def test_detect_cloudflare_email_security():
    r = detect("acme.com", ["mxa-canary.global.inbound.cf-emailsecurity.net"])
    assert r.esg == "Cloudflare Email Security"
    assert r.category == "security_gateway"


# --- detect: unknown / no_mx ------------------------------------------------

def test_detect_unknown_self_hosted():
    r = detect("selfhosted.io", ["mail.selfhosted.io"])
    assert r.esg is None
    assert r.category == "unknown"
    assert r.uses_esg is False
    assert r.mx_records == ["mail.selfhosted.io"]


def test_detect_no_mx():
    r = detect("parked.xyz", [])
    assert r.esg is None
    assert r.category == "no_mx"
    assert r.uses_esg is False


# --- detect: matching robustness --------------------------------------------

def test_matching_is_case_insensitive():
    r = detect("acme.com", ["US-SMTP-INBOUND-1.MIMECAST.COM"])
    assert r.esg == "Mimecast"


def test_suffix_boundary_no_false_positive():
    # "notpphosted.com" must NOT match the "pphosted.com" suffix rule.
    r = detect("evil.com", ["mail.notpphosted.com"])
    assert r.esg is None
    assert r.category == "unknown"


def test_trailing_dot_is_ignored():
    # Some resolvers return FQDNs with a trailing dot.
    r = detect("acme.com", ["us-smtp-inbound-1.mimecast.com."])
    assert r.esg == "Mimecast"


def test_gateway_wins_over_native_when_both_present():
    # A domain on M365 but routed through Proofpoint should report the gateway.
    r = detect("acme.com", [
        "mx1.acme.com.pphosted.com",
        "acme-com.mail.protection.outlook.com",
    ])
    assert r.esg == "Proofpoint"
    assert r.category == "security_gateway"


# --- Result serialization ----------------------------------------------------

def test_result_to_dict():
    r = detect("acme.com", ["mx1.iphmx.com"])
    d = r.to_dict()
    assert d == {
        "domain": "acme.com",
        "esg": "Cisco Secure Email",
        "category": "security_gateway",
        "uses_esg": True,
        "mx_records": ["mx1.iphmx.com"],
        "matched_mx": "mx1.iphmx.com",
    }


# --- check_mx: glue over injected MX (no DNS) -------------------------------

def test_check_mx_accepts_email_and_returns_result():
    r = check_mx("john@acme.com", ["us-smtp-inbound-1.mimecast.com"])
    assert r.domain == "acme.com"
    assert r.esg == "Mimecast"
