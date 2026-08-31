"""Tests for CLI rendering and the input-validation exit path (no network)."""

import json

from esgcheck.cli import render_text, main
from esgcheck.detect import detect


def test_render_text_names_the_gateway():
    out = render_text(detect("acme.com", ["mx1.acme.com.pphosted.com"]))
    assert "acme.com" in out
    assert "Proofpoint" in out
    assert "security gateway" in out
    assert "uses ESG: yes" in out
    assert "mx1.acme.com.pphosted.com" in out


def test_render_text_native_provider_says_no():
    out = render_text(detect("bigco.com", ["bigco.mail.protection.outlook.com"]))
    assert "Microsoft 365 (EOP)" in out
    assert "uses ESG: no" in out


def test_render_text_no_mx():
    out = render_text(detect("parked.xyz", []))
    assert "No mail server" in out
    assert "uses ESG: no" in out


def test_main_returns_2_on_invalid_input(capsys):
    code = main(["not-an-email"])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_json_output_is_valid_and_roundtrips():
    # render the dict the CLI would print and confirm it parses back
    result = detect("acme.com", ["mx1.iphmx.com"])
    parsed = json.loads(json.dumps(result.to_dict()))
    assert parsed["esg"] == "Cisco Secure Email"
    assert parsed["uses_esg"] is True
