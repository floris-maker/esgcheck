# esgcheck

Detect which **Email Security Gateway (ESG)** a domain sits behind — from its DNS **MX records**.

**▶ Live demo: https://floris-maker.github.io/esgcheck/** — type any domain, get the gateway.

Give it an email address or a bare domain, and it tells you whether inbound mail is screened by a third-party gateway like **Proofpoint, Mimecast, Barracuda, Cisco Secure Email, Sophos, Symantec, Forcepoint, Trend Micro** (and more), or just handled by a native provider's built-in filtering (**Microsoft 365, Google Workspace, Zoho**).

This is the signal that matters most for cold-email deliverability: a domain behind a dedicated security gateway screens inbound mail far more aggressively than one on plain M365 or Google.

## How it works

A domain that routes mail through a security gateway has **MX records pointing at the gateway provider** (e.g. `mx1.acme.com.pphosted.com` → Proofpoint). `esgcheck` resolves the MX records and matches their hostnames against a list of known providers. No mail is sent; it's a single DNS lookup.

## Install

```bash
pip install git+https://github.com/floris-maker/esgcheck
```

> A PyPI release (`pip install esgcheck`) is planned. Until then, install from GitHub as above.

Or from a clone:

```bash
git clone https://github.com/floris-maker/esgcheck
cd esgcheck
pip install .
```

## Usage

```bash
esgcheck john@acme.com
```

```
acme.com  ->  Proofpoint  [security gateway]
    uses ESG: yes
    MX: mx1.acme.com.pphosted.com, mx2.acme.com.pphosted.com
```

A domain on Microsoft 365 with no third-party gateway:

```bash
esgcheck jane@bigco.com
```

```
bigco.com  ->  Microsoft 365 (EOP)  [native provider]
    uses ESG: no
    MX: bigco-com.mail.protection.outlook.com
```

JSON output for scripting:

```bash
esgcheck john@acme.com --json
```

```json
{
  "domain": "acme.com",
  "esg": "Proofpoint",
  "category": "security_gateway",
  "uses_esg": true,
  "mx_records": ["mx1.acme.com.pphosted.com", "mx2.acme.com.pphosted.com"],
  "matched_mx": "mx1.acme.com.pphosted.com"
}
```

## Use it as a library

```python
from esgcheck import check

result = check("john@acme.com")   # live DNS lookup
print(result.esg)                 # "Proofpoint"
print(result.uses_esg)            # True
print(result.category)            # "security_gateway"

# Already have the MX records? Skip the network:
from esgcheck import check_mx
check_mx("john@acme.com", ["us-smtp-inbound-1.mimecast.com"]).esg   # "Mimecast"
```

### Result fields

| Field | Meaning |
|-------|---------|
| `domain` | the domain that was checked |
| `esg` | the detected provider name, or `None` |
| `category` | `security_gateway`, `native_provider`, `unknown`, `null_mx`, or `no_mx` |
| `uses_esg` | `True` only when a third-party security gateway is detected |
| `mx_records` | the raw MX hostnames the verdict is based on |
| `matched_mx` | the specific MX hostname that identified the provider |

## Verdict categories

- **`security_gateway`** — a third-party ESG is in front of the inbox. This is the "yes, it uses an ESG" case.
- **`native_provider`** — a mailbox host with built-in filtering but no dedicated third-party gateway (Microsoft 365, Google Workspace, Zoho, Fastmail, Proton Mail, and others).
- **`unknown`** — has MX records but matches no known provider (likely self-hosted).
- **`null_mx`** — the domain publishes an [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505) null MX (`.`): it explicitly refuses all mail.
- **`no_mx`** — the domain has no MX records at all and cannot receive mail.

## Resiliency

- **Input** — accepts a bare domain, an email, and messy pasted forms: `Name <a@b.com>`, `mailto:a@b.com`, quoted addresses, a full URL, and a trailing port.
- **DNS** — queries the system resolver first and falls back to public resolvers (Cloudflare `1.1.1.1`, then Google `8.8.8.8`) on timeout or resolver failure, so a flaky local resolver doesn't produce a false negative.
- **IDN** — internationalized domains are handled by the resolver's IDNA support.

## What it can't detect

Detection is MX-based, so it only sees gateways that sit **in front of** the inbox and change the domain's MX records. Modern API-based / ICES email security tools — **Abnormal, Avanan (Check Point Harmony), IRONSCALES, Material Security, GreatHorn** — plug into Microsoft 365 or Google *via API* and leave the MX records pointing at `outlook.com` / `google.com`. Those domains correctly report `native_provider`; there is no public DNS signal that reveals an API-based tool behind them.

## Adding a provider

Detection data lives in [`esgcheck/providers.py`](esgcheck/providers.py) as a plain list. To add a gateway, append an entry with the MX-hostname suffixes that identify it:

```python
{"name": "Some Gateway", "category": SECURITY_GATEWAY,
 "patterns": ["somegateway.com"]},
```

Patterns match on a DNS-label boundary (so `pphosted.com` matches `mx.acme.com.pphosted.com` but not `notpphosted.com`). PRs adding providers are welcome.

## Development

```bash
git clone https://github.com/floris-maker/esgcheck
cd esgcheck
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The detection logic (`esgcheck/detect.py`) is a pure function tested with injected MX data, so the test suite needs no network access.

## License

[MIT](LICENSE)
