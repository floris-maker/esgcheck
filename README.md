# esgcheck

Detect which **Email Security Gateway (ESG)** a domain sits behind — from its DNS **MX records**.

Give it an email address or a bare domain, and it tells you whether inbound mail is screened by a third-party gateway like **Proofpoint, Mimecast, Barracuda, Cisco Secure Email, Sophos, Symantec, Forcepoint, Trend Micro** (and more), or just handled by a native provider's built-in filtering (**Microsoft 365, Google Workspace, Zoho**).

This is the signal that matters most for cold-email deliverability: a domain behind a dedicated security gateway screens inbound mail far more aggressively than one on plain M365 or Google.

## How it works

A domain that routes mail through a security gateway has **MX records pointing at the gateway provider** (e.g. `mx1.acme.com.pphosted.com` → Proofpoint). `esgcheck` resolves the MX records and matches their hostnames against a list of known providers. No mail is sent; it's a single DNS lookup.

## Install

```bash
pip install esgcheck
```

Or from source:

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
| `category` | `security_gateway`, `native_provider`, `unknown`, or `no_mx` |
| `uses_esg` | `True` only when a third-party security gateway is detected |
| `mx_records` | the raw MX hostnames the verdict is based on |
| `matched_mx` | the specific MX hostname that identified the provider |

## Verdict categories

- **`security_gateway`** — a third-party ESG is in front of the inbox. This is the "yes, it uses an ESG" case.
- **`native_provider`** — Microsoft 365, Google Workspace, or Zoho. Built-in filtering, but no dedicated third-party gateway.
- **`unknown`** — has MX records but matches no known provider (likely self-hosted).
- **`no_mx`** — the domain has no MX records and cannot receive mail.

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
