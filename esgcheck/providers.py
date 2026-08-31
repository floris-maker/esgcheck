"""Known email-provider fingerprints, matched against a domain's MX hostnames.

Each entry maps a provider to the MX-hostname suffixes that identify it and a
category:

  * ``security_gateway`` - a third-party Email Security Gateway (ESG) sits in
    front of the inbox and screens inbound mail (the "yes, it uses an ESG" case).
  * ``native_provider`` - a mailbox host with built-in filtering but no dedicated
    third-party gateway in front (Microsoft 365, Google Workspace, Zoho).

Patterns are matched on a DNS-label boundary: a pattern ``P`` matches an MX
hostname ``H`` when ``H == P`` or ``H`` ends with ``"." + P`` (case-insensitive).

To add a provider, append a dict here. Keep security gateways before native
providers; within each group order does not matter.
"""

SECURITY_GATEWAY = "security_gateway"
NATIVE_PROVIDER = "native_provider"

# Order matters only in that security gateways are listed first; detection
# prefers a gateway match over a native match when a domain has both.
PROVIDERS = [
    # --- Third-party Email Security Gateways --------------------------------
    {"name": "Proofpoint", "category": SECURITY_GATEWAY,
     "patterns": ["pphosted.com", "ppe-hosted.com"]},
    {"name": "Mimecast", "category": SECURITY_GATEWAY,
     "patterns": ["mimecast.com", "mimecast.co.za",
                  "mimecast-offshore.com", "mimecast.com.au"]},
    {"name": "Barracuda", "category": SECURITY_GATEWAY,
     "patterns": ["barracudanetworks.com", "barracuda.com"]},
    {"name": "Cisco Secure Email", "category": SECURITY_GATEWAY,
     "patterns": ["iphmx.com"]},
    {"name": "Sophos Email", "category": SECURITY_GATEWAY,
     "patterns": ["sophos.com"]},
    {"name": "Symantec Email Security.cloud", "category": SECURITY_GATEWAY,
     "patterns": ["messagelabs.com"]},
    {"name": "Forcepoint Email Security", "category": SECURITY_GATEWAY,
     "patterns": ["mailcontrol.com"]},
    {"name": "Trend Micro Email Security", "category": SECURITY_GATEWAY,
     "patterns": ["hes.trendmicro.com", "trendmicro.com"]},
    {"name": "Cloudflare Email Security", "category": SECURITY_GATEWAY,
     "patterns": ["cf-emailsecurity.net", "mx.cloudflare.net"]},
    {"name": "Trellix Email Security", "category": SECURITY_GATEWAY,
     "patterns": ["fireeyecloud.com"]},
    {"name": "Perception Point", "category": SECURITY_GATEWAY,
     "patterns": ["perceptionpoint.io"]},
    {"name": "MailChannels", "category": SECURITY_GATEWAY,
     "patterns": ["mailchannels.net"]},
    {"name": "Mailprotector", "category": SECURITY_GATEWAY,
     "patterns": ["mailprotector.com"]},
    {"name": "FortiMail Cloud", "category": SECURITY_GATEWAY,
     "patterns": ["fortimail.com"]},
    {"name": "Hornetsecurity", "category": SECURITY_GATEWAY,
     "patterns": ["antispameurope.com", "hornetsecurity.com"]},
    {"name": "AppRiver", "category": SECURITY_GATEWAY,
     "patterns": ["arsmtp.com"]},
    {"name": "Retarus", "category": SECURITY_GATEWAY,
     "patterns": ["retarus.com"]},

    # --- Native mailbox providers (built-in filtering, no third-party ESG) ---
    {"name": "Microsoft 365 (EOP)", "category": NATIVE_PROVIDER,
     "patterns": ["mail.protection.outlook.com", "protection.outlook.com",
                  "mx.microsoft", "outlook.com"]},
    {"name": "Google Workspace", "category": NATIVE_PROVIDER,
     "patterns": ["google.com", "googlemail.com"]},
    {"name": "Zoho", "category": NATIVE_PROVIDER,
     "patterns": ["zoho.com", "zoho.eu", "zohomail.com"]},
    {"name": "Fastmail", "category": NATIVE_PROVIDER,
     "patterns": ["messagingengine.com", "fastmail.com"]},
    {"name": "Proton Mail", "category": NATIVE_PROVIDER,
     "patterns": ["protonmail.ch"]},
    {"name": "Rackspace Email", "category": NATIVE_PROVIDER,
     "patterns": ["emailsrvr.com"]},
    {"name": "GoDaddy", "category": NATIVE_PROVIDER,
     "patterns": ["secureserver.net"]},
    {"name": "OVH", "category": NATIVE_PROVIDER,
     "patterns": ["ovh.net"]},
    {"name": "IONOS", "category": NATIVE_PROVIDER,
     "patterns": ["1and1.com", "kundenserver.de"]},
    {"name": "Namecheap Private Email", "category": NATIVE_PROVIDER,
     "patterns": ["privateemail.com"]},
    {"name": "Yandex", "category": NATIVE_PROVIDER,
     "patterns": ["yandex.ru", "yandex.net"]},
]
