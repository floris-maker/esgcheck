"""Command-line interface for esgcheck."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, check, extract_domain, DNSLookupError

CATEGORY_LABEL = {
    "security_gateway": "security gateway",
    "native_provider": "native provider",
    "unknown": "unknown",
    "no_mx": "no mail server",
}


def render_text(result) -> str:
    """Human-readable one-block summary of a Result."""
    name = result.esg or {
        "no_mx": "No mail server",
        "unknown": "Unknown (self-hosted or unrecognized)",
    }.get(result.category, "Unknown")

    lines = [
        f"{result.domain}  ->  {name}  [{CATEGORY_LABEL.get(result.category, result.category)}]",
        f"    uses ESG: {'yes' if result.uses_esg else 'no'}",
    ]
    if result.mx_records:
        lines.append("    MX: " + ", ".join(result.mx_records))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="esgcheck",
        description="Detect which Email Security Gateway (ESG) a domain sits "
                    "behind, from its MX records.",
    )
    parser.add_argument("target", help="an email address or a bare domain")
    parser.add_argument("--json", action="store_true",
                        help="output the result as JSON")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="DNS timeout in seconds (default: 5)")
    parser.add_argument("--version", action="version",
                        version=f"esgcheck {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        extract_domain(args.target)  # validate early for a clean error
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = check(args.target, timeout=args.timeout)
    except DNSLookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
