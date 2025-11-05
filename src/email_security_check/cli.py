import argparse
import json
import sys
import asyncio

from .core import generate_report, human_report

def main(argv=None):
    parser = argparse.ArgumentParser(description="Email auth (SPF/DKIM/DMARC) checker")
    parser.add_argument("domain", help="domain to check (e.g. example.com)")
    parser.add_argument("--aggressive-dkim", action="store_true", help="Try more DKIM selectors (slower)")
    parser.add_argument("--json-out", help="Write JSON summary to this file")
    parser.add_argument("--quiet", action="store_true", help="Only output JSON or minimal info")
    args = parser.parse_args(argv)

    try:
        result = asyncio.run(generate_report(args.domain.strip(), aggressive_dkim=args.aggressive_dkim))
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        if not args.quiet:
            print(f"Wrote JSON summary to {args.json_out}")

    if not args.quiet:
        print(human_report(result))
    else:
        print(json.dumps(result))

if __name__ == "__main__":
    main()