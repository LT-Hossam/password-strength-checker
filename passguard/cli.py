"""
Command-line interface for PassGuard.

Examples
--------
Interactive (password is typed hidden, never echoed):
    python -m passguard check

Skip the online breach check (fully offline):
    python -m passguard check --no-breach

Machine-readable output:
    python -m passguard check --json

Pass a password directly (less secure — it lands in your shell history):
    python -m passguard check --password "hunter2"
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import strength
from .breach import check_pwned


def _gather_report(password: str, do_breach: bool) -> dict:
    report = strength.analyze(password)
    if do_breach:
        count = check_pwned(password)
        report["breach_count"] = count
        if count is None:
            report["breach_status"] = "unchecked (could not reach the breach API)"
        elif count > 0:
            report["breach_status"] = "FOUND IN BREACHES — do not use this password"
        else:
            report["breach_status"] = "not found in known breaches"
    else:
        report["breach_count"] = None
        report["breach_status"] = "skipped"
    return report


def _bar(score: int, width: int = 24) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {score}/100"


def _print_human(report: dict) -> None:
    print()
    print(f"  Rating:        {report['rating']}")
    print(f"  Strength:      {_bar(report['score'])}")
    print(f"  Length:        {report['length']} characters")
    print(f"  Entropy:       {report['effective_entropy_bits']} bits "
          f"(raw {report['raw_entropy_bits']})")
    print(f"  Est. crack:    {report['estimated_offline_crack_time']} "
          f"(offline, fast hash)")

    status = report.get("breach_status", "skipped")
    print(f"  Breach check:  {status}")
    if report.get("breach_count"):
        print(f"                 seen {report['breach_count']:,} times in breaches")

    if report["warnings"]:
        print("\n  Warnings:")
        for w in report["warnings"]:
            print(f"    - {w}")

    print("\n  Suggestions:")
    for tip in report["suggestions"]:
        print(f"    - {tip}")
    print()


def _cmd_check(args: argparse.Namespace) -> int:
    if args.password is not None:
        password = args.password
    else:
        password = getpass.getpass("Enter password to analyze (hidden): ")

    if not password:
        print("No password provided.", file=sys.stderr)
        return 1

    report = _gather_report(password, do_breach=not args.no_breach)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    # Exit non-zero if the password is breached or very weak — handy in scripts.
    if report.get("breach_count"):
        return 2
    if report["rating"] in ("Very Weak", "Weak"):
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="Analyze password strength and check it against breach data "
                    "(privacy-preserving k-anonymity). Standard library only.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="analyze a password")
    p_check.add_argument("--password", default=None,
                         help="password to check (omit to type it hidden)")
    p_check.add_argument("--no-breach", action="store_true",
                         help="skip the online breach check (fully offline)")
    p_check.add_argument("--json", action="store_true",
                         help="emit a JSON report")
    p_check.set_defaults(func=_cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
