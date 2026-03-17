"""primust CLI

Usage:
  primust --version
  primust verify <file>              # verify a VPEC artifact
  primust verify <file> --json
  primust verify-report <file.pdf>   # verify a signed PDF audit report
  primust pack verify <pack.json>    # verify an evidence pack
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="primust",
        description="Primust SDK CLI — verifiable governance credentials.",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version and exit"
    )

    subparsers = parser.add_subparsers(dest="command")

    # primust verify — delegates to primust-verify
    verify_parser = subparsers.add_parser(
        "verify", help="Verify a VPEC artifact (delegates to primust-verify)"
    )
    verify_parser.add_argument("file", nargs="?", help="Path to artifact JSON file")
    verify_parser.add_argument(
        "--production", action="store_true", help="Reject test_mode: true"
    )
    verify_parser.add_argument(
        "--skip-network", action="store_true", help="Skip Rekor check"
    )
    verify_parser.add_argument(
        "--trust-root", type=str, help="Path to custom public key PEM"
    )
    verify_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )

    # primust verify-report — verify a signed PDF audit report
    report_parser = subparsers.add_parser(
        "verify-report", help="Verify a signed PDF audit report"
    )
    report_parser.add_argument("file", nargs="?", help="Path to report PDF file")
    report_parser.add_argument(
        "--trust-root", type=str, help="Path to custom public key PEM"
    )
    report_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )

    # primust pack verify — verify an evidence pack
    pack_parser = subparsers.add_parser(
        "pack", help="Evidence pack commands"
    )
    pack_sub = pack_parser.add_subparsers(dest="pack_command")
    pack_verify = pack_sub.add_parser("verify", help="Verify an evidence pack")
    pack_verify.add_argument("file", nargs="?", help="Path to pack JSON file")
    pack_verify.add_argument(
        "--trust-root", type=str, help="Path to custom public key PEM"
    )
    pack_verify.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )

    args = parser.parse_args(argv)

    if args.version:
        from primust import __version__

        print(f"primust {__version__}")
        return 0

    if args.command == "verify":
        try:
            from primust_verify.cli import main as verify_main
        except ImportError:
            print(
                "Error: primust-verify is not installed.\n"
                "Install it with: pip install primust-verify",
                file=sys.stderr,
            )
            return 2

        verify_argv = []
        if args.file:
            verify_argv.append(args.file)
        if args.production:
            verify_argv.append("--production")
        if args.skip_network:
            verify_argv.append("--skip-network")
        if args.trust_root:
            verify_argv.extend(["--trust-root", args.trust_root])
        if args.json_output:
            verify_argv.append("--json")

        return verify_main(verify_argv)

    if args.command == "verify-report":
        try:
            from primust_verify.cli import main as verify_main
        except ImportError:
            print(
                "Error: primust-verify is not installed.\n"
                "Install it with: pip install primust-verify",
                file=sys.stderr,
            )
            return 2

        verify_argv = []
        if args.file:
            verify_argv.append(args.file)
        verify_argv.extend(["--type", "report"])
        if args.trust_root:
            verify_argv.extend(["--trust-root", args.trust_root])
        if args.json_output:
            verify_argv.append("--json")

        return verify_main(verify_argv)

    if args.command == "pack" and getattr(args, "pack_command", None) == "verify":
        try:
            from primust_verify.cli import main as verify_main
        except ImportError:
            print(
                "Error: primust-verify is not installed.\n"
                "Install it with: pip install primust-verify",
                file=sys.stderr,
            )
            return 2

        verify_argv = []
        if args.file:
            verify_argv.append(args.file)
        if args.trust_root:
            verify_argv.extend(["--trust-root", args.trust_root])
        if args.json_output:
            verify_argv.append("--json")

        return verify_main(verify_argv)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
