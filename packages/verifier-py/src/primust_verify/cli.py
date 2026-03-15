"""primust-verify CLI

Usage:
  primust-verify vpec_<id>.json
  primust-verify vpec_<id>.json --production
  primust-verify vpec_<id>.json --trust-root ./my-pubkey.pem
  primust-verify vpec_<id>.json --skip-network
  primust-verify vpec_<id>.json --json
  primust-verify report.pdf                    # auto-detects PDF report
  primust-verify report.pdf --type report      # explicit report mode
  primust-verify report.json --type report     # legacy JSON report (deprecated)

Exit codes:
  0 = valid
  1 = invalid
  2 = sandbox / system error
  3 = key revoked
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from primust_verify.verifier import verify
from primust_verify.report_verifier import verify_report, ReportVerificationResult
from primust_verify.types import VerifyOptions, VerificationResult


PROOF_LEVEL_DISPLAY = {
    "mathematical": "mathematical",
    "verifiable_inference": "Verifiable Inference",
    "execution": "execution",
    "witnessed": "witnessed",
    "attestation": "attestation",
}


def _format_proof_level(level: str) -> str:
    return PROOF_LEVEL_DISPLAY.get(level, level)


def _format_distribution(dist: dict) -> str:
    levels = ["mathematical", "verifiable_inference", "execution", "witnessed", "attestation"]
    parts = []
    for l in levels:
        v = dist.get(l)
        if isinstance(v, (int, float)) and v > 0:
            parts.append(f"{_format_proof_level(l)}: {v}")
    return "  ".join(parts)


def _format_gaps_summary(gaps: list[dict]) -> str:
    if not gaps:
        return "0"
    counts: dict[str, int] = {}
    for g in gaps:
        sev = g.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    parts = [f"{n} {sev}" for sev, n in counts.items()]
    return f"{len(gaps)} ({', '.join(parts)})"


def _print_human_result(result: VerificationResult) -> None:
    cov = result.coverage

    if result.valid:
        print(f"\n  \u2713 VPEC {result.vpec_id} \u2014 VALID")
    else:
        print(f"\n  \u2717 VPEC {result.vpec_id} \u2014 INVALID")
        for err in result.errors:
            print(f"    Error: {err}")

    print(f"    Proof level:   {_format_proof_level(result.proof_level)} (weakest-link)")

    dist_str = _format_distribution(result.proof_distribution)
    if dist_str:
        print(f"    Distribution:  {dist_str}")

    print(f"    Workflow:      {result.workflow_id}")
    print(f"    Org:           {result.org_id}")

    ts_str = result.signed_at
    if result.timestamp_anchor_valid is True:
        ts_str += " (RFC 3161 \u2713)"
    print(f"    Signed:        {ts_str}")

    print(f"    Signer:        {result.signer_id} / kid: {result.kid}")
    print(f"    Rekor:         {result.rekor_status}")

    if isinstance(cov, dict) and "policy_coverage_pct" in cov:
        cov_str = f"{cov['policy_coverage_pct']}% policy"
        if cov.get("instrumentation_surface_pct") is not None:
            cov_str += f" | {cov['instrumentation_surface_pct']}% instrumentation surface"
        print(f"    Coverage:      {cov_str}")

    print(f"    Gaps:          {_format_gaps_summary(result.gaps)}")

    if result.process_context_hash:
        print(f"    Process hash:  {result.process_context_hash}")

    print(f"    Test mode:     {str(result.test_mode).lower()}")

    if result.test_mode and result.valid:
        print("    \u26A0 TEST CREDENTIAL \u2014 not for production use")

    for w in result.warnings:
        print(f"    Warning: {w}")

    print()


def _print_report_result(result: ReportVerificationResult) -> None:
    """Print human-readable report verification result."""
    if result.valid:
        print(f"\n  \u2713 Report \u2014 VALID")
    else:
        print(f"\n  \u2717 Report \u2014 INVALID")
        for err in result.errors:
            print(f"    Error: {err}")

    print(f"    Pack:          {result.pack_id}")
    print(f"    Kid:           {result.kid}")
    print(f"    Trust anchor:  {result.trust_anchor}")
    print(f"    Generated:     {result.generated_at}")
    print(f"    PDF SHA-256:   {result.pdf_sha256}")
    print(f"    Sig valid:     {str(result.signature_valid).lower()}")

    for w in result.warnings:
        print(f"    Warning: {w}")

    print()


def _is_pdf(file_path: Path) -> bool:
    """Check if a file is a PDF by extension or magic bytes."""
    if file_path.suffix.lower() == ".pdf":
        return True
    # Check magic bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(5)
        return header == b"%PDF-"
    except OSError:
        return False


def _is_report_json(data: dict) -> bool:
    """Detect whether a JSON document is a report (vs a VPEC)."""
    return "report_version" in data and "cover" in data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="primust-verify",
        description="Verify a VPEC artifact or audit report offline.",
    )
    parser.add_argument("file", nargs="?", help="Path to artifact JSON or report PDF file")
    parser.add_argument(
        "--type",
        choices=["vpec", "report"],
        default=None,
        dest="doc_type",
        help="Document type (auto-detected if not specified)",
    )
    parser.add_argument("--production", action="store_true", help="Reject test_mode: true")
    parser.add_argument("--skip-network", action="store_true", help="Skip Rekor check")
    parser.add_argument("--trust-root", type=str, help="Path to custom public key PEM")
    parser.add_argument("--json", action="store_true", dest="json_output", help="JSON output")

    args = parser.parse_args(argv)

    if not args.file:
        parser.print_help()
        return 2

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    # Determine document type
    doc_type = args.doc_type

    if doc_type is None:
        # Auto-detect: PDF files are reports, JSON files need further inspection
        if _is_pdf(file_path):
            doc_type = "report"
        else:
            # Try parsing as JSON to detect report vs VPEC
            try:
                data = json.loads(file_path.read_text())
                doc_type = "report" if _is_report_json(data) else "vpec"
            except (json.JSONDecodeError, OSError):
                print(f"Error: cannot parse {args.file} as JSON or PDF", file=sys.stderr)
                return 2

    if doc_type == "report":
        return _verify_report_flow(file_path, args)
    else:
        return _verify_vpec_flow(file_path, args)


def _verify_report_flow(file_path: Path, args: argparse.Namespace) -> int:
    """Verify an audit report (PDF or legacy JSON)."""
    try:
        if _is_pdf(file_path):
            pdf_bytes = file_path.read_bytes()
            result = verify_report(pdf_bytes, trust_root=args.trust_root)
        else:
            # Legacy JSON report path
            data = json.loads(file_path.read_text())
            result = verify_report(data, trust_root=args.trust_root)
    except Exception as e:
        print(f"Error: report verification failed: {e}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_report_result(result)

    return 0 if result.valid else 1


def _verify_vpec_flow(file_path: Path, args: argparse.Namespace) -> int:
    """Verify a VPEC artifact."""
    try:
        raw_json = file_path.read_text()
    except OSError:
        print(f"Error: cannot read file: {args.file}", file=sys.stderr)
        return 2

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        print(f"Error: invalid JSON in {args.file}", file=sys.stderr)
        return 2

    try:
        result = verify(
            data,
            VerifyOptions(
                production=args.production,
                skip_network=args.skip_network,
                trust_root=args.trust_root,
            ),
        )
    except Exception as e:
        print(f"Error: verification failed: {e}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human_result(result)

    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
