#!/usr/bin/env python3
"""
Export the active signing public key from GCP KMS as PEM.

Usage:
    python export_public_key.py --key-name projects/primust/locations/us/keyRings/.../cryptoKeyVersions/1

Writes kid_api.pem to stdout (redirect to file as needed).
For key rotation: export the new key, add it to the well_known registry, keep old keys accessible.
"""

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Export GCP KMS public key as PEM")
    parser.add_argument("--key-name", required=True, help="Full GCP KMS key version resource name")
    parser.add_argument("--kid", default="kid_api", help="Key ID (default: kid_api)")
    args = parser.parse_args()

    try:
        from google.cloud import kms
    except ImportError:
        print("Error: google-cloud-kms not installed. Run: pip install google-cloud-kms", file=sys.stderr)
        sys.exit(1)

    client = kms.KeyManagementServiceClient()
    public_key = client.get_public_key(request={"name": args.key_name})

    # Write PEM to stdout
    sys.stdout.write(public_key.pem)
    print(f"\n# kid: {args.kid}", file=sys.stderr)
    print(f"# algorithm: {public_key.algorithm.name}", file=sys.stderr)
    print(f"# Save as: {args.kid}.pem", file=sys.stderr)


if __name__ == "__main__":
    main()
