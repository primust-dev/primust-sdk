# primust-verify

**Free forever. No account required. Apache-2.0.**

Offline verifier for Primust VPECs (Verifiable Process Execution Credentials).

```bash
pip install primust-verify
```

## Verify a VPEC

```python
from primust_verify import verify

result = verify(vpec_json)
assert result.valid
```

Or from the command line:

```bash
primust-verify vpec.json
```

Exit codes:
- `0` — valid
- `1` — invalid (signature mismatch, tampered, or failed checks)
- `2` — system error

## Zero-network verification

Use `--trust-root` to verify without any network calls:

```bash
primust-verify vpec.json --trust-root ./primust-pubkey.pem
```

This fetches no external resources. The public key PEM is the only trust anchor needed.

Download the Primust public key from:
`https://primust.com/.well-known/primust-pubkey.pem`

## You don't need a Primust account to verify a VPEC

This tool is free, open source (Apache-2.0), and works offline. Anyone can verify a VPEC — regulators, auditors, counterparties — without creating an account or contacting Primust.

## Options

| Flag | Description |
|------|-------------|
| `--production` | Reject VPECs issued with test keys |
| `--skip-network` | Skip Rekor transparency log check |
| `--trust-root <path>` | Use a local PEM file as trust anchor (zero-network mode) |
| `--json` | Output structured JSON instead of human-readable text |

## Requirements

- Python 3.11+

## License

Apache-2.0

---

[Docs](https://docs.primust.com) | [Verify online](https://verify.primust.com) | [Primust](https://primust.com)
