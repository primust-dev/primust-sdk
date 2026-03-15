# Primust Artifact Core (Python)

Canonical JSON serialization, commitment hashing, and Ed25519 signing primitives for the Primust protocol.

```bash
pip install primust-artifact-core
```

## What this package does

`artifact-core-py` provides the low-level building blocks that all Primust artifacts depend on:

- **Canonical JSON** — deterministic serialization (sorted keys, no trailing commas, no whitespace) so that the same logical document always produces the same byte sequence.
- **Commitment hashing** — Poseidon2 and SHA-256 commitment computation over inputs. Data is committed locally and never transmitted.
- **Ed25519 signing** — key generation, signing, and verification for VPEC artifacts, Evidence Packs, and check manifests.

## Usage

```python
from primust_artifact_core import canonical, sign, verify, generate_key_pair, build_commitment_root

# Canonical JSON
doc = {"b": 2, "a": 1}
assert canonical(doc) == '{"a":1,"b":2}'

# Key pair
signer, private_key = generate_key_pair("signer_001", "org_001", "artifact_signer")

# Sign
signature_envelope = sign(doc, private_key, signer)

# Verify
assert verify(doc, signature_envelope, signer.public_key)

# Commitment root
root = build_commitment_root(["poseidon2:aabb...", "poseidon2:ccdd..."])
```

## License

Apache 2.0
