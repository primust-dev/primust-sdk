# Audit Guide

For auditors, compliance officers, and GRC teams evaluating Primust Evidence Packs.

---

## The Fundamental Claim

When an organization presents a Primust Evidence Pack, they are making a specific, bounded claim:

> **"For every declared operation in this pipeline, we can prove — via cryptographic signature, zero-knowledge proof, or attested record — that the code which was supposed to run did run, on the data it was supposed to process, producing the output that was recorded."**

**Critical disclosure:** Primust proves what was declared should run — not that everything was declared. An organization could omit pipeline stages from their VPEC definition. The Gap Taxonomy identifies and labels known omission categories, but the declaration boundary is set by the organization. Auditors must independently assess declaration completeness.

This distinction is fundamental. Primust can guarantee execution integrity within the declared surface. It cannot guarantee the declared surface is exhaustive. The `provable_surface` report and gap taxonomy exist to make this boundary visible.

---

## Five-Minute Verification

Every claim in an Evidence Pack can be verified using the open-source `primust-verify` tool. No Primust account required.

```bash
pip install primust-verify

primust verify evidence-pack-2026-03-16.json
```

**Expected output:**
```
Primust Verify v2.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence Pack: evidence-pack-2026-03-16.json
Organization:  Acme Corp
Pipeline:      loan-underwriting-v3
Generated:     2026-03-16T09:14:00Z
Environment:   production

✓ Signature valid           Ed25519 / org-key-abc123
✓ Chain intact              47 records, 0 breaks
✓ ZK proofs verified        12/12 circuits passed
✓ Timestamps consistent     All within declared window
✓ Gaps disclosed            3 gaps (0 Critical, 2 High, 1 Medium)

RESULT: PASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Verification is fully offline with a pinned trust root:**
```bash
primust verify evidence-pack.json --trust-root org-key.pem
```

---

## What the Five Verification Checks Prove

| Check | What It Proves | Failure Means |
|---|---|---|
| **Signature** | Pack was signed by the declared org key and not modified since | Tampered or key not recognized |
| **Chain** | Every record links to the prior via cryptographic hash — no records inserted, removed, or reordered | Records altered after the fact |
| **ZK Proofs** | For Mathematical-level checks, the declared computation ran on the declared inputs — without revealing the inputs | The claimed computation did not occur as described |
| **Timestamps** | All records fall within the declared execution window, monotonically ordered | Timeline manipulated or records out of sequence |
| **Gaps** | Organization has disclosed known coverage gaps per the canonical gap taxonomy | Undisclosed gaps or unresolved Critical gaps |

---

## Proof Levels — What Each Means for Audit

| Level | Enum | Mechanism | Audit Guidance |
|---|---|---|---|
| **Mathematical** | `mathematical` | ZK circuit (Noir/UltraHonk) — cryptographically proves check ran on declared inputs | Strongest practical proof. Verifier confirms execution integrity without seeing data. Suitable for regulated, high-risk operations. |
| **Verifiable Inference** | `verifiable_inference` | ONNX-to-circuit (EZKL) — proves ML model inference ran | Trust the model weights (auditable). Stronger than Execution — model and its inference are proven, not just invoked. |
| **Execution** | `execution` | Model-hash-binding circuit — proves specific named model ran | Trust the model identity (public, auditable). Request model card and version documentation. Suitable when ML model identity is verifiable. |
| **Witnessed** | `witnessed` | Two RFC 3161 timestamps + Ed25519 reviewer signature | Trust the reviewer identity (key in org JWKS). Confirm reviewer credential is valid and not revoked. Minimum review duration enforced by protocol. |
| **Attestation** | `attestation` | Invocation-binding — proves call occurred | Trust the process owner's word. Weakest evidence. Flag if used for high-risk operations. Request compensating controls. |

**Weakest-link rule:** The VPEC's `proof_level_floor` is the minimum proof level across all checks. One Attestation check makes the floor Attestation — even if 22 others are Mathematical.

**What to look at:** `proof_level_floor` is the compliance gate. `provable_surface_breakdown` is the full picture. A `proof_level_floor` of Attestation with `provable_surface_breakdown.mathematical: 0.73` means most governance is mathematically proven — the floor reflects one weak link, not the overall posture.

---

## Reading the Provable Surface Report

```bash
primust verify vpec.json --json | jq '{
  floor: .proof_level_floor,
  surface: .provable_surface,
  breakdown: .provable_surface_breakdown,
  ungoverned: .provable_surface_ungoverned
}'
```

**Example output:**
```json
{
  "floor": "attestation",
  "surface": 0.73,
  "breakdown": {
    "mathematical": 0.62,
    "verifiable_inference": 0.00,
    "execution": 0.11,
    "witnessed": 0.00,
    "attestation": 0.00
  },
  "ungoverned": 0.27
}
```

**Reading this:** 73% of declared checks have cryptographic proof — 62% mathematical, 11% execution-level. 27% of manifest checks have no record this run (`provable_surface_ungoverned`). The floor of Attestation reflects a single non-ZK step, but the majority of governance is strongly proven.

**`provable_surface_basis`** tells you the denominator:
- `executed_records` — share of checks that actually ran in this period
- `manifest_checks` — share of all declared checks in the manifest (stricter — counts ungoverned)

---

## Verifying an Evidence Pack

```bash
# Standard verification
primust verify evidence-pack-2026-03-16.json

# Production mode (stricter — rejects sandbox VPECs)
primust verify evidence-pack.json --production

# Offline with pinned trust root
primust verify evidence-pack.json --trust-root org-key.pem

# Machine-readable JSON for automated audit workflows
primust verify evidence-pack.json --json
```

---

## Framework Alignment

### EU AI Act

Articles 9, 12, and 17 require risk management documentation, logging of automatic decisions, and quality management systems. Primust VPECs provide cryptographically verifiable execution logs.

- **Article 12 (Logging):** `eu_ai_act_art12_v1` bundle — `enforcement_rate` (ZK), `pii_non_detection` (ZK), `policy_continuity` (ZK). All Mathematical ceiling.
- **Article 9 (Risk Management):** `risk_classification` field on pipeline init (`EU_HIGH_RISK` / `EU_LIMITED_RISK` / `EU_MINIMAL_RISK`).
- **Article 13 (Transparency):** `explanation_commitment` on check execution records. `ai_disclosure_check` archetype.
- **Article 19 (Record-keeping):** `retention_policy: "EU_AI_ACT_10Y"` on pipeline init.

Primust does not assess EU AI Act risk classification — that is the provider's responsibility.

### HIPAA

Security Rule (§164.312) requires audit controls and integrity controls.

- **Audit controls:** VPEC chain provides tamper-evident execution records. `hipaa_safeguards_v1` bundle covers PHI access governance.
- **Integrity controls:** Hash-locked and Mathematical-level checks satisfy integrity verification.
- **PHI:** Primust never transits PHI. ZK proofs confirm computation integrity without exposing health data. `retention_policy: "HIPAA_6Y"` on pipeline init.

### SOC 2

Trust Services Criteria CC7.1 (monitoring) and CC8.1 (change management) align with VPEC execution records and policy bundle versioning. `soc2_cc_v1` bundle. Evidence Packs can serve as SOC 2 Type II artifacts — auditors verify independently with `primust verify`.

### AIUC-1

Primust implements AIUC-1 natively. Schema fields `actor_id`, `explanation_commitment`, `bias_audit`, `regulatory_context`, and `retention_policy` are built-in. The Evidence Pack `framework_view` section maps VPEC claims to AIUC-1 controls.

> **Critical limitation:** Primust is evidence infrastructure, not a compliance assessment tool. It proves execution integrity for declared operations. Compliance determination is the responsibility of qualified assessors evaluating Primust artifacts alongside other evidence.

---

## Red Flags

| Condition | What It Indicates |
|---|---|
| **All checks at Attestation** | No cryptographic proof — signed declarations only. Flag if used for regulated, high-risk operations. Request compensating controls. |
| **`environment: "sandbox"` in production evidence** | Sandbox VPECs are not audit-acceptable. Verify `environment: "production"` on all VPECs in the pack. |
| **Unresolved Critical gaps** | `proof_level_floor_breach`, `reviewer_credential_invalid`, `deterministic_consistency_violation`, `enforcement_override`, `admission_gate_override` — must have waivers with `risk_treatment` declared or remediation plans. |
| **Expired waivers** | Waivers have mandatory expiration (max 90 days). Expired = unresolved gap. `risk_treatment` must be re-declared. |
| **Large timestamp gaps between sequential records** | May indicate removed or suppressed records. Compare against expected pipeline execution duration. |
| **`provable_surface_ungoverned` > 0.30** | Over 30% of declared checks have no record this run. Investigate why manifest checks weren't executed. |
| **Signing key mismatch** | Signing key does not match org's registered key. Possible unauthorized Evidence Pack generation or key compromise. |
| **Missing cross-org VPECs** | If pipeline depends on upstream data, `upstream_vpec_verify` records should be present. Missing = `upstream_vpec_missing` gap. |
| **Connector-specific gaps** | `{platform}_api_error` or `{platform}_auth_failure` — the regulated platform was unreachable during the period. Governance for that process is unverifiable. |

---

## Enterprise BYOK — Bring Your Own Key

Enterprise customers use their own signing key. The organization's PKI — not Primust's — is the root of trust.

```bash
# Auditor verifies against org's trust root directly
primust verify evidence-pack.json --trust-root https://pki.acme.corp/.well-known/primust-pubkey.pem
```

When `--trust-root` is specified, `primust-verify` bypasses Primust's key registry entirely and validates against the org's own public key.

---

## Standard Audit Procedure

```python
import subprocess
import json
import sys

def audit_evidence_pack(pack_path, trust_root=None):
    cmd = ["primust", "verify", pack_path, "--json"]
    if trust_root:
        cmd.extend(["--trust-root", trust_root])

    result = subprocess.run(cmd, capture_output=True, text=True)
    verification = json.loads(result.stdout)

    if verification["result"] != "PASS":
        print(f"FAIL: {verification['failures']}")
        sys.exit(1)

    # Red flag checks
    flags = []
    if verification.get("environment") == "sandbox":
        flags.append("SANDBOX_VPEC — not audit-acceptable")
    if verification["gaps"]["critical"] > 0:
        flags.append(f"CRITICAL_GAPS: {verification['gaps']['critical']} unresolved")
    if any(w.get("expired") for w in verification.get("waivers", [])):
        flags.append("EXPIRED_WAIVERS — treat as unresolved gaps")
    if verification.get("provable_surface_ungoverned", 0) > 0.30:
        flags.append(f"HIGH_UNGOVERNED: {verification['provable_surface_ungoverned']:.0%} of manifest checks unexecuted")

    summary = {
        "pack": pack_path,
        "verification": "PASS",
        "proof_level_floor": verification.get("proof_level_floor"),
        "provable_surface": verification.get("provable_surface"),
        "provable_surface_breakdown": verification.get("provable_surface_breakdown"),
        "gaps": verification["gaps"],
        "red_flags": flags,
        "recommendation": "CLEAR" if not flags else "REVIEW_REQUIRED"
    }

    print(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    audit_evidence_pack(sys.argv[1])
```

---

## Audit Reports

Primust generates signed PDF audit reports from Evidence Packs.

```bash
# Verify a signed PDF audit report
primust verify-report audit-report-2026-03-16.pdf
```

**Report contents:**
- Executive Summary — pass/fail, pipeline, date range, `provable_surface`
- Verification Results — all five checks with detail
- Provable Surface Report — breakdown by proof level
- Gap Analysis — all gaps with taxonomy codes, severity, waiver status and `risk_treatment`
- Framework Alignment — Evidence Pack claims mapped to applicable framework controls
- Red Flag Assessment — automated checks
- Cryptographic Signatures — report signing key, Evidence Pack signing key, chain of trust

---

*Primust Audit Guide · docs.primust.com/audit*
*Canonical sources: DECISIONS_v13, MASTER_v9, TECH_SPEC_v8*
