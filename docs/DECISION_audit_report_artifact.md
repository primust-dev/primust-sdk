# DECISION: Audit Report as Named Artifact Type
## Primust, Inc. · Proposed Addition to DECISIONS
### March 15, 2026 · For review and merge into DECISIONS_v12

---

## Summary

The signed Audit Report is a new named artifact type alongside VPEC, Evidence Pack, and Waiver. It is the artifact an auditor receives, verifies, and signs off on. The raw Evidence Pack is the developer/engineering artifact. The Audit Report is the compliance/governance artifact.

---

## Artifact Taxonomy (Updated)

| Artifact | Audience | Contains | Signed By |
|---|---|---|---|
| VPEC | Machines, SDKs, downstream pipelines | Commitment hashes, proof level, check manifest, gaps | Primust KMS or org BYOK |
| Evidence Pack | Engineering, internal review | Multiple VPECs, observation summaries, selective disclosure set | Primust KMS or org BYOK |
| Waiver | Compliance, risk management | Gap acknowledgment, rationale, expiry, approver identity | Org BYOK (required) |
| **Audit Report** | **Auditors, regulators, external reviewers** | **Cover, governance summary, per-VPEC results, framework mappings, gaps/waivers, verification instructions** | **Primust KMS or org BYOK** |

---

## Generation

Audit Reports are generated from an Evidence Pack. They are never created from scratch or from individual VPECs.

```
POST /api/v1/evidence-packs/{pack_id}/report
```

**Request parameters:**
- `framework_mappings`: optional list of frameworks to map against (e.g., `["eu_ai_act", "sox", "hipaa", "iso_9001"]`)
- `include_waivers`: boolean, default `true`
- `signing_key`: `primust` (default) or `byok` (Enterprise tier)

**Response:** Signed Audit Report JSON artifact with `Content-Type: application/json` and `X-Primust-Signature` header.

---

## Signing

Ed25519 over SHA-256 of the canonical report JSON.

**Canonicalization:** JSON Canonicalization Scheme (JCS, RFC 8785). Deterministic serialization ensures the same report always produces the same hash. No whitespace ambiguity. No key ordering ambiguity.

**Signing key selection:** Same rules as VPEC signing (DECISIONS_v11 Section 7).

| Tier | Signing Key | Trust Anchor |
|---|---|---|
| Developer / Growth | Primust GCP KMS Ed25519 | primust.com/.well-known/primust-pubkey.pem |
| Enterprise | Customer BYOK Ed25519 | customer.com/.well-known/primust-pubkey.pem |

---

## Offline Verification

```bash
primust verify-report report.json
# Exit codes: 0 = valid, 1 = invalid, 2 = valid SANDBOX, 3 = valid but key expired/revoked
```

**No account required.** No API key. No network calls after initial public key fetch (or zero network calls with `--trust-root key.pem`). Ships in `primust-verify` (Apache-2.0).

The `verify-report` command:
1. Parses the report JSON
2. Extracts the signature from the `_signature` field
3. Strips the `_signature` field
4. Canonicalizes the remaining JSON (JCS)
5. Computes SHA-256 of the canonical form
6. Verifies Ed25519 signature against the resolved public key
7. Validates that all referenced VPECs have valid commitment hashes
8. Returns structured result with per-section integrity status

---

## Report Contents

| Section | Contents | Privacy Guarantee |
|---|---|---|
| Cover | Report ID, generation timestamp, org name, Evidence Pack ID, framework list, signing key fingerprint | No sensitive data |
| Governance Summary | Total VPECs, provable surface aggregate, proof level floor, check count by type, gap count by severity | Aggregate metrics only |
| Per-VPEC Results | For each VPEC: check manifest, proof level floor, provable surface breakdown, gap records, waiver references | Commitment hashes only — no raw check inputs |
| Framework Control Mappings | For each requested framework: control ID, control description, mapped check(s), pass/fail/gap status | Framework metadata + check results |
| Gaps and Waivers | All gap records across all VPECs, linked waiver records where applicable, unresolved gaps highlighted | Gap type and severity — no raw data |
| Verification Instructions | CLI command to verify, public key location, expected hash, manual verification steps | Public information only |

**Privacy guarantee:** The Audit Report does NOT contain raw check inputs. Only commitment hashes. An auditor can verify that checks ran and what their results were. An auditor cannot extract the original data that was checked. This is the same privacy boundary as the VPEC itself, extended to the report layer.

---

## P1 Watermark Requirement

Reports generated during P1 (pre-production phase) MUST display a watermark. This is a hard requirement, not a configuration option.

**Watermark rules:**
- If any VPEC in the Evidence Pack has `environment: "sandbox"` or `test: true`, the report is P1
- P1 reports include `"p1_watermark": true` at the top level
- P1 reports include `"p1_notice": "PRE-PRODUCTION — NOT FOR AUDIT ACCEPTANCE"` in the cover section
- `primust verify-report` on a P1 report returns exit code 2 (valid SANDBOX), not 0
- The verify site (verify.primust.com) renders P1 reports with a visible watermark banner

**Rationale:** Prevents sandbox/test reports from being passed off as production audit evidence. The watermark is cryptographically bound — it cannot be stripped without invalidating the signature.

---

## Auditor Workflow

```
1. Receive Audit Report (JSON file or verify.primust.com link)
2. Run: primust verify-report report.json
3. Confirm exit code 0 (valid, production)
4. Review governance summary — provable surface, proof level floor
5. Review per-VPEC results — check manifest coverage, gaps
6. Review framework mappings — control coverage for applicable framework
7. Review gaps/waivers — assess risk of unresolved gaps
8. Sign off or request remediation
```

The auditor does NOT need:
- A Primust account
- Access to the Evidence Pack
- Access to the raw data that was checked
- Network connectivity (after initial key fetch, or with pinned trust root)

---

## Report vs. Evidence Pack: Separation of Concerns

| Dimension | Evidence Pack | Audit Report |
|---|---|---|
| Audience | Engineering, DevOps, internal compliance | External auditors, regulators, reviewers |
| Contains raw observation data | Yes (within selective disclosure bounds) | No — commitment hashes only |
| Contains framework mappings | No | Yes |
| Contains verification instructions | No (assumes technical user) | Yes (assumes non-technical auditor) |
| Mutable | Yes (VPECs can be added before pack close) | No — immutable once signed |
| Generated from | Pipeline runs (VPECs accumulate) | Evidence Pack (single generation step) |

---

## API Surface

```
POST   /api/v1/evidence-packs/{pack_id}/report     # Generate report
GET    /api/v1/reports/{report_id}                   # Fetch report
GET    /api/v1/reports/{report_id}/verify            # Server-side verify (convenience)
DELETE /api/v1/reports/{report_id}                   # Soft-delete (org admin only)
```

CLI:
```bash
primust report generate --pack-id {pack_id}                    # Generate
primust report generate --pack-id {pack_id} --frameworks eu_ai_act,sox  # With mappings
primust verify-report report.json                               # Verify (Apache-2.0)
primust verify-report report.json --trust-root key.pem          # Verify offline
```

---

## Rationale

1. **Auditors need a different artifact than engineers.** The Evidence Pack is too detailed and too raw for an auditor's workflow. The VPEC is too granular — auditors evaluate governance posture across a body of work, not per-execution. The Audit Report is the right abstraction for the audit workflow.

2. **Signed reports are verifiable artifacts, not PDFs.** A PDF report is a screenshot. A signed JSON report is a cryptographic artifact that can be independently verified. This is the difference between "trust the report generator" and "trust math."

3. **Privacy guarantee must extend to the report layer.** If VPECs contain only commitment hashes (no raw data), but the report leaks raw data, the privacy boundary is broken. The report inherits the VPEC privacy model: commitment hashes only.

4. **P1 watermark prevents misrepresentation.** Without the watermark, a sandbox report could be presented to an auditor as production evidence. The watermark is cryptographically bound, not cosmetic.

5. **Offline verification is non-negotiable.** Same principle as VPEC verification (DECISIONS_v11 Section 8): the report must be verifiable without Primust infrastructure. `primust verify-report` ships in the Apache-2.0 `primust-verify` package.

---

*DECISION_audit_report_artifact.md · March 15, 2026 · Primust, Inc.*
*Proposed for DECISIONS_v12. Subject to review.*
