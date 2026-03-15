# DECISION: Cross-Org Verification as First-Class Check Type
## Primust, Inc. · Proposed Addition to DECISIONS
### March 15, 2026 · For review and merge into DECISIONS_v12

---

## Summary

`upstream_vpec_verify` is a named built-in check in primust-checks (Apache-2.0). It verifies that an upstream organization's VPEC is cryptographically valid, unexpired, and meets the verifier's policy requirements. This check is domain-neutral — it verifies any VPEC regardless of the upstream process type.

---

## Proof Ceiling

**Mathematical.** Ed25519 signature verification is deterministic, pure math. No trust in Primust infrastructure required at verification time. The check reads a VPEC, fetches or loads a public key, and performs `Ed25519_verify(pubkey, message, signature)`. The result is binary: valid or invalid. No model, no heuristic, no judgment call.

---

## Check Definition

```
check_name: upstream_vpec_verify
check_type: built_in
proof_level_ceiling: mathematical
license: Apache-2.0
ships_in: primust-checks
```

**Inputs:**
- `vpec`: the upstream VPEC JSON artifact (or URL to fetch it)
- `trust_root_mode`: `network` | `pinned`
- `trust_root_value`: well-known URL (network mode) or local PEM path (pinned mode)
- `policy`: optional constraints (max_age, required_org, min_proof_level_floor, required_checks, reject_test_mode)

**Output:** CheckExecutionRecord with pass/fail and, on failure, one or more gap records from the taxonomy below.

---

## Trust Root Modes

| Mode | Resolution | When to Use |
|---|---|---|
| `network` | Fetch public key from `https://{org_domain}/.well-known/primust-pubkey.pem` | Standard inter-org verification. Requires network at check time. |
| `pinned` | Load public key from local filesystem path | Air-gapped environments, CI pipelines, or when upstream key is pre-distributed. Zero network calls. |

In `network` mode, the check caches the fetched key with a configurable TTL (default 24h). Cache miss triggers a fresh fetch. If fetch fails and no cached key exists, the check emits `upstream_vpec_unavailable`.

---

## Gap Taxonomy

When `upstream_vpec_verify` fails, it emits one or more of the following gaps. These extend the canonical 21-type gap taxonomy from DECISIONS_v11 Section 22.

| Gap Type | Severity | Condition |
|---|---|---|
| `upstream_vpec_invalid` | Critical | Signature does not verify against the resolved public key. The VPEC has been tampered with or signed by an unknown key. |
| `upstream_vpec_expired` | High | VPEC `issued_at` is older than the policy-configured `max_age`. The upstream governance proof is stale. |
| `upstream_org_mismatch` | Critical | VPEC `org_id` or `org_domain` does not match the expected upstream organization. Wrong vendor, wrong entity. |
| `upstream_proof_level_insufficient` | High | VPEC `proof_level_floor` is below the policy-configured `min_proof_level_floor`. Upstream governance is weaker than required. |
| `upstream_checks_missing` | Medium | One or more checks listed in `policy.required_checks` are absent from the VPEC's check manifest. Upstream ran fewer checks than the verifier demands. |
| `upstream_vpec_test_mode` | High | VPEC has `environment: "sandbox"` or `test: true` but the verifying pipeline is running in a production context. Test/sandbox VPECs are not audit-acceptable. |
| `upstream_vpec_unavailable` | Critical | No VPEC was provided at all. The upstream organization did not supply a governance proof for this artifact/process. |

---

## Composability: Multi-Hop Provenance Chains

A pipeline that runs `upstream_vpec_verify` and then closes its own VPEC produces a new VPEC that contains a CheckExecutionRecord proving the upstream verification occurred. This VPEC can itself be verified by a further downstream organization. The result is a directed acyclic chain of cryptographic governance proofs.

```
Org A (data producer)
  → issues VPEC_A (proves data quality checks ran)

Org B (data processor)
  → runs upstream_vpec_verify on VPEC_A (mathematical proof it verified)
  → runs its own checks
  → issues VPEC_B (proves both its own checks AND upstream verification)

Org C (data consumer / regulated entity)
  → runs upstream_vpec_verify on VPEC_B
  → transitively trusts Org A's governance via the chain
  → issues VPEC_C for its own audit record
```

Each link in the chain is independently verifiable. No centralized trust broker. No shared infrastructure. The chain degrades gracefully: if Org C cannot verify VPEC_B, it gets a gap record — it does not silently accept unverified upstream data.

---

## Cross-Domain Examples

### AI: Platform Verifying ISV Governance
An enterprise AI platform accepts third-party AI agents from ISV vendors. Before routing user requests to a vendor agent, the platform runs `upstream_vpec_verify` on the vendor's latest VPEC. Policy requires: `min_proof_level_floor: execution`, `required_checks: ["pii_regex", "cost_bounds"]`, `max_age: 24h`. If the vendor's governance proof is missing or insufficient, the platform logs a gap and routes to a fallback agent.

### FSI: Bank Verifying Fintech Vendor's Data Quality
A bank consumes market data from a fintech data vendor. The vendor runs reconciliation checks and schema validation on every data delivery, issuing a VPEC per batch. The bank's ingestion pipeline runs `upstream_vpec_verify` with `required_checks: ["reconciliation_check", "schema_validation"]` and `max_age: 1h`. SOX audit evidence includes the bank's own VPEC proving it verified the vendor's governance.

### Software Supply Chain: Enterprise Verifying Vendor Build Pipeline
An enterprise consumes a vendor's SDK. The vendor's CI pipeline runs SAST, dependency hash checks, and SBOM generation, issuing a VPEC per release. The enterprise's dependency ingestion workflow runs `upstream_vpec_verify` with `pinned` trust root (vendor's public key distributed via secure channel). SLSA compliance evidence includes the verification record.

### Healthcare: Sponsor Verifying CRO Data Integrity
A pharmaceutical sponsor receives clinical trial data from a contract research organization (CRO). The CRO's data pipeline runs 21 CFR Part 11-aligned checks (audit trail integrity, electronic signature validation, data completeness) and issues a VPEC per data transfer. The sponsor's ingestion pipeline runs `upstream_vpec_verify` with `required_checks: ["audit_trail_integrity", "e_signature_validation"]`. FDA submission evidence includes the chain.

### Manufacturing: OEM Verifying Supplier QC
An aerospace OEM receives components from a tier-1 supplier. The supplier's QC process runs dimensional inspection checks, material certification validation, and batch traceability checks, issuing a VPEC per lot. The OEM's incoming inspection workflow runs `upstream_vpec_verify` with `required_checks: ["dimensional_inspection", "material_cert_validation"]`. AS9100 audit evidence includes the verification chain.

---

## Patent Surface

Cross-org verification chain composition — the mechanism by which a VPEC verification itself produces a VPEC, enabling multi-hop directed acyclic provenance chains across organizational boundaries — is a novel claim. This extends the existing PVP (Provenance Verification Protocol) provisional.

**Action required:** Flag for PCT continuation claim before July 2026 filing deadline. The claim covers: (1) the chain composition mechanism, (2) the gap taxonomy for cross-org failure modes, (3) the trust root resolution protocol (network vs. pinned), and (4) the transitive verification property.

---

## Rationale

1. **Cross-org trust is the killer feature.** A single-org governance proof is useful. A verifiable chain across organizational boundaries is transformative. Every regulated supply chain — software, financial, pharmaceutical, manufacturing — requires trust in upstream processes.

2. **Mathematical ceiling matters.** Because Ed25519 verification is pure math, cross-org verification does not degrade the verifier's proof level. A mathematical check verifying a mathematical VPEC remains mathematical end-to-end.

3. **Domain neutrality is essential.** The check verifies VPEC structure and signature. It does not know or care what the upstream process was. This is why it belongs in primust-checks (core), not in a domain pack.

4. **Two trust root modes cover all deployment contexts.** Network mode is convenient for standard inter-org flows. Pinned mode is required for air-gapped, regulated, and high-assurance environments. Both modes produce the same CheckExecutionRecord.

5. **Gap taxonomy makes failures actionable.** Seven distinct gap types mean the verifier knows exactly what went wrong and can route to the correct remediation workflow. "Upstream verification failed" is not actionable. "Upstream VPEC expired by 3 hours" is.

---

*DECISION_crossorg_verification.md · March 15, 2026 · Primust, Inc.*
*Proposed for DECISIONS_v12. Subject to review.*
