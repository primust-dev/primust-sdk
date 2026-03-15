"""
Startup seeder — loads built-in policy bundles into DB on API boot.

Uses INSERT … ON CONFLICT DO NOTHING for idempotency.
Bundle data is embedded directly (the primust-checks package may not be
installed in the API runtime).
"""

from __future__ import annotations

import json

import structlog

from ..db import execute, get_pool

logger = structlog.get_logger("primust.bundle_seeder")

# ── Built-in bundle definitions ──

BUILTIN_BUNDLES: list[dict] = [
    {
        "bundle_id": "ai_agent_general_v1",
        "name": "AI Agent General",
        "description": (
            "Baseline policy bundle for any AI agent deployment. Covers PII scanning, "
            "prompt injection detection, output toxicity, hallucination grounding, "
            "and data-leak prevention."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "pii_scan", "version": "2.4.1", "required": True},
            {"check": "prompt_injection", "version": "1.2.0", "required": True},
            {"check": "output_toxicity", "version": "1.1.0", "required": True},
            {"check": "hallucination_grounding", "version": "1.0.0", "required": True},
            {"check": "data_leak_prevention", "version": "1.3.0", "required": True},
        ],
        "framework_mappings": [],
        "estimated_provable_surface": 0.72,
    },
    {
        "bundle_id": "eu_ai_act_art12_v1",
        "name": "EU AI Act Article 12",
        "description": (
            "Policy bundle aligned with EU AI Act Article 12 transparency and "
            "record-keeping obligations for high-risk AI systems."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "pii_scan", "version": "2.4.1", "required": True},
            {"check": "prompt_injection", "version": "1.2.0", "required": True},
            {"check": "output_toxicity", "version": "1.1.0", "required": True},
            {"check": "bias_detection", "version": "1.0.0", "required": True},
            {"check": "transparency_logging", "version": "1.0.0", "required": True},
            {"check": "human_oversight_flag", "version": "1.0.0", "required": True},
            {"check": "data_provenance", "version": "1.0.0", "required": True},
        ],
        "framework_mappings": [
            {"framework": "eu_ai_act", "article": "12", "obligation": "record_keeping"},
            {"framework": "eu_ai_act", "article": "13", "obligation": "transparency"},
        ],
        "estimated_provable_surface": 0.65,
    },
    {
        "bundle_id": "hipaa_safeguards_v1",
        "name": "HIPAA Safeguards",
        "description": (
            "Policy bundle covering HIPAA technical safeguards for AI systems "
            "handling protected health information (PHI)."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "pii_scan", "version": "2.4.1", "required": True, "config": {"phi_mode": True}},
            {"check": "data_leak_prevention", "version": "1.3.0", "required": True},
            {"check": "access_control_verify", "version": "1.0.0", "required": True},
            {"check": "audit_trail_integrity", "version": "1.0.0", "required": True},
            {"check": "encryption_at_rest", "version": "1.0.0", "required": True},
            {"check": "encryption_in_transit", "version": "1.0.0", "required": True},
        ],
        "framework_mappings": [
            {"framework": "hipaa", "section": "164.312(a)", "safeguard": "access_control"},
            {"framework": "hipaa", "section": "164.312(e)", "safeguard": "transmission_security"},
        ],
        "estimated_provable_surface": 0.70,
    },
    {
        "bundle_id": "soc2_cc_v1",
        "name": "SOC 2 Common Criteria",
        "description": (
            "Policy bundle mapping to SOC 2 Type II Common Criteria (CC) trust "
            "service principles for AI-powered services."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "pii_scan", "version": "2.4.1", "required": True},
            {"check": "access_control_verify", "version": "1.0.0", "required": True},
            {"check": "change_management_log", "version": "1.0.0", "required": True},
            {"check": "risk_assessment_tag", "version": "1.0.0", "required": True},
            {"check": "incident_response_hook", "version": "1.0.0", "required": True},
            {"check": "availability_monitor", "version": "1.0.0", "required": True},
        ],
        "framework_mappings": [
            {"framework": "soc2", "criteria": "CC6.1", "principle": "logical_access"},
            {"framework": "soc2", "criteria": "CC7.2", "principle": "system_monitoring"},
            {"framework": "soc2", "criteria": "CC8.1", "principle": "change_management"},
        ],
        "estimated_provable_surface": 0.68,
    },
    {
        "bundle_id": "coding_agent_v1",
        "name": "Coding Agent",
        "description": (
            "Policy bundle tailored for AI coding agents. Covers code injection "
            "prevention, secret detection, license compliance, and sandbox enforcement."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "code_injection_scan", "version": "1.0.0", "required": True},
            {"check": "secret_detection", "version": "1.1.0", "required": True},
            {"check": "license_compliance", "version": "1.0.0", "required": True},
            {"check": "sandbox_enforcement", "version": "1.0.0", "required": True},
            {"check": "output_toxicity", "version": "1.1.0", "required": False},
            {"check": "data_leak_prevention", "version": "1.3.0", "required": True},
        ],
        "framework_mappings": [],
        "estimated_provable_surface": 0.78,
    },
    {
        "bundle_id": "supply_chain_governance_v1",
        "name": "Supply Chain Governance",
        "description": (
            "Policy bundle for software supply chain verification. Covers upstream VPEC "
            "verification, dependency hash checking, schema validation, and secrets scanning. "
            "Entry point for SLSA, NIST SSDF, and 2026 NDAA AI supply chain buyers."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "upstream_vpec_verify", "version": "1.0.0", "required": True},
            {"check": "dependency_hash_check", "version": "1.0.0", "required": True},
            {"check": "schema_validation", "version": "1.0.0", "required": False},
            {"check": "secrets_scanner", "version": "1.0.0", "required": True},
        ],
        "framework_mappings": [
            {"framework": "slsa", "level": "L2", "requirement": "provenance"},
            {"framework": "nist_ssdf", "practice": "PS.1", "requirement": "software_integrity"},
        ],
        "estimated_provable_surface": 0.90,
    },
    {
        "bundle_id": "financial_data_governance_v1",
        "name": "Financial Data Governance",
        "description": (
            "Policy bundle for financial data pipeline governance. Covers schema validation, "
            "reconciliation checks, PII scanning, and upstream VPEC verification. "
            "Entry point for OCC/FCA model risk and SEC audit trail buyers."
        ),
        "version": "1.0.0",
        "checks": [
            {"check": "schema_validation", "version": "1.0.0", "required": True},
            {"check": "reconciliation_check", "version": "1.0.0", "required": True},
            {"check": "pii_regex", "version": "1.0.0", "required": True},
            {"check": "upstream_vpec_verify", "version": "1.0.0", "required": False},
        ],
        "framework_mappings": [
            {"framework": "occ_sr1115", "requirement": "model_risk_management"},
            {"framework": "sec", "requirement": "audit_trail"},
        ],
        "estimated_provable_surface": 0.85,
    },
]


async def seed_builtin_bundles() -> None:
    """Insert built-in bundles into both regional DBs. Idempotent."""
    for region in ("us", "eu"):
        pool = await get_pool(region)
        async with pool.acquire() as conn:
            for bundle in BUILTIN_BUNDLES:
                await conn.execute(
                    """INSERT INTO policy_bundles
                       (bundle_id, org_id, name, description, version, checks,
                        framework_mappings, estimated_provable_surface, is_builtin, created_at)
                       VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, TRUE, NOW())
                       ON CONFLICT (bundle_id) DO NOTHING""",
                    bundle["bundle_id"],
                    bundle["name"],
                    bundle["description"],
                    bundle["version"],
                    json.dumps(bundle["checks"]),
                    json.dumps(bundle["framework_mappings"]),
                    bundle["estimated_provable_surface"],
                )
            logger.info(
                "Built-in bundles seeded",
                region=region,
                count=len(BUILTIN_BUNDLES),
            )
