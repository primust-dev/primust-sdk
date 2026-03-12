"""
Primust SDK
===========
Verifiable Process Execution Credentials for regulated workflows.

Quickstart:
    import primust

    p = primust.Pipeline(api_key="pk_live_...", workflow_id="my-workflow")

    run = p.open()
    result = run.record(
        check="aml_screen",
        manifest_id="sha256:abc123...",
        input=entity_data,       # committed locally — never sent to Primust
        check_result="pass",
    )
    # Write result.commitment_hash to your own logs (log linkage anchor)
    vpec = run.close()

Privacy guarantee:
    Raw input values are committed locally via Poseidon2 (or SHA-256 when
    the native extension is unavailable). Only commitment hashes and bounded
    normalized metadata transit to api.primust.com. Your data never leaves
    your environment.

Docs: https://docs.primust.com
Verify: https://verify.primust.com
"""

from primust.pipeline import (
    Pipeline,
    CheckSession,
    ReviewSession,
    ResumedContext,
    ZK_IS_BLOCKING,
)
from primust.models import (
    CheckResult,
    GovernanceGap,
    LoggerOptions,
    ManifestRegistration,
    PrimustLogEvent,
    ProofLevel,
    ProofLevelBreakdown,
    RecordResult,
    VPEC,
    VisibilityMode,
)
from primust.models import (
    CheckSession as ModelCheckSession,
    ReviewSession as ModelReviewSession,
)

__version__ = "0.1.0"
__all__ = [
    "Pipeline",
    "CheckResult",
    "CheckSession",
    "GovernanceGap",
    "LoggerOptions",
    "ManifestRegistration",
    "ModelCheckSession",
    "ModelReviewSession",
    "PrimustLogEvent",
    "ProofLevel",
    "ProofLevelBreakdown",
    "RecordResult",
    "ResumedContext",
    "ReviewSession",
    "VPEC",
    "VisibilityMode",
    "ZK_IS_BLOCKING",
]
