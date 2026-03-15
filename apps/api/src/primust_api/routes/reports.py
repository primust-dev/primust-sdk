"""
Audit report endpoints.

POST /api/v1/evidence-packs/{pack_id}/report — Generate a signed PDF audit report
GET  /api/v1/reports/{report_id}             — Download the signed PDF
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from ..auth import AuthContext, require_auth
from ..db import fetch_one
from ..services.report_generator import generate_audit_report

router = APIRouter(prefix="/api/v1", tags=["reports"])

_STORAGE_PATH = os.environ.get(
    "PRIMUST_REPORT_STORAGE_PATH",
    "/tmp/primust-reports",
)


@router.post("/evidence-packs/{pack_id}/report")
async def create_report(
    pack_id: str,
    include_framework_mapping: bool = Query(default=True),
    auth: AuthContext = Depends(require_auth),
) -> dict[str, str]:
    """Generate a signed PDF audit report from an Evidence Pack.

    Returns:
        { "report_id": "...", "download_url": "...", "signed_at": "...", "expires_at": "..." }
    """
    # Verify org ownership of the pack
    pack_row = await fetch_one(
        auth.org_region,
        "SELECT org_id FROM evidence_packs WHERE pack_id = $1",
        pack_id,
    )
    if not pack_row:
        raise HTTPException(status_code=404, detail=f"Evidence pack {pack_id} not found")
    if pack_row["org_id"] != auth.org_id:
        raise HTTPException(status_code=404, detail=f"Evidence pack {pack_id} not found")

    try:
        result = await generate_audit_report(
            pack_id=pack_id,
            region=auth.org_region,
            include_framework_mapping=include_framework_mapping,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Report generation failed. Please retry or contact support@primust.com.",
        )

    return result


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    auth: AuthContext = Depends(require_auth),
) -> FileResponse:
    """Download a previously generated audit report PDF.

    Requires authentication — caller must belong to the org that generated the report.
    Once downloaded, verify offline with: primust verify-report report.pdf
    """
    # Check if report exists and is not expired
    for region in ("us", "eu"):
        try:
            row = await fetch_one(
                region,
                "SELECT report_id, org_id, expires_at FROM audit_reports WHERE report_id = $1",
                report_id,
            )
            if row:
                # Verify org ownership
                if row.get("org_id") != auth.org_id:
                    raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

                # Check expiry
                expires_at = row.get("expires_at")
                if expires_at:
                    if isinstance(expires_at, str):
                        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    else:
                        exp_dt = expires_at
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if exp_dt < datetime.now(timezone.utc):
                        raise HTTPException(
                            status_code=410,
                            detail=f"Report {report_id} has expired",
                        )

                # Serve the PDF file
                pdf_path = Path(_STORAGE_PATH) / f"{report_id}.pdf"
                if not pdf_path.exists():
                    raise HTTPException(
                        status_code=404,
                        detail=f"Report {report_id} file not found on disk",
                    )

                return FileResponse(
                    path=str(pdf_path),
                    media_type="application/pdf",
                    filename=f"{report_id}.pdf",
                    headers={
                        "Content-Disposition": f'attachment; filename="{report_id}.pdf"',
                    },
                )
        except HTTPException:
            raise
        except Exception:
            # Region might be unreachable — try the other
            continue

    raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
