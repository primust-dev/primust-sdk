"""
Banned field enforcement — reject any request/response containing banned names.

BANNED: agent_id, pipeline_id, tool_name, session_id, trace_id, reliance_mode
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

BANNED_FIELDS = frozenset(
    ["agent_id", "pipeline_id", "tool_name", "session_id", "trace_id", "reliance_mode"]
)


def reject_banned_fields(body: dict[str, Any]) -> None:
    """Raise 422 if any banned field name appears in the body (recursively)."""
    _check_dict(body, "")


def _check_dict(obj: dict[str, Any], path: str) -> None:
    for key, value in obj.items():
        current = f"{path}.{key}" if path else key
        if key in BANNED_FIELDS:
            raise HTTPException(
                status_code=422,
                detail=f"Banned field '{key}' at '{current}'. "
                "See PRIMUST spec §4 — this field name is permanently retired.",
            )
        if isinstance(value, dict):
            _check_dict(value, current)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    _check_dict(item, f"{current}[{i}]")
