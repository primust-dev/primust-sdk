"""Static analysis tool for discovering governance decision points.

This is a STATIC ANALYSIS tool. It does NOT execute code.
It does NOT read data. It does NOT access any customer content.

It walks the codebase and identifies governance decision points via AST parsing.
"""

from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from primust.discovery.patterns import (
    PATTERNS,
    MODULE_PATTERNS,
    CALL_PATTERNS,
    Pattern,
)


@dataclass
class DecisionPoint:
    """A discovered governance decision point."""
    file: str
    line: int
    function_name: str
    pattern: Pattern
    suggested_manifest_id: str


@dataclass
class DiscoveryReport:
    """Result of analyzing a codebase."""
    root_path: str
    files_analyzed: int
    lines_analyzed: int
    decision_points: list[DecisionPoint] = field(default_factory=list)
    manifests_generated: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.decision_points)

    def by_proof_level(self) -> dict[str, list[DecisionPoint]]:
        result: dict[str, list[DecisionPoint]] = {
            "mathematical": [],
            "execution": [],
            "witnessed": [],
            "attestation": [],
        }
        for dp in self.decision_points:
            level = dp.pattern.proof_level
            if level == "verifiable_inference":
                level = "execution"
            result.setdefault(level, []).append(dp)
        return result


class _Visitor(ast.NodeVisitor):
    """AST visitor that finds governance decision points."""

    def __init__(self, file_path: str, imported_modules: set[str]) -> None:
        self.file_path = file_path
        self.imported_modules = imported_modules
        self.points: list[DecisionPoint] = []
        self._manifest_counter = 0

    def visit_Call(self, node: ast.Call) -> None:
        call_str = self._get_call_string(node)

        # Check against call patterns
        for pattern_str, pattern in CALL_PATTERNS.items():
            if self._matches_call(call_str, pattern_str):
                self._add_point(node, call_str, pattern)
                break

        # Check function name for human review patterns
        if isinstance(node.func, ast.Name):
            for p in PATTERNS:
                if p.category == "human_review" and node.func.id in p.call_patterns:
                    self._add_point(node, node.func.id, p)
                    break

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imported_modules.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imported_modules.add(node.module.split(".")[0])
        self.generic_visit(node)

    def _get_call_string(self, node: ast.Call) -> str:
        """Reconstruct a dotted call string from an AST Call node."""
        parts: list[str] = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)

    def _matches_call(self, call_str: str, pattern_str: str) -> bool:
        """Check if a call string matches a pattern (suffix match)."""
        return call_str == pattern_str or call_str.endswith("." + pattern_str)

    def _add_point(self, node: ast.Call, call_str: str, pattern: Pattern) -> None:
        self._manifest_counter += 1
        manifest_id = f"{pattern.suggested_manifest_prefix}v{self._manifest_counter}"
        self.points.append(
            DecisionPoint(
                file=self.file_path,
                line=node.lineno,
                function_name=call_str,
                pattern=pattern,
                suggested_manifest_id=manifest_id,
            )
        )


def discover(
    root_path: str,
    output_dir: str | None = None,
) -> DiscoveryReport:
    """Analyze a codebase for governance decision points.

    Static analysis only — does NOT execute any code.
    Zero API calls — fully offline.

    Args:
        root_path: Path to the codebase root.
        output_dir: Optional directory for generated manifest stubs.

    Returns:
        DiscoveryReport with all found decision points.
    """
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {root_path}")

    files_analyzed = 0
    lines_analyzed = 0
    all_points: list[DecisionPoint] = []

    for py_file in root.rglob("*.py"):
        # Skip __pycache__, .venv, node_modules
        parts = py_file.parts
        if any(p.startswith(".") or p in ("__pycache__", "node_modules", ".venv") for p in parts):
            continue

        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        files_analyzed += 1
        lines_analyzed += source.count("\n") + 1

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        imported_modules: set[str] = set()
        visitor = _Visitor(str(py_file.relative_to(root)), imported_modules)
        visitor.visit(tree)
        all_points.extend(visitor.points)

    report = DiscoveryReport(
        root_path=root_path,
        files_analyzed=files_analyzed,
        lines_analyzed=lines_analyzed,
        decision_points=all_points,
    )

    # Generate manifest stubs if output_dir specified
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for dp in all_points:
            manifest = {
                "manifest_id": dp.suggested_manifest_id,
                "name": dp.function_name,
                "proof_level": dp.pattern.proof_level,
                "category": dp.pattern.category,
                "source_file": dp.file,
                "source_line": dp.line,
            }
            manifest_path = out / f"{dp.suggested_manifest_id}.json"
            manifest_path.write_text(json.dumps(manifest, indent=2))
            report.manifests_generated.append(str(manifest_path))

    return report


def format_report(report: DiscoveryReport) -> str:
    """Format a discovery report for CLI output."""
    lines = [
        "=== Primust Discovery Report ===",
        f"Analyzed: {report.root_path} ({report.files_analyzed} files, "
        f"{report.lines_analyzed:,} lines)",
        "",
        f"Governance Decision Points Found: {report.count}",
        "",
    ]

    by_level = report.by_proof_level()
    level_labels = {
        "mathematical": "Mathematical (deterministic, ZK-provable)",
        "execution": "Execution (ML model, hash-bindable)",
        "witnessed": "Witnessed (human review patterns)",
        "attestation": "Attestation (LLM calls, opaque)",
    }

    for level, label in level_labels.items():
        points = by_level.get(level, [])
        if points:
            lines.append(f"{label}:")
            for dp in points:
                lines.append(
                    f"  {dp.file}:{dp.line}  — {dp.function_name}() "
                    f"— suggest: manifest {dp.suggested_manifest_id}"
                )
            lines.append("")

    if report.manifests_generated:
        lines.append(
            f"Manifest Scaffolding Generated: {len(report.manifests_generated)} files"
        )

    lines.append("=== End Report ===")
    return "\n".join(lines)
