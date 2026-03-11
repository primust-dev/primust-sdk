"""P15-A: primust discover — 6 MUST PASS."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust.discovery.analyzer import discover, format_report
from primust.discovery.patterns import PATTERNS

SAMPLE_DIR = str(Path(__file__).resolve().parent / "discovery_sample")


class TestDiscovery:
    def test_discovers_langgraph_tool_calls(self) -> None:
        """MUST PASS: discover finds LangGraph tool calls in sample codebase."""
        report = discover(SAMPLE_DIR)

        langgraph_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "langgraph_tool"
        ]
        assert len(langgraph_points) > 0, "Should find LangGraph tool calls"
        assert any("add_node" in dp.function_name for dp in langgraph_points)

    def test_discovers_openai_chat(self) -> None:
        """MUST PASS: discover finds openai.chat.completions.create()."""
        report = discover(SAMPLE_DIR)

        openai_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "openai_chat"
        ]
        assert len(openai_points) > 0, "Should find OpenAI chat calls"
        assert openai_points[0].pattern.proof_level == "attestation"

    def test_regex_classified_as_mathematical(self) -> None:
        """MUST PASS: discover finds regex patterns → classifies as Mathematical."""
        report = discover(SAMPLE_DIR)

        regex_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "regex_check"
        ]
        assert len(regex_points) > 0, "Should find regex patterns"
        for dp in regex_points:
            assert dp.pattern.proof_level == "mathematical"
            assert dp.pattern.category == "deterministic"

    def test_makes_zero_api_calls(self) -> None:
        """MUST PASS: discover makes zero API calls (interceptor test)."""
        import urllib.request

        with patch.object(urllib.request, "urlopen", side_effect=AssertionError("No network calls allowed")) as mock:
            report = discover(SAMPLE_DIR)
            # Should complete without triggering the mock
            assert report.count > 0
            mock.assert_not_called()

    def test_makes_zero_file_writes_outside_output_dir(self, tmp_path: Path) -> None:
        """MUST PASS: discover does not write files outside ./primust_manifests/."""
        output_dir = str(tmp_path / "primust_manifests")

        # Track all file writes
        original_write = Path.write_text
        writes: list[str] = []

        def tracking_write(self_path: Path, *args: object, **kwargs: object) -> None:
            writes.append(str(self_path))
            return original_write(self_path, *args, **kwargs)  # type: ignore

        with patch.object(Path, "write_text", tracking_write):
            report = discover(SAMPLE_DIR, output_dir=output_dir)

        # All writes should be inside output_dir
        for w in writes:
            assert w.startswith(output_dir), f"Write outside output dir: {w}"

    def test_does_not_execute_discovered_functions(self) -> None:
        """MUST PASS: discover does not execute any discovered functions."""
        # If discover executed the sample code, it would try to import
        # sklearn, openai, anthropic, etc. which would fail since they're
        # not installed. The fact that discover succeeds proves it only
        # does AST parsing, not execution.
        report = discover(SAMPLE_DIR)

        # Should find points from files that import unavailable modules
        sklearn_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "sklearn_predict"
        ]
        openai_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "openai_chat"
        ]
        anthropic_points = [
            dp for dp in report.decision_points
            if dp.pattern.name == "anthropic_messages"
        ]

        # All found without executing any code
        assert len(sklearn_points) > 0
        assert len(openai_points) > 0
        assert len(anthropic_points) > 0

        # Verify the report format
        output = format_report(report)
        assert "=== Primust Discovery Report ===" in output
        assert "=== End Report ===" in output
        assert str(report.files_analyzed) in output
