"""primust-ai: Unified entry point for Primust AI framework adapters.

Detects which adapter packages are installed (primust-langgraph,
primust-openai-agents, primust-google-adk) and provides a single
autoinstrument() call that wires them up.

Usage:
    import primust_ai
    primust_ai.autoinstrument(pipeline=p)
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

logger = logging.getLogger("primust.ai")

_ADAPTERS: dict[str, tuple[str, str]] = {
    # module_name -> (import_path, adapter_class_name)
    "primust_langgraph": ("primust_langgraph", "PrimustLangGraph"),
    "primust_openai_agents": ("primust_openai_agents", "PrimustOpenAIAgents"),
    "primust_google_adk": ("primust_google_adk", "PrimustGoogleADK"),
    # Built-in adapters shipped inside sdk-python
    "primust.adapters.crewai": ("primust.adapters.crewai", "PrimustCrewAICallback"),
    "primust.adapters.pydantic_ai": ("primust.adapters.pydantic_ai", "PrimustPydanticAIDep"),
}


def _detect_adapters() -> list[str]:
    """Return names of installed adapter packages."""
    found: list[str] = []
    for module_name in _ADAPTERS:
        try:
            importlib.import_module(module_name)
            found.append(module_name)
        except ImportError:
            pass
    return found


def autoinstrument(*, pipeline: Any, **kwargs: Any) -> list[Any]:
    """Auto-detect installed adapters and instrument the given pipeline.

    Args:
        pipeline: A Primust Pipeline instance (from `primust.Pipeline`).
        **kwargs: Additional keyword arguments forwarded to each adapter constructor.

    Returns:
        A list of instantiated adapter objects (one per detected adapter).

    Raises:
        RuntimeError: If no adapter packages are installed.
    """
    installed = _detect_adapters()
    if not installed:
        raise RuntimeError(
            "No Primust AI adapter packages found. Install at least one of: "
            "primust-langgraph, primust-openai-agents, primust-google-adk, "
            "or use built-in adapters (crewai, pydantic_ai) via pip install primust. "
            "Example: pip install primust-ai[langgraph]"
        )

    adapters: list[Any] = []
    for module_name in installed:
        import_path, class_name = _ADAPTERS[module_name]
        try:
            mod = importlib.import_module(import_path)
            cls = getattr(mod, class_name)
            adapter = cls(pipeline=pipeline, **kwargs)
            adapters.append(adapter)
            logger.info("Instrumented adapter: %s.%s", import_path, class_name)
        except Exception:
            logger.warning(
                "Failed to instrument adapter %s.%s",
                import_path,
                class_name,
                exc_info=True,
            )

    return adapters


__all__ = ["autoinstrument"]
