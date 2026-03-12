"""Library signature patterns for governance decision point detection.

Static analysis only — no code execution.
Classifies by proof level based on pattern type.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Pattern:
    """A pattern matching a governance decision point."""
    name: str
    # AST matching: module + function call patterns
    modules: list[str]
    call_patterns: list[str]
    # Classification
    proof_level: str  # mathematical | verifiable_inference | execution | witnessed | attestation
    category: str  # deterministic | ml_model | llm_call | human_review | external_api
    suggested_manifest_prefix: str


# ── Mathematical (deterministic, ZK-provable) ──

REGEX_PATTERN = Pattern(
    name="regex_check",
    modules=["re"],
    call_patterns=["re.match", "re.search", "re.fullmatch", "re.findall", "re.sub"],
    proof_level="mathematical",
    category="deterministic",
    suggested_manifest_prefix="regex_",
)

THRESHOLD_PATTERN = Pattern(
    name="threshold_check",
    modules=[],
    call_patterns=[],  # detected via AST comparison operators
    proof_level="mathematical",
    category="deterministic",
    suggested_manifest_prefix="threshold_",
)

ALLOWLIST_PATTERN = Pattern(
    name="allowlist_check",
    modules=[],
    call_patterns=[],  # detected via `in` operator on sets/lists
    proof_level="mathematical",
    category="deterministic",
    suggested_manifest_prefix="allowlist_",
)

# ── Execution (ML model, hash-bindable) ──

SKLEARN_PATTERN = Pattern(
    name="sklearn_predict",
    modules=["sklearn", "sklearn.ensemble", "sklearn.linear_model", "sklearn.svm"],
    call_patterns=["model.predict", "model.predict_proba", "model.transform", "model.fit_predict"],
    proof_level="execution",
    category="ml_model",
    suggested_manifest_prefix="ml_",
)

TORCH_PATTERN = Pattern(
    name="torch_inference",
    modules=["torch", "torch.nn"],
    call_patterns=["model.forward", "model.eval", "torch.no_grad"],
    proof_level="execution",
    category="ml_model",
    suggested_manifest_prefix="ml_",
)

EXTERNAL_API_PATTERN = Pattern(
    name="external_api_call",
    modules=["requests", "httpx", "aiohttp", "urllib3"],
    call_patterns=[
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
        "httpx.AsyncClient.get", "httpx.AsyncClient.post",
        "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
    ],
    proof_level="execution",
    category="external_api",
    suggested_manifest_prefix="api_",
)

# ── Witnessed (human review patterns) ──

HUMAN_REVIEW_PATTERN = Pattern(
    name="human_review",
    modules=[],
    call_patterns=[
        "approve", "human_approve", "sign_off", "human_review",
        "manual_review", "human_in_the_loop", "request_approval",
    ],
    proof_level="witnessed",
    category="human_review",
    suggested_manifest_prefix="review_",
)

# ── Attestation (LLM calls, opaque) ──

OPENAI_PATTERN = Pattern(
    name="openai_chat",
    modules=["openai"],
    call_patterns=[
        "openai.chat.completions.create",
        "openai.ChatCompletion.create",
        "client.chat.completions.create",
    ],
    proof_level="attestation",
    category="llm_call",
    suggested_manifest_prefix="llm_output_",
)

ANTHROPIC_PATTERN = Pattern(
    name="anthropic_messages",
    modules=["anthropic"],
    call_patterns=[
        "anthropic.messages.create",
        "anthropic.Anthropic.messages.create",
        "client.messages.create",
    ],
    proof_level="attestation",
    category="llm_call",
    suggested_manifest_prefix="llm_output_",
)

LANGGRAPH_PATTERN = Pattern(
    name="langgraph_tool",
    modules=["langgraph", "langchain", "langchain_core"],
    call_patterns=[
        "tool", "ToolNode", "StateGraph.add_node",
        "graph.add_node", "graph.add_edge",
    ],
    proof_level="execution",
    category="ml_model",
    suggested_manifest_prefix="tool_",
)

GOOGLE_GENAI_PATTERN = Pattern(
    name="google_genai",
    modules=["google.generativeai", "vertexai"],
    call_patterns=[
        "genai.GenerativeModel.generate_content",
        "model.generate_content",
    ],
    proof_level="attestation",
    category="llm_call",
    suggested_manifest_prefix="llm_output_",
)


# All patterns for matching
PATTERNS: list[Pattern] = [
    REGEX_PATTERN,
    SKLEARN_PATTERN,
    TORCH_PATTERN,
    EXTERNAL_API_PATTERN,
    HUMAN_REVIEW_PATTERN,
    OPENAI_PATTERN,
    ANTHROPIC_PATTERN,
    LANGGRAPH_PATTERN,
    GOOGLE_GENAI_PATTERN,
]

# Module-to-pattern lookup
MODULE_PATTERNS: dict[str, list[Pattern]] = {}
for p in PATTERNS:
    for m in p.modules:
        MODULE_PATTERNS.setdefault(m, []).append(p)

# Call-to-pattern lookup
CALL_PATTERNS: dict[str, Pattern] = {}
for p in PATTERNS:
    for c in p.call_patterns:
        CALL_PATTERNS[c] = p
