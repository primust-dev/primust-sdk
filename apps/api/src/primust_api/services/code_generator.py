"""
Stateless code generation service — template-based, NOT AI-generated.

Produces copy-paste-ready integration code for supported frameworks and languages.
"""

from __future__ import annotations

from textwrap import dedent


def generate_code(
    framework: str,  # "langgraph" | "openai_agents" | "google_adk" | "otel" | "custom"
    manifest_ids: list[str],
    policy_id: str | None = None,
) -> dict[str, str]:
    """Return integration code for Python, TypeScript, and Java.

    Parameters
    ----------
    framework:
        One of ``langgraph``, ``openai_agents``, ``google_adk``, ``otel``, ``custom``.
    manifest_ids:
        List of content-addressed manifest IDs (``sha256:...``) to embed.
    policy_id:
        Optional policy/bundle ID for configuration.

    Returns
    -------
    dict with keys ``python_code``, ``typescript_code``, ``java_code``.
    """
    manifests_comment = "\n".join(f"# Manifest: {mid}" for mid in manifest_ids)
    manifests_ts_comment = "\n".join(f"// Manifest: {mid}" for mid in manifest_ids)
    manifests_java_comment = "\n".join(f"// Manifest: {mid}" for mid in manifest_ids)
    manifests_list_py = ", ".join(f'"{mid}"' for mid in manifest_ids)
    manifests_list_ts = ", ".join(f'"{mid}"' for mid in manifest_ids)
    manifests_list_java = ", ".join(f'"{mid}"' for mid in manifest_ids)
    policy_line_py = f'    policy_id="{policy_id}",' if policy_id else ""
    policy_line_ts = f'  policyId: "{policy_id}",' if policy_id else ""
    policy_line_java = f'        .policyId("{policy_id}")' if policy_id else ""

    generators = {
        "langgraph": _langgraph,
        "openai_agents": _openai_agents,
        "google_adk": _google_adk,
        "otel": _otel,
        "custom": _custom,
    }

    gen = generators.get(framework, _custom)
    return gen(
        manifests_comment=manifests_comment,
        manifests_ts_comment=manifests_ts_comment,
        manifests_java_comment=manifests_java_comment,
        manifests_list_py=manifests_list_py,
        manifests_list_ts=manifests_list_ts,
        manifests_list_java=manifests_list_java,
        policy_line_py=policy_line_py,
        policy_line_ts=policy_line_ts,
        policy_line_java=policy_line_java,
    )


# ── Framework templates ──


def _langgraph(**kw: str) -> dict[str, str]:
    python_code = dedent(f"""\
        import primust
        from primust_langgraph import PrimustLangGraph

        p = primust.Pipeline(
            api_key="YOUR_API_KEY",
            workflow_id="your-workflow",
        {kw['policy_line_py']}
        )
        adapter = PrimustLangGraph(pipeline=p)
        {kw['manifests_comment']}
        instrumented = adapter.instrument(your_compiled_graph)
    """)

    typescript_code = dedent(f"""\
        import {{ Pipeline }} from "@primust/sdk";
        import {{ PrimustLangGraph }} from "@primust/langgraph";

        const p = new Pipeline({{
          apiKey: "YOUR_API_KEY",
          workflowId: "your-workflow",
        {kw['policy_line_ts']}
        }});
        const adapter = new PrimustLangGraph({{ pipeline: p }});
        {kw['manifests_ts_comment']}
        const instrumented = adapter.instrument(yourCompiledGraph);
    """)

    java_code = dedent(f"""\
        import com.primust.Pipeline;
        import com.primust.langgraph.PrimustLangGraph;

        Pipeline p = Pipeline.builder()
            .apiKey("YOUR_API_KEY")
            .workflowId("your-workflow")
        {kw['policy_line_java']}
            .build();
        PrimustLangGraph adapter = new PrimustLangGraph(p);
        {kw['manifests_java_comment']}
        var instrumented = adapter.instrument(yourCompiledGraph);
    """)

    return {
        "python_code": python_code,
        "typescript_code": typescript_code,
        "java_code": java_code,
    }


def _openai_agents(**kw: str) -> dict[str, str]:
    python_code = dedent(f"""\
        import primust
        from primust_openai import PrimustOpenAIAgents

        p = primust.Pipeline(
            api_key="YOUR_API_KEY",
            workflow_id="your-workflow",
        {kw['policy_line_py']}
        )
        adapter = PrimustOpenAIAgents(pipeline=p)
        {kw['manifests_comment']}
        instrumented_agent = adapter.instrument(your_agent)
    """)

    typescript_code = dedent(f"""\
        import {{ Pipeline }} from "@primust/sdk";
        import {{ PrimustOpenAIAgents }} from "@primust/openai-agents";

        const p = new Pipeline({{
          apiKey: "YOUR_API_KEY",
          workflowId: "your-workflow",
        {kw['policy_line_ts']}
        }});
        const adapter = new PrimustOpenAIAgents({{ pipeline: p }});
        {kw['manifests_ts_comment']}
        const instrumented = adapter.instrument(yourAgent);
    """)

    java_code = dedent(f"""\
        import com.primust.Pipeline;
        import com.primust.openai.PrimustOpenAIAgents;

        Pipeline p = Pipeline.builder()
            .apiKey("YOUR_API_KEY")
            .workflowId("your-workflow")
        {kw['policy_line_java']}
            .build();
        PrimustOpenAIAgents adapter = new PrimustOpenAIAgents(p);
        {kw['manifests_java_comment']}
        var instrumented = adapter.instrument(yourAgent);
    """)

    return {
        "python_code": python_code,
        "typescript_code": typescript_code,
        "java_code": java_code,
    }


def _google_adk(**kw: str) -> dict[str, str]:
    python_code = dedent(f"""\
        import primust
        from primust_google_adk import PrimustGoogleADK

        p = primust.Pipeline(
            api_key="YOUR_API_KEY",
            workflow_id="your-workflow",
        {kw['policy_line_py']}
        )
        adapter = PrimustGoogleADK(pipeline=p)
        {kw['manifests_comment']}
        instrumented_agent = adapter.instrument(your_adk_agent)
    """)

    typescript_code = dedent(f"""\
        import {{ Pipeline }} from "@primust/sdk";
        import {{ PrimustGoogleADK }} from "@primust/google-adk";

        const p = new Pipeline({{
          apiKey: "YOUR_API_KEY",
          workflowId: "your-workflow",
        {kw['policy_line_ts']}
        }});
        const adapter = new PrimustGoogleADK({{ pipeline: p }});
        {kw['manifests_ts_comment']}
        const instrumented = adapter.instrument(yourAdkAgent);
    """)

    java_code = dedent(f"""\
        import com.primust.Pipeline;
        import com.primust.googleadk.PrimustGoogleADK;

        Pipeline p = Pipeline.builder()
            .apiKey("YOUR_API_KEY")
            .workflowId("your-workflow")
        {kw['policy_line_java']}
            .build();
        PrimustGoogleADK adapter = new PrimustGoogleADK(p);
        {kw['manifests_java_comment']}
        var instrumented = adapter.instrument(yourAdkAgent);
    """)

    return {
        "python_code": python_code,
        "typescript_code": typescript_code,
        "java_code": java_code,
    }


def _otel(**kw: str) -> dict[str, str]:
    python_code = dedent(f"""\
        import primust
        from primust_otel import PrimustOTelExporter

        p = primust.Pipeline(
            api_key="YOUR_API_KEY",
            workflow_id="your-workflow",
        {kw['policy_line_py']}
        )
        exporter = PrimustOTelExporter(pipeline=p)
        {kw['manifests_comment']}

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(exporter))
    """)

    typescript_code = dedent(f"""\
        import {{ Pipeline }} from "@primust/sdk";
        import {{ PrimustOTelExporter }} from "@primust/otel";
        import {{ NodeTracerProvider }} from "@opentelemetry/sdk-trace-node";
        import {{ BatchSpanProcessor }} from "@opentelemetry/sdk-trace-base";

        const p = new Pipeline({{
          apiKey: "YOUR_API_KEY",
          workflowId: "your-workflow",
        {kw['policy_line_ts']}
        }});
        const exporter = new PrimustOTelExporter({{ pipeline: p }});
        {kw['manifests_ts_comment']}

        const provider = new NodeTracerProvider();
        provider.addSpanProcessor(new BatchSpanProcessor(exporter));
    """)

    java_code = dedent(f"""\
        import com.primust.Pipeline;
        import com.primust.otel.PrimustOTelExporter;
        import io.opentelemetry.sdk.trace.SdkTracerProvider;
        import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;

        Pipeline p = Pipeline.builder()
            .apiKey("YOUR_API_KEY")
            .workflowId("your-workflow")
        {kw['policy_line_java']}
            .build();
        PrimustOTelExporter exporter = new PrimustOTelExporter(p);
        {kw['manifests_java_comment']}

        SdkTracerProvider provider = SdkTracerProvider.builder()
            .addSpanProcessor(BatchSpanProcessor.builder(exporter).build())
            .build();
    """)

    return {
        "python_code": python_code,
        "typescript_code": typescript_code,
        "java_code": java_code,
    }


def _custom(**kw: str) -> dict[str, str]:
    python_code = dedent(f"""\
        import primust

        p = primust.Pipeline(
            api_key="YOUR_API_KEY",
            workflow_id="your-workflow",
        {kw['policy_line_py']}
        )
        {kw['manifests_comment']}

        # Start a run
        run = p.start_run(surface_id="your-surface")

        # Record check executions
        run.record(
            manifest_id="{kw['manifests_list_py'].split(',')[0].strip().strip(chr(34)) if kw['manifests_list_py'] else 'sha256:...'}",
            commitment_hash="sha256:<your-commitment>",
            check_result="pass",
            proof_level="execution",
        )

        # Close and get VPEC
        vpec = run.close()
    """)

    typescript_code = dedent(f"""\
        import {{ Pipeline }} from "@primust/sdk";

        const p = new Pipeline({{
          apiKey: "YOUR_API_KEY",
          workflowId: "your-workflow",
        {kw['policy_line_ts']}
        }});
        {kw['manifests_ts_comment']}

        // Start a run
        const run = await p.startRun({{ surfaceId: "your-surface" }});

        // Record check executions
        await run.record({{
          manifestId: "sha256:...",
          commitmentHash: "sha256:<your-commitment>",
          checkResult: "pass",
          proofLevel: "execution",
        }});

        // Close and get VPEC
        const vpec = await run.close();
    """)

    java_code = dedent(f"""\
        import com.primust.Pipeline;
        import com.primust.Run;

        Pipeline p = Pipeline.builder()
            .apiKey("YOUR_API_KEY")
            .workflowId("your-workflow")
        {kw['policy_line_java']}
            .build();
        {kw['manifests_java_comment']}

        // Start a run
        Run run = p.startRun("your-surface");

        // Record check executions
        run.record("sha256:...", "sha256:<your-commitment>", "pass", "execution");

        // Close and get VPEC
        var vpec = run.close();
    """)

    return {
        "python_code": python_code,
        "typescript_code": typescript_code,
        "java_code": java_code,
    }
