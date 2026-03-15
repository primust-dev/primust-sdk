"""Tests for the Harness class."""

from primust_checks import CheckResult, Harness


def test_observability_only_mode():
    """Harness without api_key runs in observability-only mode."""
    harness = Harness(policy="ai_agent_general_v1")
    result = harness.run(input="Hello world")
    assert result.observability_only is True
    assert result.vpec is None


def test_byoc_decorator_bare():
    """@harness.check without arguments registers a check."""
    harness = Harness(policy="ai_agent_general_v1")

    @harness.check
    def my_check(*, input, output=None, context=None, config=None):
        return CheckResult(passed=True, check_id="my_check", evidence="ok")

    assert len(harness.checks) == 1
    assert harness.checks[0].name == "my_check"


def test_byoc_decorator_with_args():
    """@harness.check(name=...) registers with custom name."""
    harness = Harness(policy="ai_agent_general_v1")

    @harness.check(name="custom_name", proof_ceiling="execution")
    def my_check(*, input, output=None, context=None, config=None):
        return CheckResult(passed=True, evidence="ok")

    assert harness.checks[0].name == "custom_name"
    assert harness.checks[0].proof_ceiling == "execution"


def test_byoc_check_runs():
    """Registered BYOC check executes and its result appears in HarnessResult."""
    harness = Harness(policy="ai_agent_general_v1")

    @harness.check(name="always_pass")
    def always_pass(*, input, output=None, context=None, config=None):
        return CheckResult(passed=True, check_id="always_pass", evidence="clean")

    result = harness.run(input="test")
    assert any(r.check_id == "always_pass" and r.passed for r in result.results)


def test_failing_check():
    """A failing check causes HarnessResult.passed to be False."""
    harness = Harness(policy="ai_agent_general_v1")

    @harness.check(name="always_fail")
    def always_fail(*, input, output=None, context=None, config=None):
        return CheckResult(passed=False, check_id="always_fail", evidence="bad")

    result = harness.run(input="test")
    assert result.passed is False


def test_bundle_loading():
    """Harness loads the correct bundle by policy name."""
    harness = Harness(policy="coding_agent_v1")
    assert harness.bundle["bundle_id"] == "coding_agent_v1"
    check_ids = [c["check_id"] for c in harness.bundle["checks"]]
    assert "command_patterns" in check_ids
    assert "secrets_scanner" in check_ids


def test_gaps_reported_for_missing_required_checks():
    """Required bundle checks without registered implementations show as gaps."""
    harness = Harness(policy="ai_agent_general_v1")
    # No checks registered -- all required checks are gaps
    result = harness.run(input="test")
    assert "secrets_scanner" in result.gaps
    assert "pii_regex" in result.gaps
    assert "enforcement_rate" in result.gaps
    assert result.passed is False


def test_unknown_policy_returns_empty_bundle():
    """Unknown policy name yields an empty bundle with no errors."""
    harness = Harness(policy="nonexistent_policy_v99")
    assert harness.bundle["bundle_id"] == "nonexistent_policy_v99"
    assert harness.bundle["checks"] == []


def test_check_exception_handled():
    """If a check raises, it produces a failed CheckResult."""
    harness = Harness(policy="ai_agent_general_v1")

    @harness.check(name="bad_check")
    def bad_check(*, input, output=None, context=None, config=None):
        raise ValueError("boom")

    result = harness.run(input="test")
    assert any(r.check_id == "bad_check" and not r.passed for r in result.results)
