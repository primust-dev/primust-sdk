package com.primust.sdk;

/**
 * Result of a governance check execution.
 */
public enum CheckResult {
    PASS("pass"),
    FAIL("fail"),
    ERROR("error"),
    SKIPPED("skipped"),
    DEGRADED("degraded"),
    OVERRIDE("override"),
    NOT_APPLICABLE("not_applicable");

    private final String value;

    CheckResult(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
