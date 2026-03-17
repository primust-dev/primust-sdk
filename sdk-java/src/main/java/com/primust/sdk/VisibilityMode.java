package com.primust.sdk;

/**
 * Data visibility level for governance records.
 */
public enum VisibilityMode {
    TRANSPARENT("transparent"),
    SELECTIVE("selective"),
    OPAQUE("opaque");

    private final String value;

    VisibilityMode(String value) {
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
