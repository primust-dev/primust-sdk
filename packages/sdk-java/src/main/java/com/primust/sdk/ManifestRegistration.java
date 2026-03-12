package com.primust.sdk;

/**
 * Returned by Pipeline.registerCheck(). Content-addressed — idempotent.
 */
public final class ManifestRegistration {

    private final String manifestId;
    private final String name;
    private final String registeredAt;

    public ManifestRegistration(String manifestId, String name, String registeredAt) {
        this.manifestId = manifestId;
        this.name = name;
        this.registeredAt = registeredAt;
    }

    public String manifestId() { return manifestId; }
    public String name() { return name; }
    public String registeredAt() { return registeredAt; }
}
