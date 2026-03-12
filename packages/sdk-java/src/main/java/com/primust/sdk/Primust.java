package com.primust.sdk;

/**
 * Entry point for the Primust Java SDK.
 *
 * <pre>
 * Pipeline p = Primust.builder()
 *     .apiKey("pk_live_...")
 *     .workflowId("fraud-scoring")
 *     .build();
 * </pre>
 */
public final class Primust {

    private static final String DEFAULT_BASE_URL = "https://api.primust.com";

    private Primust() {}

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String apiKey;
        private String workflowId = "default";
        private String baseUrl = DEFAULT_BASE_URL;
        private String surfaceId;

        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder workflowId(String workflowId) {
            this.workflowId = workflowId;
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder surfaceId(String surfaceId) {
            this.surfaceId = surfaceId;
            return this;
        }

        public Pipeline build() {
            String key = apiKey;
            if (key == null || key.isBlank()) {
                key = System.getenv("PRIMUST_API_KEY");
            }
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException(
                        "apiKey is required. Pass it via builder or set PRIMUST_API_KEY env var.");
            }
            return new Pipeline(key, workflowId, baseUrl, surfaceId);
        }
    }
}
