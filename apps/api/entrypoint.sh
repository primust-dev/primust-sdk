#!/bin/sh
# Write GCP credentials JSON to a file if provided as inline env var.
# google-cloud-* SDKs expect GOOGLE_APPLICATION_CREDENTIALS to be a file path.
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS_JSON" ] && [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  printf '%s' "$GOOGLE_APPLICATION_CREDENTIALS_JSON" > /tmp/gcp-credentials.json
  export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-credentials.json
fi

exec "$@"
