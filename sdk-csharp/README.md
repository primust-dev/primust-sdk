# Primust SDK for .NET

Prove governance ran. Disclose nothing.

Pipeline/Run/Record API for issuing Verifiable Process Execution Credentials (VPECs).

## Installation

```
dotnet add package Primust.SDK
```

## Quick Start

```csharp
using Primust;

var pipeline = new Pipeline("pk_live_...", "claims-adjudication-v1");
var run = pipeline.Open();

await run.RecordAsync(new RecordInput
{
    Check = "coverage_verification",
    ManifestId = "sha256:abc...",
    Input = Encoding.UTF8.GetBytes(canonicalJson),
    CheckResult = CheckResult.Pass,
    Visibility = "opaque",
});

var vpec = await run.CloseAsync();
```

## Privacy Guarantee

Raw input bytes are committed locally via SHA-256 before any transmission.
Only commitment hashes and bounded metadata transit to `api.primust.com`.
The raw input **never leaves your environment**.

## Requirements

- .NET 8.0+
