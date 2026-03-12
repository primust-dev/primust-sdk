"""
Primust ZK Worker — Modal serverless proof generation.

Accepts WitnessInput + circuit name, runs nargo prove with UltraHonk,
returns proof bytes. Deployed as a Modal web endpoint.

Endpoints:
  POST /submit       — Submit a proof job (returns job_id immediately)
  GET  /status/{id}  — Check job status
  GET  /proof/{id}   — Retrieve completed proof

Environment secrets (Modal):
  PRIMUST_WEBHOOK_URL   — Callback URL for proof completion
  PRIMUST_WEBHOOK_TOKEN — Bearer token for webhook auth
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import modal

# ── Modal App ──

app = modal.App("primust-zk-worker")

# Image with nargo + bb (Barretenberg) installed
nargo_image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("curl", "tar", "gzip")
    .run_commands(
        # Install nargo
        "curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash",
        'export PATH="$HOME/.nargo/bin:$PATH" && noirup -v 1.0.0-beta.18',
    )
    .pip_install("httpx")
)

# Circuits volume: compiled ACIR bytecode mounted from repo
circuits_volume = modal.Volume.from_name("primust-circuits", create_if_missing=True)

CIRCUITS_MOUNT = "/circuits"
NARGO_BIN = "/root/.nargo/bin/nargo"

# In-memory job store (for prototype; production would use KV/DB)
job_store: dict[str, dict] = {}


# ── Helpers ──


def _write_prover_toml(witness: dict, circuit_dir: Path) -> None:
    """Write witness data to Prover.toml for nargo prove."""
    toml_lines: list[str] = []

    # Public inputs
    toml_lines.append(f'commitment_root = "{witness["commitment_root"]}"')
    toml_lines.append(f'policy_snapshot_hash = "{witness["policy_snapshot_hash"]}"')

    # Private inputs: arrays
    hashes = witness["commitment_hashes"]
    toml_lines.append(f'commitment_hashes = {json.dumps(hashes)}')

    results = witness["check_results"]
    toml_lines.append(f'check_results = {json.dumps(results)}')

    manifest_hashes = witness["manifest_hash_values"]
    toml_lines.append(f'manifest_hash_values = {json.dumps(manifest_hashes)}')

    toml_lines.append(f'record_count = {witness["record_count"]}')

    prover_toml = circuit_dir / "Prover.toml"
    prover_toml.write_text("\n".join(toml_lines) + "\n")


def _notify_webhook(job_id: str, run_id: str, proof_hex: str, vk_hex: str) -> None:
    """Fire-and-forget webhook notification on proof completion."""
    webhook_url = os.environ.get("PRIMUST_WEBHOOK_URL")
    webhook_token = os.environ.get("PRIMUST_WEBHOOK_TOKEN", "")
    if not webhook_url:
        return

    try:
        import httpx

        httpx.post(
            webhook_url,
            json={
                "job_id": job_id,
                "run_id": run_id,
                "proof_hex": proof_hex,
                "vk_hex": vk_hex,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {webhook_token}",
            },
            timeout=10.0,
        )
    except Exception as e:
        print(f"[primust-zk-worker] Webhook notification failed: {e}")


# ── Modal Functions ──


@app.function(
    image=nargo_image,
    volumes={CIRCUITS_MOUNT: circuits_volume},
    cpu=4,
    memory=8192,
    timeout=300,
)
def prove_ultrahonk(
    witness_json: str, circuit_name: str, run_id: str, job_id: str
) -> dict:
    """
    Run nargo prove for a given circuit with the provided witness.

    Args:
        witness_json: JSON-serialized WitnessInput
        circuit_name: One of primust_governance_v1, skip_condition_proof, config_epoch_continuity
        run_id: The process run ID (for webhook callback)
        job_id: The job ID (for status tracking)

    Returns:
        dict with proof_hex, vk_hex, public_inputs, status
    """
    witness = json.loads(witness_json)

    circuit_dir = Path(CIRCUITS_MOUNT) / circuit_name
    if not circuit_dir.exists():
        return {
            "job_id": job_id,
            "status": "failed",
            "error": f"Circuit {circuit_name} not found at {circuit_dir}",
        }

    # Write witness to Prover.toml
    _write_prover_toml(witness, circuit_dir)

    # Run nargo prove
    try:
        result = subprocess.run(
            [NARGO_BIN, "prove"],
            cwd=str(circuit_dir),
            capture_output=True,
            text=True,
            timeout=240,
        )

        if result.returncode != 0:
            return {
                "job_id": job_id,
                "status": "failed",
                "error": f"nargo prove failed: {result.stderr}",
            }

        # Read proof from target/
        proof_path = circuit_dir / "target" / f"{circuit_name}.proof"
        if proof_path.exists():
            proof_hex = proof_path.read_bytes().hex()
        else:
            # Check for alternative proof locations
            proof_files = list((circuit_dir / "target").glob("*.proof"))
            if proof_files:
                proof_hex = proof_files[0].read_bytes().hex()
            else:
                return {
                    "job_id": job_id,
                    "status": "failed",
                    "error": "Proof file not found after nargo prove",
                }

        # Read verification key
        vk_path = circuit_dir / "target" / "vk"
        vk_hex = vk_path.read_bytes().hex() if vk_path.exists() else ""

        # Notify webhook
        _notify_webhook(job_id, run_id, proof_hex, vk_hex)

        return {
            "job_id": job_id,
            "status": "complete",
            "proof_hex": proof_hex,
            "vk_hex": vk_hex,
            "circuit_name": circuit_name,
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    except subprocess.TimeoutExpired:
        return {
            "job_id": job_id,
            "status": "timed_out",
            "error": "nargo prove timed out after 240s",
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
        }


# ── Web Endpoints ──


@app.function(image=nargo_image)
@modal.web_endpoint(method="POST")
def submit(body: dict) -> dict:
    """Submit a proof job. Returns job_id immediately."""
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    witness_json = json.dumps(body.get("witness", {}))
    circuit_name = body.get("circuit", "primust_governance_v1")
    run_id = body.get("run_id", "")

    # Submit async proving job (non-blocking)
    prove_ultrahonk.spawn(
        witness_json=witness_json,
        circuit_name=circuit_name,
        run_id=run_id,
        job_id=job_id,
    )

    return {
        "job_id": job_id,
        "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "pending",
    }


@app.function(image=nargo_image)
@modal.web_endpoint(method="GET")
def status(job_id: str) -> dict:
    """Check job status."""
    job = job_store.get(job_id)
    if not job:
        return {
            "job_id": job_id,
            "submitted_at": "",
            "status": "pending",
        }
    return job


@app.function(image=nargo_image)
@modal.web_endpoint(method="GET")
def proof(job_id: str) -> dict:
    """Retrieve completed proof."""
    job = job_store.get(job_id)
    if not job or job.get("status") != "complete":
        return {"error": "Proof not available", "status": 404}
    return {
        "proof_hex": job.get("proof_hex", ""),
        "vk_hex": job.get("vk_hex", ""),
        "circuit_name": job.get("circuit_name", ""),
        "prover_system": "ultrahonk",
        "proof_level": "mathematical",
        "verified": False,
    }
