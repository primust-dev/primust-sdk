"""Public key cache — filesystem cache at ~/.primust/keys/{kid}.pem

Keys are immutable by kid. Once cached, never re-fetched.
On cache miss with network failure: raises Exception("key_unavailable").
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional
from urllib.request import urlopen
from urllib.error import URLError

CACHE_DIR = Path.home() / ".primust" / "keys"


def _safe_kid(kid: str) -> str:
    """Sanitize kid to prevent path traversal."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", kid)


def get_key(
    kid: str,
    public_key_url: str,
    trust_root: Optional[str] = None,
) -> str:
    """Resolve a public key PEM for the given kid.

    Resolution order:
    1. If trust_root is provided, read from that path (bypass cache/fetch)
    2. Check filesystem cache (~/.primust/keys/{kid}.pem)
    3. Fetch from public_key_url, write to cache
    4. On network failure with cache miss: raise "key_unavailable"
    """
    # Option 1: custom trust root
    if trust_root is not None:
        try:
            return Path(trust_root).read_text().strip()
        except OSError:
            raise Exception(f"key_unavailable: cannot read trust root at {trust_root}")

    # Option 2: check cache
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cached = CACHE_DIR / f"{_safe_kid(kid)}.pem"
    if cached.exists():
        return cached.read_text().strip()

    # Option 3: fetch from URL
    try:
        with urlopen(public_key_url) as resp:
            pem = resp.read().decode("utf-8").strip()
        cached.write_text(pem)
        return pem
    except (URLError, OSError):
        raise Exception(
            f"key_unavailable: cannot fetch public key for kid {kid} from {public_key_url}"
        )
