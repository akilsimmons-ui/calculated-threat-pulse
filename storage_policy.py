"""Hard limits for low-maintenance Threat Pulse publishing.

Preserve CISA's complete current catalog; limit how much is mirrored as static
pages. Never delete a previously published CVE page just to make room.
"""
from pathlib import Path

RECENT_RECORD_LIMIT = 200
CVE_PAGE_LIMIT = 500
MAX_SOURCE_BYTES = 8_000_000
MAX_PUBLIC_BYTES = 25 * 1024 * 1024


def check_source_budget(data: Path):
    """Raise before a build publishes an unexpectedly large or invalid cache."""
    if data.exists() and data.stat().st_size > MAX_SOURCE_BYTES:
        raise RuntimeError(
            f"CISA catalog cache is {data.stat().st_size:,} bytes, "
            f"over the {MAX_SOURCE_BYTES:,}-byte safety limit. "
            "Review data growth before increasing the cap."
        )


def check_public_budget(public: Path):
    """Reject oversized deploys rather than deleting or losing historical records."""
    if not public.exists():
        return 0
    total = sum(path.stat().st_size for path in public.rglob("*") if path.is_file())
    if total > MAX_PUBLIC_BYTES:
        raise RuntimeError(
            f"Published site size {total:,} bytes exceeds "
            f"{MAX_PUBLIC_BYTES:,}-byte limit. "
            "Prior deployment remains available; review before adjusting."
        )
    return total
