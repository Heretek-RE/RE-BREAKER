"""MCP server entry point for re-patch.

Exposes on-disk binary patching primitives to Claude Code via
the Model Context Protocol stdio transport.

The server is **pure Python** (no system deps). It does
**not** enforce policy — the ``confirm_legal`` parameter is
the audit-trail hook: every call must carry a free-text
justification that the calling agent writes into the report.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_patch import patcher

logger = logging.getLogger("re_patch")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-patch")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_patch() -> dict:
    """Return server status + version. Always ``status: OK`` —
    ``re-patch`` has no external system dependencies (pure
    Python stdlib + ``mcp`` / ``pydantic``).
    """
    return {
        "server": "re-patch",
        "version": "0.1.0",
        "status": "OK",
        "deps": {"mcp": "std", "pydantic": "std"},
        "audit_required": True,
        "notes": (
            "Every call must carry a free-text `confirm_legal` "
            "justification. The server does not enforce policy; "
            "the justification is the audit trail."
        ),
    }


# ── Manifest ────────────────────────────────────────────────────────────


@mcp.tool()
def sha256_manifest(path: str) -> dict:
    """Compute the SHA-256 manifest of *path*.

    Args:
        path: file to hash

    Returns::

        {
          "path": "...",
          "size": N,
          "sha256": "<64 hex chars>",
        }

    Use this to record the canonical SHA-256 of the original
    binary before any patch is applied. The hash is the
    rollback key: ``restore_original(original, target,
    expected_sha256=...)`` will refuse to proceed if the
    original's hash has drifted.
    """
    return patcher.sha256_manifest(path)


# ── Patch application ───────────────────────────────────────────────────


@mcp.tool()
def apply_patch(
    src: str,
    dst: str,
    offset: int,
    new_bytes_b64: str,
    confirm_legal: str = "",
) -> dict:
    """Copy *src* to *dst*, then splice *new_bytes_b64* at *offset*.

    This is the **on-disk patch primitive**. The original
    bytes at *src* are never modified; the patch is written
    to a *copy* at *dst*. The function returns both the
    pre-patch and post-patch SHA-256 so the analyst can
    record the patch's net effect in the report.

    Args:
        src: source file (the original; never modified)
        dst: destination file (created or overwritten with
            the patched copy)
        offset: byte offset into *dst* at which to write
            (0-based)
        new_bytes_b64: base64-encoded bytes to splice in
        confirm_legal: free-text justification (the audit
            trail; the server does not enforce policy)

    Returns::

        {
          "src": "...",
          "dst": "...",
          "src_sha256": "<original>",
          "dst_sha256": "<patched>",
          "src_size": N,
          "dst_size": N,
          "offset": N,
          "patched_bytes": M,
          "confirm_legal": "...",
        }

    **Override-scope contract**: this tool is gated behind
    the run's policy override (see ``override-scope.md`` of
    the active run). The override authorizes on-disk patches
    only inside ``Output/<run-id>/patches/``; the
    ``confirm_legal`` text must reference the override file
    and the rationale.
    """
    return patcher.apply_patch(
        src=src,
        dst=dst,
        offset=offset,
        new_bytes_b64=new_bytes_b64,
        confirm_legal=confirm_legal,
    )


# ── Restore ─────────────────────────────────────────────────────────────


@mcp.tool()
def restore_original(
    original: str,
    restore_target: str,
    expected_sha256: str = "",
    confirm_legal: str = "",
) -> dict:
    """Copy *original* back to *restore_target*, optionally
    verifying the original's SHA-256 against *expected_sha256*
    first.

    This is the **rollback primitive**. The function:

      1. Computes the SHA-256 of *original*.
      2. If *expected_sha256* is non-empty, verifies the
         computed hash matches (refuses to proceed otherwise).
      3. Copies *original* to *restore_target* (overwriting).

    Args:
        original: file whose bytes are the canonical "original"
            (typically the source the patch was applied from)
        restore_target: file to write the original bytes to
            (typically the patched copy)
        expected_sha256: optional hex-encoded SHA-256 to verify
            *original* against
        confirm_legal: free-text justification (audit trail)

    Returns::

        {
          "original": "...",
          "restore_target": "...",
          "original_sha256": "<hash>",
          "expected_sha256": "<hash>" or null,
          "verified": bool,
          "confirm_legal": "...",
        }
    """
    return patcher.restore_original(
        original=original,
        restore_target=restore_target,
        expected_sha256=expected_sha256,
        confirm_legal=confirm_legal,
    )


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (the standard Claude Code transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
