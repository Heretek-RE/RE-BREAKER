"""On-disk binary patch primitives.

The functions in this module are the heavy lifting the
``re-patch`` MCP server wraps. They are pure stdlib Python —
no third-party deps — so the server can run in any venv that
has ``mcp[cli]`` and ``pydantic``.

The audit pattern is consistent: every public function takes
a ``confirm_legal`` string. The server passes the analyst's
typed justification through unchanged; the helper records it
in the returned dict so the agent can write it into a report.
The helper does **not** enforce policy — it surfaces the
audit string. The policy decision lives in the calling skill /
agent.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
from pathlib import Path
from typing import Any


def sha256_manifest(path: str) -> dict[str, Any]:
    """Compute the SHA-256 of *path* (hex-encoded).

    Args:
        path: file to hash

    Returns::

        {
          "path": "...",
          "size": N,
          "sha256": "<64 hex chars>",
        }
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"not a file: {path}")
    h = hashlib.sha256()
    size = 0
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return {
        "path": str(p),
        "size": size,
        "sha256": h.hexdigest(),
    }


def apply_patch(
    src: str,
    dst: str,
    offset: int,
    new_bytes_b64: str,
    confirm_legal: str = "",
) -> dict[str, Any]:
    """Copy *src* to *dst*, then write *new_bytes_b64* at *offset* in *dst*.

    Args:
        src: source file (the original binary; never modified)
        dst: destination file (will be created or overwritten)
        offset: byte offset into *dst* at which to write (0-based)
        new_bytes_b64: base64-encoded bytes to splice in
        confirm_legal: free-text justification (recorded in
            the audit log; the server does not enforce policy)

    Returns::

        {
          "src": "...",
          "dst": "...",
          "src_sha256": "<original sha256>",
          "dst_sha256": "<patched sha256>",
          "offset": N,
          "patched_bytes": M,
          "confirm_legal": "...",
        }

    Raises:
        FileNotFoundError: if *src* does not exist
        ValueError: if *offset* is negative or *new_bytes_b64* is empty
        OSError: on write failure
    """
    if offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset}")
    new_bytes = base64.b64decode(new_bytes_b64, validate=True)
    if not new_bytes:
        raise ValueError("new_bytes_b64 is empty (decoded 0 bytes)")

    src_path = Path(src)
    if not src_path.is_file():
        raise FileNotFoundError(f"source not found: {src}")
    dst_path = Path(dst)
    # Pre-flight: make sure dst's parent exists
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Compute original SHA-256 (before any write)
    pre_manifest = sha256_manifest(str(src_path))

    # 2. Copy src -> dst (in-place if src == dst; shutil.copy2 refuses,
    #    so fall through to the same-file path explicitly)
    if src_path.resolve() != dst_path.resolve():
        shutil.copy2(src_path, dst_path)

    # 3. Splice the patch bytes
    with dst_path.open("r+b") as f:
        f.seek(offset)
        f.write(new_bytes)
        f.flush()

    # 4. Compute patched SHA-256
    post_manifest = sha256_manifest(str(dst_path))

    return {
        "src": str(src_path),
        "dst": str(dst_path),
        "src_sha256": pre_manifest["sha256"],
        "dst_sha256": post_manifest["sha256"],
        "src_size": pre_manifest["size"],
        "dst_size": post_manifest["size"],
        "offset": offset,
        "patched_bytes": len(new_bytes),
        "confirm_legal": confirm_legal or "",
    }


def restore_original(
    original: str,
    restore_target: str,
    expected_sha256: str = "",
    confirm_legal: str = "",
) -> dict[str, Any]:
    """Copy *original* back to *restore_target* (with optional SHA-256 check).

    Use this after patching to roll back to the original bytes.
    The function:

      1. Computes the SHA-256 of *original*.
      2. If *expected_sha256* is non-empty, verifies the
         computed hash matches.
      3. Copies *original* to *restore_target* (overwriting).

    Args:
        original: the file whose bytes are the canonical "original"
            (typically the source the patch was applied from)
        restore_target: the file to write the original bytes to
            (typically the patched file)
        expected_sha256: optional hex-encoded SHA-256 to verify
            *original* against before the copy
        confirm_legal: free-text justification (recorded in
            the audit log)

    Returns::

        {
          "original": "...",
          "restore_target": "...",
          "original_sha256": "<hash>",
          "expected_sha256": "<hash>" or null,
          "verified": bool,
          "confirm_legal": "...",
        }

    Raises:
        FileNotFoundError: if *original* does not exist
        ValueError: if *expected_sha256* is non-empty and does not match
    """
    src_path = Path(original)
    if not src_path.is_file():
        raise FileNotFoundError(f"original not found: {original}")
    dst_path = Path(restore_target)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    pre_manifest = sha256_manifest(str(src_path))
    if expected_sha256:
        if pre_manifest["sha256"] != expected_sha256:
            raise ValueError(
                f"SHA-256 mismatch: original={pre_manifest['sha256']!r} "
                f"expected={expected_sha256!r}"
            )

    if src_path.resolve() != dst_path.resolve():
        shutil.copy2(src_path, dst_path)

    return {
        "original": str(src_path),
        "restore_target": str(dst_path),
        "original_sha256": pre_manifest["sha256"],
        "expected_sha256": expected_sha256 or None,
        "verified": bool(expected_sha256),
        "confirm_legal": confirm_legal or "",
    }
