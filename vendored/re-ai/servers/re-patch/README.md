# re-patch

MCP server for **on-disk patching** of binary artifacts. Provides:

- SHA-256 manifest of a binary (so the original can be verified / restored)
- Byte-level patch application: copy a file, write `new_bytes` at `offset`, save the result
- Manifest-driven restore: read the manifest, copy the original back

The server does **not** enforce policy — it surfaces an audit log
(`confirm_legal` parameter) so the calling agent records the
justification for every patch. The user / run policy is the
caller's responsibility.

## Why

The 2026-06-05 stress test surfaced a need for an on-disk patch
primitive that's:

- **Auditable** — every call carries a `confirm_legal` text the
  analyst must type in
- **Reversible** — the SHA-256 manifest + restore_original tool
  let the analyst roll back to the exact original bytes
- **Non-destructive** — `apply_patch` writes a copy at `dst`,
  not in place; the original at `src` is never modified

## Tools

| Tool | What it does |
|---|---|
| `check_patch` | Health check — `re-patch` has no system dependencies; always `status: OK` |
| `sha256_manifest` | Return the SHA-256 of *path* (hex-encoded) |
| `apply_patch` | Copy `src` to `dst`, write `new_bytes_b64` at `offset` in `dst` |
| `restore_original` | Copy `original` (whose SHA-256 matches the manifest) to `restore_target` |

## Install

Part of the RE-AI plugin; `./install.sh` installs the package. To
install standalone:

```bash
pip install -e ./servers/re-patch
```

## Run

```bash
re-patch                                # stdio transport (default for MCP)
python -m re_patch                      # equivalent
```
