# Vendored upstreams

These directories contain copies of upstream repositories that RE-BREAKER
either (a) ships as MCP servers or (b) imports as Python libraries.

## `persistproc/` — irskep/persistproc @ v0.2.1 (MIT)

Vendored at commit hash from the `v0.2.1` tag, with a vendored venv
at `persistproc/.venv/` (built with `uv venv` and `uv pip install
fastmcp==2.9.2 mcp==1.9.4 pydantic==2.11.7 -e .`).

**Why vendored?** The RE-BREAKER plugin's MCP server `re-persistproc`
launches this as a sidecar via `.mcp.json` with the exact path
`${CLAUDE_PLUGIN_ROOT}/vendored/persistproc/.venv/bin/persistproc`.

**Version pins matter.** fastmcp 2.9.2 + mcp 1.9.4 + pydantic 2.11.7
are the only known-good combination. Newer fastmcp requires APIs not
in mcp 1.9.x; newer pydantic breaks fastmcp 2.9.2's `Settings`
class. **Do not bump these versions in the vendored venv without
re-running the spike test** at
`tests/integration/test_persistproc_spike.py`.

**Used by**: `re-launch-and-observe` (Phase 2.1 of v0.6.0) — wraps
ffmpeg x11grab captures with cross-restart persistence.

**Docs**: https://steveasleep.com/persistproc/

## `touchpoint/` — Touchpoint-Labs/touchpoint @ main (MIT)

Vendored at the latest `main` commit. **Not yet wired** in v0.6.0 —
planned for Phase 3 (`re-ui-automate` server).

**Why vendored?** When wired, `re-ui-automate` will wrap the
`touchpoint-mcp` binary as a registered MCP server. Vendoring gives
us a fixed source revision instead of relying on PyPI.

**Docs**: see the touchpoint repo README.

## `ssh-mcp/` — blakerouse/ssh-mcp @ main (MIT)

Vendored at the latest `main` commit. **Not yet built** — the Go
binary needs `go build`, planned for Phase 4.

**Why vendored?** When built, the Go binary will be registered in
`.mcp.json` as a sidecar with one group `re-breaker-vms` containing
the existing `john@RE_BREAKER_SSH_HOST` ed25519 target. Keeps `re-vm-ssh`
as the internal paramiko transport for the 6 import-time consumers.

**Docs**: see the ssh-mcp repo README.

## Vendoring process

Each upstream is `git clone --depth 1` then a tag/commit pin. The
.git is stripped; the local `.git` is recreated with a single commit
containing the pinned source. To bump:

```sh
cd vendored/<name>
git fetch origin
git checkout <new-tag-or-commit>
cd ..
# For persistproc: rebuild the venv
rm -rf persistproc/.venv
cd persistproc
uv venv
uv pip install "fastmcp==2.9.2" "mcp==1.9.4" "pydantic==2.11.7" -e .
cd ../..
# Re-run the spike test
pytest tests/integration/test_persistproc_spike.py -v
```

## Why we vendor at all

The RE-BREAKER plugin is self-contained: a single `git clone` of the
plugin should give a working toolchain with no transitive PyPI/GitHub
fetches at MCP-server-launch time. The `.mcp.json` references
`${CLAUDE_PLUGIN_ROOT}/vendored/...` so the paths stay valid across
plugin-root moves.
