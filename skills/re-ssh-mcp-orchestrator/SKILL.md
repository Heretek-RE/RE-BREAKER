# RE-SSH-MCP-ORCHESTRATOR

User-facing SSH orchestrator for multi-host workflows. Backed by the
vendored `blakerouse/ssh-mcp` Go binary (MIT, 10 tools). Registered in
`.mcp.json` as the `ssh-mcp` server.

## When to use

- **Fan-out to multiple hosts at once** — `perform_command` accepts a
  group name; all hosts in the group execute in parallel.
- **Long-running commands** — commands >30s auto-background; poll
  `get_command_status` for the result. No need to wrap yourself.
- **Persistent host storage** — add a host once, refer to it by name
  forever. Storage is BadgerDB at
  `${CLAUDE_PLUGIN_ROOT}/data/ssh-mcp/storage.db`.

## When NOT to use

- **The Windows VM in RE-BREAKER** — `re-vm-ssh` is the right tool
  for the libvirt KVM guest at `john@RE_BREAKER_SSH_HOST`. ssh-mcp can
  manage it too, but `re-vm-ssh` is the paramiko-based transport
  the other 6 import-time consumers (`re-vm-launch`, `re-vm-debug`,
  `re-vm-memory`, `re-ida-remote`, `re-ghidra-remote`,
  `re-x64dbg-remote`) depend on. Don't replace the import-time
  surface; use ssh-mcp for ad-hoc commands only.
- **For binary analysis** — use `re-vm-ssh.ssh_exec` from
  `re-vm-launch`, `re-vm-memory`, etc. Those are server-to-VM
  pipelines with structured output.
- **For UI automation** — `re-ui-automate` (touchpoint) drives the
  Windows VM's UI; ssh-mcp is text-only.

## Setup (one-time, per host)

1. Ensure the SSH key is in `~/.ssh/id_ed25519` (or wherever the
   `SSH_KEY` env var points).
2. Add the host: `add_host(name="win11", address="RE_BREAKER_SSH_HOST",
   user="john", port=22, identity_file="RE_BREAKER_SSH_KEY")`.
3. (Optional) Add to a group for fan-out:
   `add_host(..., group="re-breaker-vms")` or use the
   `update_os_info` flow to cache the host's OS for command-routing
   decisions.

## Common workflows

### Run a command on one host

```
perform_command(host="win11", command="ipconfig /all")
```

### Run a command on a group (fan-out)

```
perform_command(group="re-breaker-vms", command="uptime")
```

Returns per-host results in parallel.

### Long-running command (background)

```
result = perform_command(host="win11", command="npm run build")
# result contains a command_id if the command takes >30s
status = get_command_status(command_id=result.command_id)
# poll until status.state == "completed" or "failed"
```

### List all hosts

```
get_hosts()
# returns [{name, address, user, port, group, ...}, ...]
```

## Tool surface (the 10)

`add_host`, `get_hosts`, `get_groups`, `remove_host`,
`perform_command`, `list_commands`, `get_command_status`,
`cancel_command`, `get_os_info`, `update_os_info`.

## Vendoring details

- Source: `vendored/ssh-mcp/` (git clone, MIT).
- Binary: `${CLAUDE_PLUGIN_ROOT}/vendored/ssh-mcp/ssh-mcp`
  (Go, statically linked, 20MB).
- Storage: `${CLAUDE_PLUGIN_ROOT}/data/ssh-mcp/storage.db`
  (BadgerDB, persistent across MCP restarts).
- Wired in `.mcp.json` as `ssh-mcp` (stdio transport, the upstream
  default).

## Cross-restart persistence

Hosts + groups persist in the BadgerDB file. The upstream has no
in-process state to lose; restart the MCP server and the host list
is right there. Background commands in flight are also persisted
(per the upstream's design).
