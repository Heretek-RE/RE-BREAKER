# RE-VM-UI-AUTOMATE

Cross-platform UI automation for the Windows VM (and the host desktop,
if you ever need it). Backed by the vendored `touchpoint-mcp` upstream
(`Touchpoint-Labs/touchpoint` @ main, MIT, 27 tools).

## When to use

The Windows VM is reachable via SSH (re-vm-ssh) and QEMU/libvirt
(re-vm-control), but neither gives you UI-level control. Use
`re-ui-automate` when you need to:

- Click through an installer dialog.
- Drive a setup wizard that has no CLI/automation hook.
- Inspect the screen of a Wine/Windows target that's already running.
- Take a screenshot for verification or a bug report.

## Typical workflow (the "click through an installer" case)

1. **Take stock.** `apps()` — what's running? `windows()` — what windows
   are open? `screenshot()` — see the current screen.
2. **Find the element.** `find(query="Next", app="Installer")` returns
   a short alias like `uia3`. Never invent coordinates.
3. **Act.** `click(element_id="uia3")` or `type_text(text="license-key")`
   for text input.
4. **Verify.** `screenshot()` again. Check the "action flags" returned
   by the action (e.g. "(new window: 'License Agreement')" — the
   installer just popped a new dialog, go back to step 2).
5. **Wait if needed.** `wait_for(element="Ready to install")` before
   clicking the final button.

## Tool surface (the 27 you can call)

`apps`, `diagnostics`, `windows`, `find`, `get_element`, `snapshot`,
`diff_snapshot`, `screenshot`, `click`, `type_text`, `set_value`,
`press_key`, `press_key_combination`, `press_key_hold`, `press_key_release`,
`activate_window`, `close_window`, `minimize`, `maximize`, `restore`,
`fullscreen_window`, `resize_window`, `move_window`, `focus`, `drag`,
`scroll`, `mouse_move`, `wait_for`, `wait_for_app`, `wait_for_window`,
`read_text`, `is_visible`, `execute_action`, `get_text`, `state`,
`get_window`, `menus`, `capture_state`, `restore_state`, `state_diff`,
`action`, `key_down`, `key_up`, `key_press`, `drag_mouse`, `move_mouse`,
`mouse_position`, `mouse_down`, `mouse_up`, `mouse_click`,
`mouse_double_click`, `mouse_right_click`, `mouse_scroll`, `mouse_drag`,
`mouse_move`, `mouse_hold`, `mouse_release`, `quit`, `run_command`,
`shell`, `open_url`, `http_request`, `browser_action`.

(The exact list may shift slightly between touchpoint versions.)

## When NOT to use

- For text-mode analysis: use the `re-vm-ssh` MCP server. It's faster
  and doesn't need a UI.
- For binary analysis: use the `re-catalog-match` / `re-il2cpp-triage`
  / `re-vm-debug` / `re-x64dbg-remote` MCP servers. UI automation
  is for the human-facing surface, not the binary.
- For vision-based screen reading: prefer `read_text(element_id)` over
  OCR'ing a screenshot — it's faster, cheaper, and verbatim.

## Vendoring details

- Source: `vendored/touchpoint/` (git clone, MIT).
- venv: `vendored/touchpoint/.venv/` with the touchpoint package
  installed editable.
- Binary: `${CLAUDE_PLUGIN_ROOT}/vendored/touchpoint/.venv/bin/touchpoint-mcp`.
- Wired in `.mcp.json` as `re-ui-automate` (stdio transport, the
  upstream default).

## Cross-restart persistence

None — the touchpoint session is in-process and dies with the MCP
server. The discoverable apps / windows / element aliases are re-built
on next call. For long-running UI workflows, prefer re-launching the
target via `re-vm-launch` and checking progress via screenshots.

## When to escalate to a custom tool

If you find yourself calling the same 5+ touchpoint tools in the same
sequence repeatedly, ask for a custom MCP server (e.g. `re-installer-driver`)
that wraps the sequence as a single tool. Until then, use the upstream
primitives directly.
