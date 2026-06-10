# re-bypass-cinematic-wall

**v0.4.2.0 documented** (per `docs/PLAYBOOKS/cross-target-entitlement-bypass.md` §1). Closes the FM26 / HKIA / P3R / CD / TWW3 cinematic-wall failure mode.

## When to use this skill

Invoke when:
- A target reaches the splash cinematic and stays there
- The game's log ends abruptly after "TypedValue pool creation" (Unity 6) or the equivalent post-init line
- Multiple XTest key events sent to the launcher's window class produce no state change

## The failure mode

5 of 7 targets from the 2026-06-08 live-fire engagement hit the cinematic wall: FM26, HKIA, P3R, CD, TWW3. The Unity splash cinematic reads input via XInput (controller) and IMGUI (keyboard handler). Under headless Wine + DXVK, the cinematic renders the splash but never sees the "press any key" event because:
- X11 compositor switch issues (vulkan:x11 split)
- Wine's `xkey.py` resolves the wrong window ID
- Wine's `dlls/winex11.drv/keyboard.c` doesn't inject synthetic key events

## Workaround stack (in order of preference)

1. **Single-output display** — use a real Windows host, or a Linux setup with Vulkan + X11 on the same display. The `vulkan:x11` split on AtomMan is the most common cause.
2. **`xkey.py` with re-query** — `re-launch-and-observe.find_wine_window` resolves the Wine child window ID (which shifts between attempts on AtomMan). Re-query immediately before each XTest key send. See `See the RE-BREAKER output directory.`.
3. **Wine-side injection** — patch the launcher's init sequence to call `keybd_event(VK_SPACE, 0, 0, 0)` after a 3-second delay. This is `re-cinematic-skip.patch_splash_dismiss(launcher, target_purpose=any-key, inject_module=wine-key-event)`.
4. **Build-time patch** — find the "press any key" hook in the GameAssembly.dll, NOP it, synthesize the keystroke from inside the launcher. `re-cinematic-skip.patch_splash_dismiss(launcher, target_purpose=any-key, inject_module=nops)`.

## Tools invoked

- `mcp__re-cinematic-skip.list_splash_signatures` — returns the known splash catalog (FM26, Crimson Desert, Unity fallback)
- `mcp__re-cinematic-skip.patch_splash_dismiss(launcher_exe, target_purpose, inject_module)` — builds the patch
- `mcp__re-launch-and-observe.find_wine_window(winclass, winname_contains)` — re-query the Wine window ID
- `mcp__re-launch-and-observe.launch_with_observability(target, ...)` — full observability (ffmpeg capture + key injection)

## Workflow

1. **Detect the wall.** Check the target's log for the abrupt "TypedValue pool creation" line, OR the absence of any HTTP/HTTPS traffic after a 10s wait.
2. **Try the single-display workaround.** If the host has a single display (Vulkan + X11 on :0), try `xdotool key space` after the cinematic appears. If state changes, you're past the wall.
3. **Try the re-query workaround.** Use `re-launch-and-observe.find_wine_window(winclass="UnityWndClass")` repeatedly, send XTest key events via `xdotool key` or `xte`.
4. **Try the wine-side injection.** Build a small DLL that calls `keybd_event(VK_SPACE, 0, 0, 0)` after 3s. Drop it via AppInit_DLLs or LoadLibraryA-from-main.
5. **Try the build-time patch.** Use `re-patch-apply.apply_patch` to NOP the "press any key" function in GameAssembly.dll.

## What this skill does NOT do

- Does not solve the Wine `cryptasn:CryptDecodeObjectEx` page fault (different problem, see `re-bypass-wine-cryptasn-fault`)
- Does not solve the Wine `EXCEPTION_INVALID_FRAME` SEH (different problem, see `re-bypass-wine-seh-frame`)
- Does not bypass the entitlement layer — the cinematic wall is encountered AFTER entitlement, not before
