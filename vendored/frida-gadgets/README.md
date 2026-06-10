# frida-gadget (vendored)

Pre-bundled Windows frida-gadget DLLs for in-process injection under Wine.

## Versions

- `frida-gadget-windows-x86_64.dll` — 64-bit, 23.5 MB
- `frida-gadget-windows-x86.dll` — 32-bit, ~21 MB

## Source

- Upstream: https://github.com/frida/frida/releases/tag/17.11.0
- Direct:
  - https://github.com/frida/frida/releases/download/17.11.0/frida-gadget-17.11.0-windows-x86_64.dll.xz
  - https://github.com/frida/frida/releases/download/17.11.0/frida-gadget-17.11.0-windows-x86.dll.xz

## Why vendored

The in-process frida-gadget-injection path (LoadLibraryA on the gadget DLL
in a Wine-hosted target) requires a Windows .dll. The host's `frida`
Python package is 17.11.0, so the matching gadget version is required for
ABI compatibility (frida protocol is version-strict between client + gadget).

## License

Frida is licensed under the wxWindows Library Licence, Version 3.1.
