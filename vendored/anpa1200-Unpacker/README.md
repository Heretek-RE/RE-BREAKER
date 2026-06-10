# anpa1200/Unpacker (vendored stub)

This directory is the RE-BREAKER integration point for
[anpa1200/Unpacker](https://github.com/anpa1200/Unpacker).

## Setup (one-time)

```bash
# Clone anpa1200/Unpacker into this directory:
cd /home/john/Desktop/RE/RE-BREAKER/vendored/anpa1200-Unpacker
git clone https://github.com/anpa1200/Unpacker.git .

# Install the dependencies (Qiling for 64-bit, Unipacker for 32-bit):
pip install qiling-framework unipacker

# Verify the install:
python3 -c "import qiling; print('qiling:', qiling.__version__)"
```

## Usage

Once cloned, the RE-BREAKER `re-vendor-anti-tamper.run_vendor_tool()`
tool will pick up anpa1200 automatically when the vendor is
`vmprotect` or `themida`. No further configuration needed.

## Why anpa1200?

v0.2.0 of RE-BREAKER referenced `samrashaikh/Themida-Unpacker`. That
repo was last updated in 2019 and no longer works with modern (post-
2022) VMProtect 3.x and Themida 3.x builds. anpa1200/Unpacker is the
modern replacement because:

- It integrates Unipacker (32-bit, the gold-standard for legacy
  VMProtect 2.x and Themida 2.x) with Qiling (64-bit, the modern
  emulation-based approach for VMProtect 3.x 64-bit).
- It supports both VMProtect and Themida in one tool (the two
  share ~80% of the bytecode interpreter design).
- It actively maintained (last commit 2024-Q3).

## v0.8.0+ Wave 2 (Item F) integration

The wrapper is at
`servers/re-vendor-anti-tamper/src/re_vendor_anti_tamper/backends/unpacker/anpa1200.py`.

The `run_vendor_tool` tool automatically delegates to anpa1200 when:
- vendor == "vmprotect" OR vendor == "themida"
- Anpa1200 is_available() (cloned + Qiling + Unipacker installed)
- The target is a real binary on disk (not a Wine-launched process)

## License

anpa1200/Unpacker is MIT-licensed. The vendoring step is a no-op for
license purposes (we don't redistribute; we just point RE-BREAKER
at the user's local clone).
