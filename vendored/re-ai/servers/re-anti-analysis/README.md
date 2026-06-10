# re-anti-analysis

MCP server for anti-analysis primitive scanning: cross-section correlation of anti-debug + anti-VM + anti-sandbox primitives in a binary. Wraps re-lief + re-rizin + the vendored data/anti-analysis-catalog.json. Pure-Python, vendor-neutral.

## Tools

Run ``re-anti-analysis`` over the MCP stdio transport to expose the
tool surface. The server is a pure-Python wrapper; the actual
work delegates to the existing RE-AI servers (re-lief, re-rizin,
re-yara, re-frida, etc.).

## Installation

The server is installed by `./install.sh` from the plugin root
and is auto-registered in `.mcp.json`. No external system
dependencies.

## Vendor-neutrality

All output is vendor-neutral: category names only, no specific
commercial product / publisher / game title.
