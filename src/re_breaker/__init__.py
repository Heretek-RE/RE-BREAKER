"""re-breaker: RE-BREAKER Python package.

v0.2.0: thin CLI wrappers + library imports for the 7 RE-BREAKER bypass
servers. The actual bypass logic lives in the per-server MCP packages
under `servers/*/src/<name>/`; this package just provides the CLI surface
(`re-dump`, `re-catalog-match`, `re-anti-debug-patch`, etc.) and any
shared library code (catalog loader, license-ack cache, etc.).
"""
__version__ = "0.2.0"
