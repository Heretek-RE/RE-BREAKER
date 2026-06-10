#!/usr/bin/env bash
# setup_env.sh — v0.8.0+ environment for the RE-BREAKER MCP servers
#
# v0.7.0 set the plugin roots. v0.8.0+ adds:
#   - frida + frida-tools (required by re-anti-vm-spoof.spoof_runtime,
#     re-frida-runtime.frida_attach, re-frida-wine-runtime.*)
#   - pe-sieve.exe download (for re-patch-apply verify path)
#   - sunblink SDK path (for HKIA research, M)
#
# Source this file in your shell before launching Claude Code:
#   source tools/setup_env.sh
# Or add `source /path/to/RE-BREAKER/tools/setup_env.sh` to your .bashrc.
export RE_AI_PLUGIN_ROOT=../RE-AI
export RE_BREAKER_PLUGIN_ROOT=.

# v0.8.0+ Wave 1 (Item C): frida for the anti-VM spoof runtime
if ! python3 -c "import frida" 2>/dev/null; then
    echo "[setup_env] frida Python package not found; installing..."
    pip install frida frida-tools
else
    echo "[setup_env] frida already installed"
fi

# v0.8.0+ Wave 2 (Item E): pe-sieve for re-patch-apply verify
PE_SIEVE_DIR="$RE_BREAKER_PLUGIN_ROOT/vendored/pe-sieve"
if [ ! -x "$PE_SIEVE_DIR/pe-sieve.exe" ]; then
    echo "[setup_env] pe-sieve.exe not found; downloading to $PE_SIEVE_DIR..."
    mkdir -p "$PE_SIEVE_DIR"
    # Latest release URL (hasherezade/pe-sieve)
    PE_SIEVE_URL="https://github.com/hasherezade/pe-sieve/releases/download/v0.4.0/pe-sieve.zip"
    curl -sL "$PE_SIEVE_URL" -o /tmp/pe-sieve.zip && \
        unzip -o /tmp/pe-sieve.zip -d "$PE_SIEVE_DIR" && \
        rm /tmp/pe-sieve.zip
fi

echo "[setup_env] RE_AI_PLUGIN_ROOT=$RE_AI_PLUGIN_ROOT"
echo "[setup_env] RE_BREAKER_PLUGIN_ROOT=$RE_BREAKER_PLUGIN_ROOT"
