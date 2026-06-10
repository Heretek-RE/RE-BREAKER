# re-yara

MCP server wrapping the **YARA** pattern-matching engine for binary triage.

`re-yara` is intentionally **rule-agnostic**: the server compiles
whatever rule directory the analyst points it at, then scans files
or directories against the compiled rules. No rules are bundled
with the plugin — YARA rules describe categories of binary
behaviour (e.g. *encrypted-VM bytecode interpreter dispatcher*,
*MBA-obfuscated arithmetic routine*, *legacy disc-based protection
handshake*) and writing them is an analyst decision, not a plugin
one.

## Tools

| Tool | What it does |
|---|---|
| `check_yara` | Health check — return YARA version + whether `yara-python` is importable |
| `compile_rules` | Compile all `*.yar` / `*.yara` files under a directory into a YARA ruleset |
| `scan_binary` | Run a compiled ruleset against a single file |
| `scan_directory` | Walk a directory and run the compiled ruleset against every file |

## Install

Part of the RE-AI plugin; `./install.sh` installs the package. To
install standalone:

```bash
pip install -e ./servers/re-yara
```

Requires the `yara` C library (libyara) at runtime — `yara-python`
links against it. Most package managers ship `yara` as a system
package; on Debian/Ubuntu:

```bash
sudo apt-get install yara libyara-dev
```

## Run

```bash
re-yara                           # stdio transport (default for MCP)
python -m re_yara                 # equivalent
```

## Workflow

1. Author or download a directory of `*.yar` files. Each rule
   describes a category of behaviour the analyst wants to find.
2. Call `compile_rules(rules_dir=<path>)` to validate + compile.
3. Call `scan_binary(path=<file>, rules_dir=<path>)` for a single
   file, or `scan_directory(path=<dir>, rules_dir=<path>)` for a
   whole tree.

`compile_rules` is the heavy step (parses every rule file). The
scan tools re-compile as needed — they're cheap if the rules
haven't changed.

## Why no bundled rules

YARA rules are an analyst artefact: they describe **what you are
looking for**, which is a question only the user can answer. The
plugin gives the engine; the user brings the policies. The
server is also compatible with the [signature-base] and
[MalwareBazaar] rule collections — point `rules_dir` at any of
them.

[s MalwareBazaar]: https://github.com/malwarebazaar
[signature-base]: https://github.com/Neo23x0/signature-base
