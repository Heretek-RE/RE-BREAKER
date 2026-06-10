---
name: re-input-audit
version: 0.1.0
status: implemented
family: workflow
catalog_entry: null
playbook: docs/PLAYBOOKS/cross-target-entitlement-bypass.md
pattern_yaml: null
---

# re-input-audit

**v0.1.0 implemented.** A systematic integrity check that compares every file in a target's working directory tree against a known-fresh reference. Catches:

- **`.orig` files** that were created from a polluted working copy (the LIR v0.7.0 incident)
- **Working files** that have been modified since the fresh reference was captured
- **Missing files** in the working copy that exist in fresh

**Origin:** v0.4.1.9 live-fire run. The LIR session was launched against a working copy that contained 11 `.orig` files (the result of an earlier `re-patch-apply` run that failed mid-deploy). The launcher silently exited at process start with no clear log, and the `.orig` pollution was caught manually only after 2.5 hours of debugging. This skill prevents the next occurrence by running the check before any spawn.

## When to use this skill

Invoke when:

- **Before any `wine` spawn** of a target with a known-fresh reference
- **After any `re-patch-apply` call** that returned a partial success (fewer sites patched than the plan said)
- **After any manual file copy / move** into a target's working directory
- **When a target exits silently** within the first 1-2 seconds (suspect `.orig` pollution)
- **Periodically during long engagements** as a sanity check

## Tools invoked

- `Bash` — `find <target_dir> -type f | sort` and `sha256sum` (the standard Unix tools; no new MCP server needed for v0.1.0)
- `Read` — the reference `<target_dir_fresh>/SHA256SUMS` file
- The `re-input-audit` skill itself is the workflow; in v0.2.0 it may be promoted to a `re-input-audit` MCP server

## Workflow

1. **Locate the fresh reference.** Find the directory that contains the SHA256SUMS of the known-good working copy. Typical locations:
   - `Input/<target>/SHA256SUMS` (the original Input/ tree)
   - `See the RE-BREAKER output directory.` (the per-binary fresh-triage hash, if present)
   - `<target_dir_fresh>/SHA256SUMS` (the operator's per-target fresh-reference)

   If no reference SHA256SUMS exists, **generate one on the first run**:
   ```bash
   find <target_dir_fresh> -type f -not -name '*.orig' -not -name '*.bak' \
     -exec sha256sum {} \; | sort -k2 > <target_dir_fresh>/SHA256SUMS
   ```
   This becomes the reference for all subsequent runs.

2. **Run the audit on the working directory:**
   ```bash
   find <target_dir> -type f -not -name '*.orig' -not -name '*.bak' \
     -exec sha256sum {} \; | sort -k2 > /tmp/audit-working.sha256
   ```

3. **Diff the two:**
   ```bash
   diff <target_dir_fresh>/SHA256SUMS /tmp/audit-working.sha256
   ```
   The diff has 3 categories of output:
   - `<` prefix — file in fresh but not in working (missing)
   - `>` prefix — file in working but not in fresh (added; usually a screenshot or log, but also could be a stray `.dll`)
   - `3c3` style — file in both but with a different hash (modified)

4. **Specifically check for `.orig` / `.bak` pollution:**
   ```bash
   find <target_dir> -type f \( -name '*.orig' -o -name '*.bak' \) -print
   ```
   Any `.orig` or `.bak` file is suspect. For each:
   - Compute the hash
   - Compare to the hash in `<target_dir_fresh>/SHA256SUMS` for the corresponding clean file
   - If the `.orig` exists but the clean file does not, **the working copy is polluted** — the operator must restore the clean file from `<target_dir_fresh>` before spawning

5. **Emit the audit report.** Output a JSON or markdown report with:
   - `working_dir` (path)
   - `fresh_reference` (path)
   - `delta_count` (total number of differences)
   - `missing_count` (in fresh but not in working)
   - `added_count` (in working but not in fresh)
   - `modified_count` (hash mismatch)
   - `orig_pollution_count` (`.orig` / `.bak` files whose clean counterpart is missing or modified)
   - `remediation` (concrete next-step instructions)

6. **Fail loud.** If `orig_pollution_count > 0`, **do not proceed to the spawn**. The audit must report the pollution and the operator must restore the clean files before re-running the audit.

## Example

**Working copy:** `<your-working-copy>/`
**Fresh reference:** `<your-fresh-reference>/SHA256SUMS`

```bash
$ find RE_BREAKER_PLUGIN_ROOT/Input/Lost\ In\ Random/ \
    -type f -not -name '*.orig' -not -name '*.bak' \
    -exec sha256sum {} \; | sort -k2 > /tmp/audit-working.sha256

$ diff RE_BREAKER_PLUGIN_ROOT/Input/Lost\ In\ Random.fresh/SHA256SUMS \
       /tmp/audit-working.sha256 | head -20
< abc123...  /Input/<target-game>.fresh/LostInRandom.exe
> def456...  /Input/<target-game>/LostInRandom.exe.orig
> 789abc...  /Input/<target-game>/LostInRandom.exe  (this is missing!)
```

**Audit result:** `orig_pollution_count: 1` (the `LostInRandom.exe.orig` exists but the clean `LostInRandom.exe` is missing). Remediation: `cp /Input/<target-game>.fresh/LostInRandom.exe /Input/<target-game>/LostInRandom.exe && rm /Input/<target-game>/LostInRandom.exe.orig`.

## Test cases

1. **Empty audit** — `working_dir` is byte-for-byte identical to `fresh_reference`. Expected: `delta_count: 0, orig_pollution_count: 0`.
2. **Screenshot added** — `working_dir` has a `screenshot.png` that `fresh_reference` does not. Expected: `added_count: 1, orig_pollution_count: 0, remediation: "OK to spawn"`.
3. **Single `.orig` pollution** — `working_dir` has `LostInRandom.exe.orig` but is missing `LostInRandom.exe`. Expected: `orig_pollution_count: 1, remediation: "Restore LostInRandom.exe from fresh_reference, then re-audit"`.
4. **Modified working copy** — `working_dir` has a clean `LostInRandom.exe` but its hash differs from `fresh_reference`. Expected: `modified_count: 1, remediation: "Investigate why the file changed"`.
5. **Missing reference SHA256SUMS** — first-run scenario. Expected: `delta_count: 0, remediation: "Generated fresh SHA256SUMS; this is the new reference"`.

## Implementation note (v0.1.0)

v0.1.0 is a workflow skill — no MCP server. The 5-step bash recipe above is the entire implementation. v0.2.0 (planned) will:

- Wrap the workflow in a `re-input-audit` MCP server with `audit(working_dir, fresh_reference)` and `generate_reference(fresh_dir)` tools
- Add a hook into `re-launch-and-observe` to run the audit automatically before any `wine` spawn
- Emit a JSON report (not just bash diff output) for downstream consumption

## Honest read

The LIR pollution incident cost the session 2.5 hours of debugging before the `.orig` files were noticed. A 5-step bash script could have caught it in 2 seconds. The lesson: **file integrity is a precondition for any RE work**, and the toolkit should not assume the working directory is clean.
