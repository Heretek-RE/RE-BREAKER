#!/usr/bin/env bash
#
# v0.4.1.6 — re-vendor RE-AI into vendored/re-ai/ via git subtree.
#
# Why git subtree (and not git submodule):
#   - RE-AI's upstream (https://github.com/Heretek-AI/RE-AI.git) is a
#     private repo. Submodules require the upstream to be accessible at
#     clone time (each clone has to fetch the submodule's commits from
#     upstream). Tree-style vendoring copies the history into the parent's
#     history — clones are self-contained.
#   - The 8 vendored servers (re-lief, re-patch, re-anti-analysis, etc.)
#     are imported as snapshot commits via `--squash`, so each vendor
#     update is exactly one new commit on RE-BREAKER's history.
#   - Per-commit attribution: every file retains its original RE-AI
#     authorship (since `git subtree add --squash` only squashes the
#     history traversal, not the per-file authorship).
#
# Usage:
#   ./scripts/vendor-re-ai.sh                # vendor RE-AI main @ HEAD
#   ./scripts/vendor-re-ai.sh v2.9.3         # vendor specific tag/commit
#   ./scripts/vendor-re-ai.sh --pull         # re-vendor (merge future RE-AI commits)
#
# This script is idempotent: it refuses to clobber an existing vendored
# tree unless --pull is passed.

set -euo pipefail

REPO="https://github.com/Heretek-AI/RE-AI.git"
PREFIX="vendored/re-ai"
MODE="add"
REF=""

for arg in "$@"; do
    case "$arg" in
        --pull) MODE="pull" ;;
        *)      REF="$arg" ;;
    esac
done

cd "$(dirname "$0")/.."

if [ "$MODE" = "pull" ]; then
    if [ ! -d "$PREFIX" ]; then
        echo "[vendor] error: $PREFIX does not exist. Run './scripts/vendor-re-ai.sh' first." >&2
        exit 1
    fi
    echo "[vendor] pulling latest from $REPO into $PREFIX (squash) ..."
    git subtree pull --prefix="$PREFIX" "$REPO" main --squash -m "vendor(re-ai): pull latest from RE-AI main"
    echo "[vendor] done. New commits:"
    git log --oneline -1
    exit 0
fi

if [ -d "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then
    echo "[vendor] error: $PREFIX already has files. Use --pull to re-vendor." >&2
    exit 1
fi

if [ -n "$REF" ]; then
    REMOTE_REF="$REF"
else
    REMOTE_REF="main"
fi

echo "[vendor] subtree add: $REPO $REMOTE_REF -> $PREFIX (squash) ..."
git subtree add --prefix="$PREFIX" "$REPO" "$REMOTE_REF" --squash \
    -m "vendor(re-ai): add RE-AI @ $REMOTE_REF (squash)"

# Sanity: confirm the vendored files are now git-tracked
COUNT=$(git ls-files "$PREFIX" | wc -l)
echo "[vendor] done. $COUNT files now tracked under $PREFIX/."
echo ""
echo "[vendor] next steps:"
echo "  - commit any local changes (e.g. VENDORED.md updates)"
echo "  - re-run './scripts/vendor-re-ai.sh --pull' to import future RE-AI commits"
