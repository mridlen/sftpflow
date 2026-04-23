#!/usr/bin/env bash
# ============================================================
# clean-dropbox-tmp.sh
# ============================================================
#
# Removes Dropbox-lock-artifact temp files left behind by the
# editor. Pattern: "<filename>.tmp.<pid>.<timestamp>" — both
# <pid> and <timestamp> are numeric, so the glob is constrained
# enough that it won't sweep up real files (e.g. "foo.tmp"
# stays put; only "foo.tmp.123.456" is removed).
#
# Safe to run repeatedly; exits 0 when nothing is found.
#
# Usage:
#   scripts/clean-dropbox-tmp.sh          # clean repo root
#   scripts/clean-dropbox-tmp.sh <path>   # clean a different tree

set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

if [ ! -d "$root" ]; then
    echo "clean-dropbox-tmp: '$root' is not a directory" >&2
    exit 2
fi

# -regex matches the full path. The .* prefix covers the directory
# portion; the tail enforces .tmp.<digits>.<digits>. POSIX ERE for
# portability across the find versions shipped with WSL / macOS.
mapfile -t victims < <(
    find "$root" \
        -type f \
        -regextype posix-extended \
        -regex '.*\.tmp\.[0-9]+\.[0-9]+$' \
        -print
)

if [ "${#victims[@]}" -eq 0 ]; then
    echo "clean-dropbox-tmp: no temp files to remove under $root"
    exit 0
fi

for f in "${victims[@]}"; do
    rm -f -- "$f"
    echo "removed: $f"
done

echo "clean-dropbox-tmp: removed ${#victims[@]} file(s)"
