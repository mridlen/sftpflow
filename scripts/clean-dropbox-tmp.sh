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
#
# Portability notes:
#   - Some minimal-PATH shells (e.g. sandboxed tool runners) do
#     not include coreutils in PATH. We resolve `find` and `rm`
#     explicitly from a short fallback list that covers
#     WSL/Linux/macOS and Git for Windows. A missing executable
#     is a hard error — the previous version silently swallowed
#     find failures via process substitution and claimed success.

set -euo pipefail

# ------------------------------------------------------------
# Tool discovery
# ------------------------------------------------------------

# Locate a command by name, consulting $PATH first and then a
# small set of known install locations. Echoes the absolute
# path on success; exits 3 if not found.
locate_cmd() {
    local name="$1"
    local p
    p="$(command -v "$name" 2>/dev/null || true)"
    if [ -n "$p" ]; then
        echo "$p"
        return 0
    fi
    for candidate in \
        "/usr/bin/$name" \
        "/bin/$name" \
        "/c/Program Files/Git/usr/bin/$name.exe" \
        "/c/Program Files (x86)/Git/usr/bin/$name.exe" \
        "/mingw64/bin/$name.exe" \
        ; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    echo "clean-dropbox-tmp: cannot locate '$name' on PATH or fallbacks" >&2
    return 3
}

FIND="$(locate_cmd find)" || exit $?
RM="$(locate_cmd rm)"     || exit $?

# ------------------------------------------------------------
# Resolve the tree to clean
# ------------------------------------------------------------

root="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

if [ ! -d "$root" ]; then
    echo "clean-dropbox-tmp: '$root' is not a directory" >&2
    exit 2
fi

# ------------------------------------------------------------
# Enumerate victims
# ------------------------------------------------------------
#
# -regex matches the full path. The .* prefix covers the directory
# portion; the tail enforces .tmp.<digits>.<digits>. POSIX ERE for
# portability across the find versions shipped with WSL / macOS.
#
# We capture find's output via $(...) so a nonzero exit from find
# fails the script (under set -e). Process substitution would hide
# that — the earlier version of this script silently treated a
# missing `find` as "no files to clean," which masked real breakage.
if ! listing="$("$FIND" "$root" \
        -type f \
        -regextype posix-extended \
        -regex '.*\.tmp\.[0-9]+\.[0-9]+$' \
        -print)"; then
    echo "clean-dropbox-tmp: find scan failed under $root" >&2
    exit 4
fi

# Split the newline-separated listing into an array, dropping the
# trailing empty element that comes from a fully empty $listing.
victims=()
if [ -n "$listing" ]; then
    while IFS= read -r f; do
        victims+=("$f")
    done <<< "$listing"
fi

# ------------------------------------------------------------
# Remove
# ------------------------------------------------------------

if [ "${#victims[@]}" -eq 0 ]; then
    echo "clean-dropbox-tmp: no temp files to remove under $root"
    exit 0
fi

for f in "${victims[@]}"; do
    "$RM" -f -- "$f"
    echo "removed: $f"
done

echo "clean-dropbox-tmp: removed ${#victims[@]} file(s)"
