#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/src"
DIST="$SCRIPT_DIR/dist"
OUTPUT="$DIST/fix.sh"

mkdir -p "$DIST"

# Order matters: header → lib → modules → footer
FILES=(
    "$SRC/header.sh"
    "$SRC/lib/i18n.sh"
    "$SRC/lib/common.sh"
    "$SRC/lib/detect.sh"
    "$SRC/modules/00-forensics.sh"
    "$SRC/modules/01-kill.sh"
    "$SRC/modules/02-ssh.sh"
    "$SRC/modules/03-history.sh"
    "$SRC/modules/04-github.sh"
    "$SRC/modules/05-k8s.sh"
    "$SRC/modules/06-docker.sh"
    "$SRC/modules/07-keychain.sh"
    "$SRC/modules/08-env-scan.sh"
    "$SRC/modules/09-audit.sh"
    "$SRC/modules/10-npm.sh"
    "$SRC/modules/11-wincred.sh"
    "$SRC/footer.sh"
)

{
    first=true
    for f in "${FILES[@]}"; do
        if [ ! -f "$f" ]; then
            echo "Warning: $f not found, skipping" >&2
            continue
        fi
        if $first; then
            cat "$f"
            first=false
        else
            # Strip shebang and 'set -euo pipefail' from subsequent files
            sed -E '/^#!\/usr\/bin\/env bash$/d; /^#!/d; /^set -euo pipefail$/d; /^# shellcheck source/d' "$f"
        fi
        echo ""
    done
} > "$OUTPUT"

chmod +x "$OUTPUT"
echo "Built: $OUTPUT ($(wc -l < "$OUTPUT") lines)"
