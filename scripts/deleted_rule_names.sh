#!/usr/bin/env bash
# Emit comma-separated rule names whose YAML files were deleted between
# the given "from" git ref and HEAD. Used by plan/apply to pass an explicit
# deletion whitelist to sync_detections.py.
#
# Usage:
#   scripts/deleted_rule_names.sh HEAD~1
#   scripts/deleted_rule_names.sh origin/main
set -euo pipefail
FROM_REF="${1:?usage: $0 <from-ref>}"

RESULT=""
for f in $(git diff --name-only --diff-filter=D "${FROM_REF}...HEAD" -- rules/ 2>/dev/null); do
    # Read the deleted file as it existed at the previous ref; parse its
    # name: line. Quotes (single or double) around the value are stripped.
    RULE_NAME=$(git show "${FROM_REF}:${f}" 2>/dev/null | \
        awk -F: '/^name:/ {
            sub(/^name: */, "");
            gsub(/^["'"'"']|["'"'"']$/, "");
            print; exit
        }')
    if [ -n "$RULE_NAME" ]; then
        if [ -n "$RESULT" ]; then RESULT="${RESULT},"; fi
        RESULT="${RESULT}${RULE_NAME}"
    fi
done
printf "%s" "$RESULT"
