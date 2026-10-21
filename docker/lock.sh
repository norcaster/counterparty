#!/usr/bin/env bash
# Regenerate the image's hash-pinned requirements (run from the repository root, needs uv).
# After norcaster-verify's release is on PyPI, run it with no arguments and commit the result.
# Before that, pass the directory holding the norcaster-verify wheel you built:
#   docker/lock.sh path/to/dist
set -euo pipefail
cd "$(dirname "$0")"
EXTRA=()
[ -n "${1:-}" ] && EXTRA=(--find-links "$1")
for name in requirements build-requirements; do
  uv pip compile "$name.in" --generate-hashes --python-version 3.12 --python-platform linux \
    --no-header --quiet "${EXTRA[@]}" -o "$name.txt"
done
echo "wrote docker/requirements.txt and docker/build-requirements.txt"
