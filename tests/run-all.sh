#!/usr/bin/env bash
# Run all ClauKit hook tests.
# Each *.test.sh prints its own summary and exits non-zero on any failure.

set -uo pipefail

cd "$(dirname "$0")"

FAILED=0
for t in *.test.sh; do
  echo ""
  echo "════════════════════════════════════════"
  echo "  $t"
  echo "════════════════════════════════════════"
  if ! bash "$t"; then
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "════════════════════════════════════════"
if [ "$FAILED" -eq 0 ]; then
  echo "  All test files passed."
  exit 0
else
  echo "  $FAILED test file(s) failed."
  exit 1
fi
