#!/usr/bin/env bash
# Witch Dog local/VM code review. Run from a disposable, read-only checked-out PR repo.
# CI must provide exact base and head SHAs; no repo code is executed by this script.
set -euo pipefail
if [ -z "${WITCHDOG_HOME:-}" ] || [ -z "${BASE_SHA:-}" ] || [ -z "${HEAD_SHA:-}" ]; then
  echo "Set WITCHDOG_HOME, BASE_SHA and HEAD_SHA" >&2
  exit 2
fi
OUT="$PWD/.witchdog/pr-review"
if [ -n "${WITCHDOG_OUTPUT:-}" ]; then OUT="${WITCHDOG_OUTPUT:-}"; fi
POLICY="$OUT/policy"
REF=main
if [ -n "${WITCHDOG_POLICY_REF:-}" ]; then REF="${WITCHDOG_POLICY_REF:-}"; fi
python3 "$WITCHDOG_HOME/tools/pr_policy.py" --out "$POLICY" --bundled "${WITCHDOG_HOME:-}" --ref "$REF" || true
python3 "$WITCHDOG_HOME/tools/pr_review.py" inspect --repo "$PWD" --base "${BASE_SHA:-}" --head "${HEAD_SHA:-}" --out "$OUT" --kit "$POLICY"
if [ "${WITCHDOG_ENABLE_AI:-false}" = "true" ]; then
  if [ "${WITCHDOG_APPROVE_CODE_SHARING:-false}" != "true" ]; then
    echo "Code sharing not approved" >&2
    exit 2
  fi
  if [ -z "${WITCHDOG_MODEL:-}" ]; then echo "Select model" >&2; exit 2; fi
  PROVIDER=opencode-go
  if [ -n "${WITCHDOG_PROVIDER:-}" ]; then PROVIDER="${WITCHDOG_PROVIDER:-}"; fi
  python3 "$WITCHDOG_HOME/tools/pr_review.py" ai --out "$OUT" --model "${WITCHDOG_MODEL:-}" \
    --provider "$PROVIDER" --allow-code-to-model || true
fi
python3 "$WITCHDOG_HOME/tools/pr_review.py" validate --out "$OUT"
echo "Private report: $OUT/review.md"
# GitHub publishing needs a separate, narrowly credentialed process invoking pr_publish.py.
