#!/usr/bin/env bash
#
# Self-test for conformance/check.sh: run it against a known-good stub AS (must
# PASS) and a known-bad stub AS (must FAIL). This is the guard that keeps the
# checker honest — it catches both "the checker stopped reaching the server"
# (good stub fails) and "the checker stopped asserting" (bad stub passes)
# regressions. Pure stdlib stub; needs bash, curl, jq, python3.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$DIR/../check.sh"
STUB="$DIR/stub_as.py"
PORT="${PORT:-8077}"
ORIGIN="http://127.0.0.1:${PORT}"

pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; }
trap cleanup EXIT

start_stub() {
  cleanup
  STUB_MODE="$1" python3 "$STUB" "$PORT" > /tmp/stub_as.log 2>&1 &
  pid=$!
  for _ in $(seq 1 40); do
    curl -sf "${ORIGIN}/.well-known/oauth-authorization-server" >/dev/null && return 0
    sleep 0.25
  done
  echo "::error::stub ($1) did not come up"; cat /tmp/stub_as.log; exit 1
}

echo "=== self-test 1/2: GOOD stub must PASS ==="
start_stub good
"$CHECK" "$ORIGIN" opaque-no-refresh mcp-only --mcp-path /api/mcp
echo

echo "=== self-test 2/2: BAD stub must FAIL ==="
start_stub bad
if "$CHECK" "$ORIGIN" opaque-no-refresh mcp-only --mcp-path /api/mcp; then
  echo "::error::checker PASSED a non-compliant AS — the checker is not actually checking"
  exit 1
fi
echo "ok: checker correctly rejected the non-compliant AS"
echo
echo "== self-test passed =="
