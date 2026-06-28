#!/usr/bin/env bash
#
# Conformance check for the PocketID MCP-AS Contract (CONTRACT.md / contract.json).
#
# Hits a LIVE Authorization Server and asserts it matches the contract's core
# discovery rules (§1.1), the profile-specific jwks_uri rule (§2), and a DCR
# round-trip (§1.4). It does NOT drive an interactive PocketID login — the
# federation legs (§1.3) are covered by each app's own integration tests, and
# the scope posture (§3) needs a minted token, so it is recorded but not
# actively probed here.
#
# Usage:
#   conformance/check.sh <origin> <profile> <scope> [--skip-dcr]
#
#   <origin>   canonical public base URL, no trailing slash (e.g. https://replog.holthome.net)
#   <profile>  opaque-no-refresh | jwt-refresh
#   <scope>    mcp-only | shared-pat   (recorded only; not auto-verified in v1.0)
#
# Requires: curl, jq.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT="${SCRIPT_DIR}/../contract.json"

origin="${1:-}"
profile="${2:-}"
scope="${3:-}"
skip_dcr="${4:-}"

if [[ -z "$origin" || -z "$profile" || -z "$scope" ]]; then
  echo "usage: $0 <origin> <profile> <scope> [--skip-dcr]" >&2
  exit 2
fi
origin="${origin%/}"

for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 2; }
done
[[ -f "$CONTRACT" ]] || { echo "cannot find contract.json at $CONTRACT" >&2; exit 2; }

version="$(jq -r '.version' "$CONTRACT")"
echo "== PocketID MCP-AS conformance v${version} =="
echo "   origin=${origin} profile=${profile} scope=${scope}"
echo

pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

# get <url> -> echoes body, sets $HTTP_STATUS
get() {
  local url="$1" tmp; tmp="$(mktemp)"
  HTTP_STATUS="$(curl -fsS -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null || true)"
  cat "$tmp"; rm -f "$tmp"
}

# json_has_member <json> <jq-path> <expected-value-as-member>
contains() { jq -e --arg v "$2" "$1 | index(\$v) != null" >/dev/null 2>&1; }

echo "[1] RFC 8414 — authorization-server metadata"
AS_URL="${origin}/.well-known/oauth-authorization-server"
AS="$(get "$AS_URL")"
if [[ "${HTTP_STATUS:-}" != "200" ]]; then
  bad "GET ${AS_URL} -> HTTP ${HTTP_STATUS:-none} (want 200)"
else
  [[ "$(jq -r '.issuer' <<<"$AS")" == "$origin" ]] && ok "issuer == origin" || bad "issuer != origin (got $(jq -r '.issuer' <<<"$AS"))"
  [[ "$(jq -r '.authorization_endpoint' <<<"$AS")" == "${origin}/oauth/authorize" ]] && ok "authorization_endpoint" || bad "authorization_endpoint"
  [[ "$(jq -r '.token_endpoint' <<<"$AS")" == "${origin}/oauth/token" ]] && ok "token_endpoint" || bad "token_endpoint"
  [[ "$(jq -r '.registration_endpoint' <<<"$AS")" == "${origin}/oauth/register" ]] && ok "registration_endpoint" || bad "registration_endpoint"
  contains '.response_types_supported' code     <<<"$AS" && ok "response_types_supported has code" || bad "response_types_supported missing code"
  contains '.grant_types_supported' authorization_code <<<"$AS" && ok "grant_types_supported has authorization_code" || bad "grant_types_supported missing authorization_code"
  contains '.code_challenge_methods_supported' S256 <<<"$AS" && ok "code_challenge_methods_supported has S256" || bad "code_challenge_methods_supported missing S256"
  for m in client_secret_basic client_secret_post none; do
    contains '.token_endpoint_auth_methods_supported' "$m" <<<"$AS" && ok "token_endpoint_auth_methods_supported has ${m}" || bad "token_endpoint_auth_methods_supported missing ${m}"
  done
  for s in openid email profile; do
    contains '.scopes_supported' "$s" <<<"$AS" && ok "scopes_supported has ${s}" || bad "scopes_supported missing ${s}"
  done

  echo "[2] token profile — ${profile}"
  has_jwks="$(jq 'has("jwks_uri")' <<<"$AS")"
  case "$profile" in
    opaque-no-refresh)
      [[ "$has_jwks" == "false" ]] && ok "jwks_uri absent (opaque profile)" || bad "jwks_uri MUST be absent under opaque-no-refresh"
      ;;
    jwt-refresh)
      [[ "$has_jwks" == "true" ]] && ok "jwks_uri present (jwt profile)" || bad "jwks_uri MUST be present under jwt-refresh"
      contains '.grant_types_supported' refresh_token <<<"$AS" && ok "grant_types_supported has refresh_token" || bad "grant_types_supported missing refresh_token (jwt-refresh)"
      ;;
    *) bad "unknown profile '${profile}' (want opaque-no-refresh | jwt-refresh)";;
  esac
fi

echo "[3] RFC 9728 — protected-resource metadata (both variants)"
check_prm() {
  local path="$1" want_resource="$2" url body
  url="${origin}${path}"
  body="$(get "$url")"
  if [[ "${HTTP_STATUS:-}" != "200" ]]; then bad "GET ${path} -> HTTP ${HTTP_STATUS:-none}"; return; fi
  [[ "$(jq -r '.resource' <<<"$body")" == "$want_resource" ]] && ok "${path}: resource byte-matches ${want_resource}" || bad "${path}: resource '$(jq -r '.resource' <<<"$body")' != '${want_resource}' (RFC 9728 §3.3)"
  [[ "$(jq -rc '.authorization_servers' <<<"$body")" == "[\"${origin}\"]" ]] && ok "${path}: authorization_servers == [origin]" || bad "${path}: authorization_servers"
  contains '.bearer_methods_supported' header <<<"$body" && ok "${path}: bearer_methods_supported has header" || bad "${path}: bearer_methods_supported missing header"
}
check_prm "/.well-known/oauth-protected-resource"        "${origin}"
check_prm "/.well-known/oauth-protected-resource/api/mcp" "${origin}/api/mcp"

echo "[4] RFC 7591 — DCR round-trip"
if [[ "$skip_dcr" == "--skip-dcr" ]]; then
  echo "  SKIP  (--skip-dcr)"
else
  allowed="https://claude.ai/conformance-probe"
  disallowed="https://evil.example.com/x"
  reg_body="$(jq -nc --arg a "$allowed" --arg d "$disallowed" \
    '{client_name:"mcp-as-contract conformance probe", redirect_uris:[$a,$d], token_endpoint_auth_method:"client_secret_post"}')"
  tmp="$(mktemp)"
  status="$(curl -fsS -o "$tmp" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -d "$reg_body" \
    "${origin}/oauth/register" 2>/dev/null || true)"
  reg="$(cat "$tmp")"; rm -f "$tmp"
  if [[ "$status" != "201" ]]; then
    bad "POST /oauth/register -> HTTP ${status} (want 201)"
  else
    [[ -n "$(jq -r '.client_id // empty' <<<"$reg")" ]] && ok "client_id issued" || bad "no client_id in DCR response"
    [[ -n "$(jq -r '.client_secret // empty' <<<"$reg")" ]] && ok "client_secret issued" || bad "no client_secret in DCR response"
    [[ "$(jq -r '.client_secret_expires_at' <<<"$reg")" == "0" ]] && ok "client_secret_expires_at == 0" || bad "client_secret_expires_at != 0"
    if jq -e --arg a "$allowed" --arg d "$disallowed" \
        '(.redirect_uris | index($a) != null) and (.redirect_uris | index($d) == null)' <<<"$reg" >/dev/null; then
      ok "redirect_uris allowlist-filtered (kept allowed, dropped disallowed)"
    else
      bad "redirect_uris not filtered per allowlist policy (got $(jq -rc '.redirect_uris' <<<"$reg"))"
    fi
    echo "  note: a throwaway DCR client was created; prune it if your AS persists registrations."
  fi
fi

echo
echo "scope posture '${scope}' is declared, not auto-verified in v1.0 (needs a minted token)."
echo "== ${pass} passed, ${fail} failed =="
[[ "$fail" -eq 0 ]]
