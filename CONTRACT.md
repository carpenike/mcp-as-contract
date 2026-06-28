# PocketID MCP-AS Contract — v1.0.1

> Status: **active**. Source of truth for every `carpenike` app that embeds an
> MCP OAuth 2.1 Authorization Server federating login to PocketID.

This contract has three layers:

1. **Core** — invariants **every** conforming AS MUST satisfy.
2. **Token profile** — each AS declares exactly one (`opaque-no-refresh` or `jwt-refresh`).
3. **Scope posture** — each AS declares exactly one (`mcp-only` or `shared-pat`).

The machine-readable mirror of this document is [`contract.json`](./contract.json).
Where the two ever disagree, `contract.json` is authoritative for automated
checks and this file is authoritative for intent.

---

## 0. Terminology

- **AS** — the embedded Authorization Server.
- **RS** — the protected resource (the MCP endpoint, conventionally `/api/mcp`).
- **origin** — the canonical public base URL the client reaches the AS at, scheme + host (+ port), no trailing slash, no path. Example: `https://replog.holthome.net`.
- **client** — the MCP client doing the OAuth dance (claude.ai, VS Code, …).
- **IdP** — PocketID, the upstream OpenID Provider the AS federates to.

---

## 1. Core (mandatory)

### 1.1 Discovery — field names are load-bearing

Non-spec field names silently break clients with **no client-side log line**
(empirically proven during the original homelab-mcp recon: Cloudflare Access's
`authorization_code_with_pkce` instead of `authorization_code` broke Claude
invisibly). Field names below are exact and non-negotiable.

**RFC 8414 — Authorization Server Metadata**, served at
`/.well-known/oauth-authorization-server`:

| field | value |
| --- | --- |
| `issuer` | `<origin>` |
| `authorization_endpoint` | `<origin>/oauth/authorize` |
| `token_endpoint` | `<origin>/oauth/token` |
| `registration_endpoint` | `<origin>/oauth/register` |
| `response_types_supported` | `["code"]` |
| `grant_types_supported` | `["authorization_code"]` (+ `"refresh_token"` under the `jwt-refresh` profile) |
| `code_challenge_methods_supported` | `["S256"]` |
| `token_endpoint_auth_methods_supported` | MUST include `"client_secret_basic"`, `"client_secret_post"`, and `"none"` |
| `scopes_supported` | `["openid", "email", "profile"]` |

**RFC 9728 — Protected Resource Metadata**, served at **both**:

- `/.well-known/oauth-protected-resource` (origin-root; `resource` = `<origin>`)
- `/.well-known/oauth-protected-resource/api/mcp` (path-suffixed; `resource` = `<origin>/api/mcp`)

| field | value |
| --- | --- |
| `resource` | MUST **byte-match** the URL the client used to fetch this document (RFC 9728 §3.3) |
| `authorization_servers` | `["<origin>"]` |
| `bearer_methods_supported` | `["header"]` |

Both variants are required: spec-strict clients (VS Code 1.106–1.107) **reject**
the origin-root PRM because its `resource` (`<origin>`) doesn't equal the MCP URL
they called (`<origin>/api/mcp`), and refuse DCR. Older clients use the
origin-root variant. Serve both.

> **The §3.3 byte-match is the #1 silent-failure mode.** If the AS derives the
> origin from static config, that config MUST equal the public URL exactly
> (scheme, host, port). Validate it at startup and fail loudly; do not let a
> misconfigured origin ship a PRM the client will silently reject.

### 1.2 Authorization-code grant + PKCE

- `response_type=code` only. Reject anything else with `unsupported_response_type`.
- PKCE **required**: `code_challenge` + `code_challenge_method=S256`. Reject missing/`plain` with `invalid_request`.
- Verify the client's `code_verifier` at the token endpoint as `BASE64URL(SHA256(verifier)) == code_challenge`, constant-time.

### 1.3 Two-leg PKCE federation to PocketID

The AS is itself a PocketID OIDC client. There are **two independent PKCE legs
that never cross**:

- **client ↔ AS** — the client generates the verifier/challenge; the AS verifies it at `/oauth/token`.
- **AS ↔ PocketID** — the AS generates its *own* verifier/challenge for the upstream hop and presents it at PocketID's token endpoint.

Flow: `/oauth/authorize` validates the client + redirect + PKCE, stashes the
client's challenge alongside a fresh AS↔PocketID verifier + nonce in
short-lived transaction state, and 302s to PocketID. `/oauth/callback` consumes
that state (single-use), exchanges the code with PocketID, verifies the ID
token + nonce, JIT-upserts the local user keyed on the PocketID `sub`, issues a
single-use authorization code bound to `{user, client, redirect_uri,
client_code_challenge}`, and 302s back to the client.

### 1.4 Dynamic Client Registration (RFC 7591)

- `POST /oauth/register`, **rate-limited per source IP** (reference: 10/hour).
- **Redirect-URI policy = allowlist-filter, not allowlist-reject:** drop
  redirect_uris not matching an allowed prefix; only 400 (`invalid_redirect_uri`)
  when *none* remain. Clients register several and use one.
- Allowed redirect-URI prefixes (loopback entries keep the trailing `:` or `/`
  so `http://127.0.0.1.evil.com/` can't pass a naive prefix test):
  - `https://claude.ai/`
  - `https://claude.com/`
  - `http://127.0.0.1:`
  - `http://127.0.0.1/`
  - `http://localhost:`
  - `http://localhost/`
  - `https://vscode.dev/redirect`
  - `https://insiders.vscode.dev/redirect`
- Response is `201` with `client_id`, `client_secret`, `client_secret_expires_at: 0` (never expires), and the stored `redirect_uris`.

### 1.5 Token endpoint

- `grant_type=authorization_code` (+ `refresh_token` under the `jwt-refresh` profile). Reject others with `unsupported_grant_type`.
- Accept client credentials via **both** `client_secret_post` and HTTP Basic.
- Single-use-consume the authorization code; verify it was issued to this
  client + redirect, then verify PKCE. Any failure → `invalid_grant`.
- Compare the DCR client secret constant-time against a stored hash. Failure → `invalid_client` (401), with no unknown-client-vs-bad-secret oracle.
- Success → `200`, `Cache-Control: no-store`, body `{access_token, token_type:"Bearer", expires_in, scope}`.

### 1.6 Tokens at rest + revocation

- Tokens (and refresh tokens, if any) are stored **hashed (SHA-256), never plaintext**.
- Tokens are **revocable** (soft-delete / revoked-at). Validation rejects revoked or expired tokens as if unknown.

### 1.7 Unauthorized challenge

A `401` from the RS MUST carry a `WWW-Authenticate: Bearer` header that includes
`resource_metadata="<origin>/.well-known/oauth-protected-resource/api/mcp"`, so a
client can discover the AS and begin the dance (RFC 9728 §5.3).

### 1.8 Errors

OAuth errors use spec codes (`invalid_request`, `invalid_client`,
`invalid_grant`, `unsupported_grant_type`, `unsupported_response_type`,
`invalid_redirect_uri`, `temporarily_unavailable`, `server_error`) as JSON with
`error` + `error_description`, `Cache-Control: no-store`. An error is only
redirected back to a client redirect_uri after that redirect_uri has been
**validated** against the registered client; otherwise it is returned in-band.

---

## 2. Token profiles (declare exactly one)

### 2.1 `opaque-no-refresh`

- Access token is **opaque**, PAT-shaped, prefixed (e.g. `rlpat_`, `wwwpat_`, `mgpat_`), validated by hashed-handle lookup.
- **No refresh tokens.** Fixed TTL (reference default **90 days**); the client re-runs the OAuth dance on expiry.
- AS metadata **MUST omit `jwks_uri`** (there are no JWTs to verify).
- Conformers: `replog`, `whiskey-whiskey-whiskey`, `marginalia`.

### 2.2 `jwt-refresh`

- Access token is a signed **JWT (RS256)**; the AS publishes a `jwks_uri` and the RS verifies signatures against it.
- **Refresh tokens** are issued (rotating), stored hashed, revocable; the token endpoint also supports `grant_type=refresh_token`.
- Conformers: `homelab-mcp`.

---

## 3. Scope postures (declare exactly one)

### 3.1 `mcp-only`

The minted token is accepted **only** on the MCP resource path. It cannot be
replayed against the app's broader API. Smallest blast radius. (`replog`,
`homelab-mcp`.)

### 3.2 `shared-pat`

The minted token rides the app's general personal-access-token branch and is
valid across the app's API, role-capped to the user. Chosen when the app
already has a user-facing PAT system the OAuth token reuses. (`whiskey-whiskey-whiskey`,
`marginalia`.)

> A `shared-pat` AS that wants the `mcp-only` blast radius without a storage
> change can stamp the OAuth-minted token with an issuer discriminator (e.g.
> `issuer='oauth'`) and refuse those tokens outside the MCP path. This is a
> documented upgrade path, not a violation.

---

## 4. Conformance

Run [`conformance/check.sh`](./conformance/check.sh) against a live AS:

```sh
conformance/check.sh <origin> <profile> <scope>
# e.g.
conformance/check.sh https://replog.holthome.net opaque-no-refresh mcp-only
```

It validates §1.1 discovery (both PRM variants + the byte-match), the
profile-specific `jwks_uri` rule (§2), and a DCR round-trip (§1.4). It does
**not** drive an interactive PocketID login (that needs a human); the federation
legs (§1.3) are asserted by each app's own integration tests.

---

## Changelog

- **1.0.1** — conformance tooling fix only, **no normative changes**: corrected a
  subshell bug in `conformance/check.sh` where the HTTP status was set in a
  `$(...)` command-substitution subshell and never reached the caller, so every
  GET-based assertion false-failed as "HTTP none". The spec (this document and
  `contract.json`) is byte-identical to 1.0.0; a `v1.0` conformance declaration
  remains valid.
- **1.0.0** — initial contract extracted from the `replog` / `whiskey-whiskey-whiskey` /
  `marginalia` / `homelab-mcp` implementations.
