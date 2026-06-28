#!/usr/bin/env python3
"""Stub MCP-AS Authorization Server for the contract self-test.

Serves the discovery documents + DCR endpoint that conformance/check.sh probes,
so the checker can be run against a known-good (and a known-bad) target in CI.
This is the guard that catches checker regressions: a bug like "the status never
reaches the caller" makes the GOOD stub fail, and a checker that stops asserting
makes the BAD stub pass — both flip the self-test red.

Mode is selected by the STUB_MODE env var:
  good  (default) — fully contract-compliant metadata.
  bad             — the exact regression v1.0.0 shipped: AS metadata omits the
                    "none" auth method and the PRMs omit bearer_methods_supported.

Origin is derived from the request Host header, so the RFC 9728 byte-match holds
for whatever host:port the checker uses. Pure stdlib; no dependencies.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = os.environ.get("STUB_MODE", "good")

# The contract's redirect-URI allowlist (filter-don't-reject).
ALLOWLIST = (
    "https://claude.ai/",
    "https://claude.com/",
    "http://127.0.0.1:",
    "http://127.0.0.1/",
    "http://localhost:",
    "http://localhost/",
    "https://vscode.dev/redirect",
    "https://insiders.vscode.dev/redirect",
)


def as_metadata(origin):
    auth_methods = ["client_secret_basic", "client_secret_post", "none"]
    if MODE == "bad":
        auth_methods = ["client_secret_post"]  # regression: drops "none"
    return {
        "issuer": origin,
        "authorization_endpoint": origin + "/oauth/authorize",
        "token_endpoint": origin + "/oauth/token",
        "registration_endpoint": origin + "/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": auth_methods,
        "scopes_supported": ["openid", "email", "profile"],
        # jwks_uri intentionally omitted (opaque-no-refresh profile).
    }


def prm(origin, resource):
    doc = {"resource": resource, "authorization_servers": [origin]}
    if MODE != "bad":
        doc["bearer_methods_supported"] = ["header"]  # regression: dropped in bad
    return doc


class Handler(BaseHTTPRequestHandler):
    def _origin(self):
        return "http://" + self.headers.get("Host", "127.0.0.1")

    def _send(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        origin = self._origin()
        if self.path == "/.well-known/oauth-authorization-server":
            self._send(200, as_metadata(origin))
        elif self.path == "/.well-known/oauth-protected-resource":
            self._send(200, prm(origin, origin))
        elif self.path == "/.well-known/oauth-protected-resource/api/mcp":
            self._send(200, prm(origin, origin + "/api/mcp"))
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/oauth/register":
            self._send(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid_client_metadata"})
            return
        uris = [u for u in req.get("redirect_uris", [])
                if any(u.startswith(p) for p in ALLOWLIST)]
        if not uris:
            self._send(400, {"error": "invalid_redirect_uri"})
            return
        self._send(201, {
            "client_id": "stub_client",
            "client_secret": "stub_secret",
            "client_id_issued_at": 0,
            "client_secret_expires_at": 0,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        })

    def log_message(self, *args):
        pass  # quiet


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8077
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
