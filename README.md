# PocketID MCP-AS Contract

The shared contract for **self-hosted MCP OAuth 2.1 Authorization Servers that
federate login to PocketID**, across `carpenike`'s projects.

Several apps each embed their own small OAuth Authorization Server so MCP
clients (claude.ai Custom Connectors, the VS Code MCP HTTP transport, etc.) can
authenticate directly against the app's `/api/mcp` surface — no `mcp-remote`,
no external broker. They were built by copying a production-proven design from
one to the next, and they drift. This repo is the **single source of truth**
that keeps them aligned.

It is deliberately **not a library**. The four implementations span three
languages (Go, TypeScript, Python) and two legitimately different token models,
so shared *code* can't span them. What they share is a *contract*: the
discovery shapes, the federation flow, and the security invariants. That is
what lives here, in two enforceable forms:

| Artifact | Audience | Job |
| --- | --- | --- |
| [`CONTRACT.md`](./CONTRACT.md) | humans | the spec — core rules, token profiles, scope postures |
| [`contract.json`](./contract.json) | machines | the same rules as data a CI check can fetch + diff against |
| [`conformance/check.sh`](./conformance/check.sh) | CI | hits a live AS and asserts it matches the contract |

## How a build "references" the contract

Each implementation declares, in its README/CI, the **version + profile + scope
posture** it conforms to, e.g.:

> Conforms to `pocketid-mcp-as` **v1.0**, profile **opaque-no-refresh**, scope **mcp-only**.

Then runs the conformance check against its own running server in CI:

```sh
conformance/check.sh https://replog.holthome.net opaque-no-refresh mcp-only
```

The check fetches the live `.well-known` documents + does a DCR round-trip and
fails on any divergence from `contract.json`. That is the part with teeth — a
doc nobody runs is exactly how the field omissions this repo exists to prevent
crept in originally.

## Known conformers

| Project | Lang | Profile | Scope | Notes |
| --- | --- | --- | --- | --- |
| `replog` | Go | opaque-no-refresh | mcp-only | dedicated `mcp_tokens` store |
| `whiskey-whiskey-whiskey` | TS | opaque-no-refresh | shared-pat | reuses the generic PAT store |
| `marginalia` | TS | opaque-no-refresh | shared-pat | verbatim port of W.W.W. |
| `homelab-mcp` | Python | jwt-refresh | mcp-only | RS256 + rotating refresh tokens |

## Versioning

`CONTRACT.md` and `contract.json` are versioned with semver and move together.
Breaking a required field, the allowlist, or a flow step is a MAJOR bump.
Additive, backward-compatible clarifications are MINOR. Each conformer pins the
version it targets.
