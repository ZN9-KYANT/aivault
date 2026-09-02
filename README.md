# aivault

An OpenAI-compatible API gateway with per-provider encrypted credential storage.

`aivault` stores LLM provider API keys in an age-encrypted local vault
(`~/.aivault`) and exposes them to downstream apps through an
OpenAI-compatible gateway. Clients authenticate with per-app proxy keys and
never see the real credentials.

**Status:** specification + scaffold. See [SPEC.md](SPEC.md) for the full design.

## Build

```
go build ./cmd/aivault
```

Requires Go 1.23+. CI runs `go vet`, `staticcheck`, and `govulncheck` (SPEC 8.9).

## Layout

| Path | Responsibility (SPEC) |
|---|---|
| `cmd/aivault` | entry point, single binary (§1) |
| `internal/vault` | age-encrypted per-provider files + meta.json index (§3) |
| `internal/kdf` | Argon2id KEK + config.toml verifier blob (§4.1) |
| `internal/keyring` | in-memory decrypted credential store (§4.2) |
| `internal/config` | config.toml load/save (§3.1) |
| `internal/proxykey` | hashed downstream keys, scopes, limits (§4.4) |
| `internal/audit` | append-only JSONL audit log (§4.5) |
| `internal/provider` | built-in provider registry (§5) |
| `internal/server` | gateway data plane + admin plane (§6) |
| `internal/cli` | command tree (§7) |

## Security notes

- Vault files are age v1 (scrypt recipient) — one file per provider,
  decrypted only into memory at unlock time.
- Proxy keys are stored as SHA-256 hashes and compared in constant time.
- OAuth is intentionally unsupported: the vault stores static API keys only.
- Never log or commit secrets; `.gitignore` blocks `*.age`, `*.key`, `.env`.