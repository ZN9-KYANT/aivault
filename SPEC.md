# aivault — SPEC v1.0

An OpenAI-compatible API gateway with per-provider encrypted credential storage.

**Status:** Draft v1.0
**Language:** Go 1.23+ (single static binary, `aivault`, containing both server and CLI)

---

## 1. Overview

`aivault` is a local-first credential vault and API gateway for LLM providers.

- Credentials (API keys) are stored **one age-encrypted file per provider**.
- A long-running server (`aivault serve`) decrypts credentials into memory at unlock time and exposes an **OpenAI-compatible REST API** to downstream clients.
- A CLI (`aivault keys|providers|unlock|...`) manages the vault, providers, sessions, and proxy keys.
- Downstream apps never see real provider credentials; they authenticate with **proxy keys** issued by the gateway.

### Non-goals (v1.0)

- No OAuth or other token-lifecycle support — the vault stores **static API keys only**.
  OAuth clients obtain and refresh their own tokens outside the vault and can bypass it
  entirely, so supporting them adds attack surface without benefit.
- No multi-user/team vault sharing, no Shamir splitting, no HSM/KMS integration.
- No request/response translation for non-OpenAI-compatible APIs (Anthropic Messages, Gemini native) — v1.1+.
- No GUI.

---

## 2. Architecture

```
                     ┌────────────────────────────────────────┐
   client apps ─────▶│  aivault serve (HTTP :8317)            │
   (proxy keys)      │  ┌──────────┐  ┌─────────────────────┐ │
                     │  │ router / │─▶│ provider registry   │ │
                     │  │ adapter  │  │ (openai, gemini, …) │ │
                     │  └──────────┘  └────────┬────────────┘ │
   aivault CLI ─────▶│  admin API     ┌────────▼────────────┐ │
   (session token)   │  (unix sock    │ in-memory keyring   │ │
                     │   + TCP opt)   │ (mlock, zeroized)   │ │
                     │                └────────┬────────────┘ │
                     └─────────────────────────┼──────────────┘
                                               │ unlock/lock
                                        ~/.aivault/vault/
                                        ├── openai.json.age
                                        ├── gemini.json.age
                                        └── ...
```

### Components

| Component | Responsibility |
|---|---|
| `aivault serve` | HTTP gateway, admin API, keyring, auto-lock |
| `aivault` CLI | All management: init, unlock, key/provider CRUD, proxy-key CRUD, status |
| Vault store | `~/.aivault/vault/<provider>.json.age` + `meta.json` (plaintext index) |
| Keyring | Decrypted credentials in memory only; Argon2id-derived master KEK held locked |
| Provider registry | Per-provider wire adapter: base URL, auth type, header injection, model prefix map |

---

## 3. Vault storage

### 3.1 Layout

```
~/.aivault/
├── config.toml              # server + CLI config (plaintext, 0600)
├── meta.json                # plaintext index (see 3.3) (0600)
├── proxykeys.json           # hashed proxy keys (0600)
├── audit.log                # append-only audit log (0600)
├── aivault.sock             # unix socket for local admin
└── vault/
    ├── openai.json.age
    ├── anthropic.json.age
    ├── gemini.json.age
    ├── grok.json.age
    ├── deepseek.json.age
    ├── openrouter.json.age
    ├── moonshot.json.age
    ├── minimax.json.age
    ├── nvidia.json.age
    └── ollama-cloud.json.age
```

All files mode `0600`; `~/.aivault` mode `0700`. Backups: `age`-encrypted tarball or
`aivault backup --out <file>` producing one combined `.age` archive.

### 3.2 Per-provider encrypted file

- **Format:** [age](https://age-encryption.org) v1, passphrase recipient (scrypt) using the
  master passphrase. Payload is UTF-8 JSON.
- **Name:** `vault/<provider-id>.json.age`. Provider IDs: `[a-z0-9][a-z0-9-]{0,31}`.
- Decryption is whole-file (age has no random access); per-provider files mean only
  the credential being written/rotated is re-encrypted.

### 3.3 Plaintext index (`meta.json`)

Contains NO secrets — only metadata so the CLI can list providers without unlocking:

```json
{
  "version": 1,
  "providers": {
    "openai": {
      "kind": "apikey",
      "base_url": "https://api.openai.com/v1",
      "key_hint": "sk-...x8Fz",
      "enabled": true,
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    },
    "anthropic": {
      "kind": "apikey",
      "base_url": "https://api.anthropic.com",
      "key_hint": "sk-...9c2A",
      "enabled": true,
      "created_at": "2026-01-02T00:00:00Z",
      "updated_at": "2026-01-02T00:00:00Z"
    }
  }
}
```

`key_hint` is only first-3/last-4 characters. Metadata leakage of provider *names*
is accepted (v1.0 is single-user, local-first).

### 3.4 Decrypted payload schema

```json
{
  "version": 1,
  "provider": "anthropic",
  "kind": "apikey | none",
  "apikey": { "key": "sk-...", "base_url": "…", "headers": {} },
  "none": { "base_url": "http://localhost:11434" }
}
```

Exactly one of `apikey` / `none` is populated per `kind`.

---

## 4. Unlock / auth model

### 4.1 Master passphrase & KDF

- Vault initialized via `aivault init`; user sets a **master passphrase** (min 12 chars,
  zxcvbn strength ≥ 3).
- Passphrase → **Argon2id** (m=64 MiB, t=3, p=4, 16-byte random salt) → 32-byte master KEK.
  Salt + KDF params are stored in `config.toml`.
- Vault files are encrypted with age's scrypt recipient using the **master passphrase
  itself** as the scrypt passphrase (per-file random work factor ≥ log2(18)).
- `config.toml` also stores a random **verifier blob** wrapped with the Argon2id KEK
  (AEAD). It is *not* the age passphrase, and vault files do not depend on it:
  `aivault unlock` derives the KEK, unwraps the blob, and confirms the passphrase in
  constant time without touching any vault file (unwrap failure = wrong passphrase).
- **Passphrase change:** `aivault passwd` re-encrypts every vault file (new scrypt
  recipient) and re-wraps the verifier blob under the new KEK.

### 4.2 Sessions

- `aivault unlock` prompts for the passphrase, verifies it, sends it over the unix
  socket to the server, which decrypts all enabled provider files into the in-memory
  keyring. Unlock state is **server-side**; the CLI holds only a session token.
- Auto-lock: keyring zeroized after configurable idle timeout (default 15 min) or
  immediately on `aivault lock`, SIGHUP, or server shutdown.
- Memory hygiene: keyring pages `mlock`'d (best effort, warn if unsupported);
  secret buffers zeroized; secrets never logged (global redaction filter).

### 4.3 CLI ↔ server auth

- Primary transport: unix socket `~/.aivault/aivault.sock` (peer-UID check).
- Optional TCP admin API guarded by a random 32-byte **admin token** stored in
  `config.toml` (`0600`), never printed after init.

### 4.4 Proxy keys (downstream clients)

- `aivault proxykey create --name app1 --providers openai,gemini --rpm 60 --max-usd/day 5`
- Returned once: `vk-<48 hex>`. Stored as SHA-256 hash in `proxykeys.json` with scopes
  (allowed providers/models), rate limits, and optional spend caps.
- Requests to the gateway use `Authorization: Bearer vk-...`.
- Keys can be listed, revoked, and rotated (`aivault proxykey revoke <id>`).

### 4.5 Audit log

Append-only JSONL: timestamp, event (`unlock`,`lock`,`key.add`,`key.use`,
`proxykey.create`,`auth.fail`), provider, proxy-key id, outcome. Secrets never logged.

---

## 5. Provider registry

Built-in providers (v1.0):

| ID | Kind(s) | Base URL | Notes |
|---|---|---|---|
| `openai` | apikey | api.openai.com/v1 | |
| `anthropic` | apikey | api.anthropic.com | |
| `gemini` | apikey | generativelanguage.googleapis.com | |
| `grok` | apikey | api.x.ai/v1 | OpenAI-compatible |
| `deepseek` | apikey | api.deepseek.com/v1 | OpenAI-compatible |
| `openrouter` | apikey | openrouter.ai/api/v1 | OpenAI-compatible |
| `moonshot` | apikey | api.moonshot.ai/v1 | OpenAI-compatible |
| `minimax` | apikey | api.minimax.io/v1 | OpenAI-compatible |
| `nvidia` | apikey | integrate.api.nvidia.com/v1 | NVIDIA NIM; OpenAI-compatible |
| `ollama-cloud` | apikey | ollama.com/v1 | OpenAI-compatible |
| custom | apikey, none | user-defined | `aivault provider add <id> --base-url …` |

Routing: model names are namespaced — `openai/gpt-5`, `gemini/gemini-3-pro`,
`deepseek/deepseek-chat`. `aivault providers models` lists cached `/models` per provider.
Optional per-proxy-key **aliases** map virtual names to provider/model chains with
failover: `best` → `[openai/gpt-5, gemini/gemini-3-pro]`.

---

## 6. HTTP API

### 6.1 OpenAI-compatible data plane (proxy keys)

- `POST /v1/chat/completions` — streaming (SSE) + non-streaming
- `POST /v1/responses`, `POST /v1/embeddings`, `GET /v1/models`
- Header/body passthrough with these rewrites:
  - `Authorization` replaced with the real credential per resolved provider
  - `model` rewritten per alias/failover chain
- Failover: on 429/5xx/timeout from provider N, try next in chain (configurable,
  default off).
- Errors normalized to OpenAI error JSON shape.

### 6.2 Admin plane (session/admin token)

`GET /v1admin/status`, `POST /v1admin/unlock`, `POST /v1admin/lock`,
CRUD for providers/keys/proxy-keys, `GET /v1admin/audit?tail=N`.

---

## 7. CLI surface

```
aivault init                       # create vault, set master passphrase
aivault serve [--port 8317] [--config …]
aivault unlock | lock | status
aivault passwd

aivault keys add <provider> [--key-stdin]     # store API key (never arg/echo)
aivault keys list                             # from meta.json, no unlock needed
aivault keys show <provider>                  # requires unlock; prints hint by default, --reveal for full
aivault keys remove <provider>
aivault keys rotate <provider> --key-stdin

aivault proxykey create|list|revoke …
aivault providers list|models|test <provider>|add …
aivault alias create <name> --chain openai/gpt-5,gemini/gemini-3-pro
aivault backup --out backup.age / aivault restore backup.age
aivault audit --tail 50
```

Security rules: secrets only via `--key-stdin`, interactive hidden prompt, or
`$AIVAULT_*_KEY` env (with warning); clipboard support `--clipboard` with 45 s timeout.

---

## 8. Security requirements (v1.0 checklist)

1. age v1 + scrypt for at-rest; Argon2id KEK derivation; constant-time passphrase check.
2. All vault files `0600`, dir `0700`; creation via O_EXCL, atomic rename on update.
3. Keyring in memory only; `mlock` best-effort; zeroize on lock/exit; no swap of secrets
   where avoidable.
4. Redaction filter on all log sinks — known secret values and `sk-*`/`Bearer *` patterns.
5. Downstream proxy keys stored hashed (SHA-256), constant-time compare.
6. Audit log for every key use, unlock/lock, auth failure.
7. TLS: gateway data plane HTTP on loopback by default; non-loopback binds require
   `--tls-cert/--tls-key`.
8. Rate limiting + per-proxy-key spend caps (token-based estimation table in config).
9. Dependencies pinned; `go vet`, `staticcheck`, `govulncheck` in CI; age/crypto deps
   audited.

---

## 9. Testing & acceptance criteria

- Unit: KDF, vault encrypt/decrypt round-trip, atomic writes, redaction filter,
  alias resolution, failover ordering.
- Integration: mock provider servers (httptest) covering 200/stream/429/failover.
- E2E: `init → keys add → unlock → chat completion via curl → lock → 401 from gateway`.
- Acceptance: single static binary; zero secrets on disk in plaintext at any point;
  cold-start to serving < 2 s after unlock; streaming TTFT overhead < 5 ms vs direct.

---

## 10. Roadmap

- **v1.0** — as specified above.
- **v1.1** — Anthropic Messages & Gemini native translation shims; usage/cost dashboard.
- **v1.2** — OS keychain-wrapped passphrase; auto-unlock on login; YubiKey unlock.
- **v2.0** — Multi-user vaults, Shamir unlock, remote KMS, HA (shared encrypted store).