# aivault

[English](README.md) | [日本語](README.ja.md)

An OpenAI-compatible API gateway with per-provider encrypted credential storage.

`aivault` stores LLM provider API keys in an age-encrypted local vault
(`~/.aivault`) and exposes them to downstream apps through an
OpenAI-compatible gateway. Clients authenticate with per-app proxy keys and
never see the real credentials. One Go binary contains both the server and
the CLI.

**Status:** v1.0 — fully implemented. Design details live in [SPEC.md](SPEC.md);
code comments reference its sections as `SPEC <n>`.

---

## Why

- Apps and scripts need provider keys, but pasting `sk-…` keys into configs,
  shells, and CI leaks them.
- aivault keeps each key in its own age-encrypted file, decrypts into memory
  only while the gateway is unlocked, and hands clients a **revocable proxy
  key** (`vk-…`) instead of the real credential.
- Per-key rate limits and daily spend caps, alias failover chains, an
  append-only audit log, and secret redaction on every error path.

## Features

- **Encrypted vault** — one `age` v1 (scrypt) file per provider, unlocked by a
  master passphrase (Argon2id m=64 MiB t=3 p=4 verifier blob; passphrase is
  verified *before* any vault file is touched).
- **OpenAI-compatible gateway** — `/v1/chat/completions` (streaming + non-
  streaming), `/v1/responses`, `/v1/embeddings`, `/v1/models`, loopback-only.
- **Proxy keys** — SHA-256-hashed downstream credentials with provider scoping,
  per-key RPM, and per-key daily USD caps. Revocation is instant.
- **Aliases with failover** — virtual model names mapped to provider chains;
  retry the next entry on 429/5xx/timeout (opt-in).
- **Hardening** — global secret redaction in error text and audit output,
  idle auto-lock (default 15 min), spend estimation from upstream `usage`
  blocks, encrypted backup/restore.
- **No OAuth** — the vault stores static API keys only, by design.

## Build

```bash
go build -o aivault ./cmd/aivault        # Windows: aivault.exe
```

Requires the Go version in `go.mod`. CI runs `go vet`, tests, `staticcheck`,
and `govulncheck` (SPEC 8.9).

## Quickstart

```bash
# 1. Create the vault (sets a master passphrase, min 12 chars, zxcvbn >= 3)
aivault init

# 2. Store a provider key — hidden prompt, --key-stdin, or env var; never an argument
aivault keys add openai
# non-interactive alternative (consumes all of stdin):
printf '%s' "$OPENAI_API_KEY" | aivault keys add openai --key-stdin

# 3. Mint a proxy key for an app (plaintext shown exactly once)
aivault proxykey create --name myapp --providers openai --rpm 60 --max-usd/day 5

# 4. Start the gateway (loopback only, default port 8317) and unlock
aivault serve &
aivault unlock          # prompts for the master passphrase

# 5. Use it like OpenAI — model ids are namespaced provider/model
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-YOURPROXYKEY" \
  -d '{"model":"openai/gpt-5","messages":[{"role":"user","content":"hello"}]}'

# 6. Lock when done (keyring is zeroized; gateway answers 503 until re-unlock)
aivault lock
```

## CLI reference

Global flag: `--home <dir>` overrides the `~/.aivault` home (used for tests).
Secrets are only ever accepted via hidden prompt, `--key-stdin`, or
`$AIVAULT_<PROVIDER>_KEY` (uppercase provider id, prints a warning) — never as
a command-line argument.

### Vault & session

| Command | Purpose |
|---|---|
| `aivault init` | Create the vault, set the master passphrase |
| `aivault passwd` | Change the master passphrase (re-encrypts every vault file) |
| `aivault serve [--port 8317]` | Run the gateway; admin plane on `~/.aivault/aivault.sock` |
| `aivault unlock` | Verify passphrase, decrypt all enabled providers into the server keyring |
| `aivault lock` | Zeroize the server keyring immediately |
| `aivault status` | Vault status + live gateway status (locked/unlocked, providers, socket) |

`passwd` decrypts **all** vault files before writing anything: a bad file aborts
with no changes. Auto-lock idle timeout defaults to 15 minutes
(`auto_lock_minutes` in `config.toml`, `0` disables); only keyring-using
requests reset the idle timer, so status/audit polling cannot pin the vault
unlocked.

### Keys

| Command | Purpose |
|---|---|
| `aivault keys add <provider>` | Store/replace an API key (hidden prompt by default) |
| `aivault keys list` | Table from `meta.json` — hints only, **no unlock needed** |
| `aivault keys show <provider>` | Print the key hint; `--reveal` decrypts and prints the full key |
| `aivault keys rotate <provider>` | Replace the key, preserving base URL and custom headers |
| `aivault keys remove <provider>` | Delete the stored key (asks y/N; custom providers lose their registration) |

```bash
aivault keys add deepseek                          # hidden prompt
printf '%s' "$KEY" | aivault keys add deepseek --key-stdin
AIVAULT_DEEPSEEK_KEY="sk-..." aivault keys add deepseek   # env var (warns)
aivault keys show openrouter                       # hint only
aivault keys show openrouter --reveal              # full key (decrypted)
aivault keys rotate nvidia                         # swap the key, keep the provider config
```

### Providers

| Command | Purpose |
|---|---|
| `aivault providers list` | Registered providers from `meta.json` (no unlock needed) |
| `aivault providers add <id> --base-url <url>` | Register a custom provider (built-in IDs are reserved) |
| `aivault providers test <id>` | Live `GET /models` with the stored credential; reports model count |
| `aivault providers models` | Live model catalog per enabled OpenAI-compatible provider |

```bash
aivault providers add myprovider --base-url https://api.myprovider.com/v1
aivault keys add myprovider
aivault providers test nvidia        # "nvidia: OK — https://… reachable, 82 models"
aivault providers models             # model catalogs across providers
```

A registered custom provider that has **not** been keyed yet becomes kind
`none` and is routed **credential-free** — handy for local OpenAI-compatible
servers (e.g. `aivault providers add local-ollama --base-url http://localhost:11434/v1`).

Provider IDs match `[a-z0-9][a-z0-9-]{0,31}`.

### Proxy keys (downstream clients)

| Command | Purpose |
|---|---|
| `aivault proxykey create --name <name> [--providers …] [--rpm N] [--max-usd/day N]` | Issue a proxy key (`vk-<48 hex>`, shown exactly once) |
| `aivault proxykey list` | Hashes only — plaintext is never recoverable |
| `aivault proxykey revoke <id-or-name>` | Revoke immediately, **no unlock needed** (reload-per-request) |

```bash
aivault proxykey create --name ci --providers openai,openrouter --rpm 120 --max-usd/day 2
aivault proxykey list
aivault proxykey revoke ci
```

Empty `--providers` scope means all registered providers. RPM uses a rolling
window (rejected requests don't count); spend caps use the UTC day, estimated
from upstream `usage` when present, else `chars/4` (non-stream) / `bytes/4`
(stream) priced via the `[spend]` table — caps reset when the server restarts.

### Aliases & failover

```bash
# virtual model name -> chain of provider/model entries, tried in order
aivault alias create best --chain "openai/gpt-5,openrouter/openai/gpt-5:free"
aivault alias create cheap --chain "groq/llama-3.3-70b-versatile,openrouter/meta-llama/llama-3.3-70b-instruct:free"
aivault alias list
aivault alias remove cheap
```

Then `"model":"best"` resolves the chain **before** namespace splitting.
Failover (next entry on 429/5xx/timeout, and on pre-flight errors) requires
`failover = true` in `config.toml` (default **off**). Streaming responses are
not retried once headers have been sent; the proxy key's provider scope is
enforced across every chain entry.

### Backup, restore, audit

```bash
aivault backup --out vault-backup.age   # one age-encrypted tar of the whole home
aivault restore vault-backup.age        # confirm + passphrase; refuses clobbers
aivault restore vault-backup.age --force
aivault audit --tail 50                 # append-only audit log (display redacted)
aivault audit --tail 100 --json         # raw JSONL
```

Backups are encrypted under the master passphrase (verified before writing).
Restore refuses to clobber existing files without `--force`; the restored vault
uses the backup's passphrase. Audited events: `unlock`, `lock`, `key.add`,
`key.remove`, `key.rotate`, `key.use`, `proxykey.create`, `provider.add`,
`passwd`, `auth.fail`.

## Gateway API

Base URL: `http://127.0.0.1:8317` (loopback-only; TLS for non-loopback binds is
planned — SPEC 8.7). Auth: `Authorization: Bearer vk-…`.

| Endpoint | Notes |
|---|---|
| `POST /v1/chat/completions` | streaming (SSE, chunk-flushed) + non-streaming |
| `POST /v1/responses` | OpenAI Responses API passthrough |
| `POST /v1/embeddings` | |
| `GET /v1/models` | per-provider catalogs, ids namespaced `provider/model`, 10-min cache (cleared on unlock) |

```bash
# non-streaming
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/gpt-5","messages":[{"role":"user","content":"hi"}]}'

# streaming
curl -N http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# embeddings
curl http://127.0.0.1:8317/v1/embeddings \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/text-embedding-3-small","input":"hello"}'

# model list (namespaced ids: "openai/gpt-5", "nvidia/gpt-oss-20b", ...)
curl http://127.0.0.1:8317/v1/models -H "Authorization: Bearer vk-..."
```

Routing: `<provider>/<model>` is split at the **first** slash (openrouter-style
nested ids keep the rest); the body `model` is rewritten to the bare model id;
`Authorization` is replaced with the real per-provider credential; custom
payload headers are forwarded.

### Error shapes

| Status | Meaning |
|---|---|
| `401` | unknown / malformed / revoked proxy key (OpenAI error shape) |
| `403` | proxy key not scoped for the resolved provider |
| `429` `rate_limit_error` | proxy-key RPM exceeded (rejected requests don't count) |
| `429` `spend_cap_reached` | proxy-key daily USD cap reached (checked before forwarding) |
| `503` `gateway_locked` | vault is locked — unlock and retry |
| `4xx/5xx` | upstream errors pass through when already OpenAI-shaped, else wrapped (`upstream_request_error` / `api_error`) |

Bodies are capped at 16 MiB; non-streaming requests have a 120 s deadline.
Native anthropic/gemini protocols are not proxied yet (v1.1 shims) and return
`400`; their keys still store/rotate fine in the vault.

## Configuration (`~/.aivault/config.toml`)

```toml
port = 8317
auto_lock_minutes = 15
failover = false          # retry next alias chain entry on 429/5xx/timeout

[spend]                   # cost estimation for proxy-key spend caps
input_usd_per_1m = 0.5
output_usd_per_1m = 1.5

[[spend.model_prices]]    # prefix overrides, first match wins
prefix = "openai/gpt-5"
input_usd_per_1m = 1.25
output_usd_per_1m = 10.0
```

The rest of the file (KDF params, verifier blob, admin token) is managed by
aivault — don't edit it by hand.

## Security model

- age v1 (scrypt recipient, master passphrase) per provider file; payload is
  JSON, decrypted whole-file into memory only at unlock.
- Argon2id (m=64 MiB, t=3, p=4, 16 B salt) derives the KEK that wraps a random
  verifier blob — wrong passphrases are rejected constant-time **before** any
  vault file is decrypted.
- Atomic writes (`O_EXCL` tmp + rename), all files `0600`, home `0700`.
- Proxy keys stored as SHA-256 digests only, constant-time compared.
- Redaction filter (SPEC 8.4) scrubs `Bearer`/`sk-`/`vk-`/`nvapi-`/`AIza`/`gsk_`/`xai-`
  patterns **and** the runtime-registered literal keys from every error message
  and audit display — provider error bodies are shown redacted.
- Idle auto-lock, lock on SIGHUP/shutdown, best-effort zeroize of secret
  buffers; secrets never logged.
- `.gitignore` blocks `*.age`, `*.key`, `.env`. OAuth is intentionally
  unsupported (static API keys only).

## Vault home layout

```
~/.aivault/
├── config.toml        # server config + KDF params + verifier blob (0600)
├── meta.json          # plaintext index: providers, hints, aliases (no secrets)
├── proxykeys.json     # proxy-key SHA-256 digests (0600)
├── audit.log          # append-only JSONL (0600)
├── aivault.sock       # AF_UNIX admin socket (removed on every exit path)
└── vault/
    ├── openai.json.age
    ├── nvidia.json.age
    └── …              # one age file per provider
```

## Built-in providers

| ID | Base URL | Gateway-compatible |
|---|---|---|
| `openai` | `api.openai.com/v1` | yes |
| `grok` | `api.x.ai/v1` | yes |
| `deepseek` | `api.deepseek.com/v1` | yes |
| `openrouter` | `openrouter.ai/api/v1` | yes |
| `moonshot` | `api.moonshot.ai/v1` | yes |
| `minimax` | `api.minimax.io/v1` | yes |
| `nvidia` | `integrate.api.nvidia.com/v1` | yes |
| `ollama-cloud` | `ollama.com/v1` | yes |
| `anthropic` | `api.anthropic.com` | vault-only until v1.1 shims |
| `gemini` | `generativelanguage.googleapis.com` | vault-only until v1.1 shims |
| *(custom)* | user-defined via `providers add` | any OpenAI-compatible base URL |

## Development

```
go build ./... && go vet ./...
go test ./...        # vault tests take ~24s (age scrypt wf>=18) — expected
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

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
| `internal/redact` | secret redaction filter (§8.4) |
| `internal/server` | gateway data plane + admin plane (§6) |
| `internal/cli` | command tree (§7) |

## Status & roadmap

v1.0 is feature-complete (SPEC §9 acceptance incl. a real-provider E2E passed).
Known accepted deferrals: TCP admin plane, admin-plane CRUD endpoints,
mlock/memory hygiene beyond best-effort zeroize, TLS for non-loopback binds,
`keys --clipboard`, native anthropic/gemini shims (v1.1), failover for non-alias
requests, spend persistence across server restarts.

Roadmap (SPEC §10): v1.1 translation shims + usage/cost dashboard; v1.2 OS
keychain passphrase / auto-unlock / YubiKey; v2.0 multi-user vaults.