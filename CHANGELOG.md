# Changelog

All notable changes to aivault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
versions with [SemVer](https://semver.org/) (`aivault version` / `--version`).
Japanese version of the docs: [README.ja.md](README.ja.md).

## [Unreleased]

Planned backlog (learned from the pi-llm-gateway comparison — see
`HANDOFF.md` session notes):

- memguard-protected keyring (SPEC 8.3) on top of the existing core-dump
  hardening
- TLS/mTLS for non-loopback binds (SPEC 8.7), paired with the brute-force
  guard's multi-machine deployment use case
- Optional headless identity unlock (v1.2 debate: age X25519 recipient with
  identity from file/env/secret-manager command)
- Native anthropic/gemini translation shims (SPEC 10)

## [v1.2.0] — 2026-09-30

Batch B, applying the remaining quick-to-mid hardening lessons from the
[pi-llm-gateway](https://github.com/trork-code/pi-llm-gateway) comparison.

### Added

- **Egress allowlist** (`b94371d`-style feature, new commit) — new
  `internal/egress`: upstream provider connections are pinned at the dial
  layer to the hostnames of registered providers (from `meta.json` plus any
  overriding decrypted payload base URLs, refreshed at server start and on
  each unlock). HTTP redirects are re-validated because every dial goes
  through the guard, and the CLI's `providers test`/`providers models`
  probes are pinned the same way. A tampered or rogue base URL can no
  longer exfiltrate a live credential. New config knob
  `egress_allowlist` (default `true`). Tests: block/allow/redirect
  re-validation/disable/sanitize state, plus a gateway-level
  exfiltration-block test.
- **Startup permission verification** — `vault.CheckPerms` (POSIX;
  documented no-op on Windows where Stat cannot see NTFS ACLs) refuses to
  `serve`, `unlock`, or pass `doctor` when the vault home, its files, or
  the `vault/` subtree carry group/world permissions. Error output names
  each offending path with a chmod hint. (`permissions_unix.go` + `_windows.go`)
- **Brute-force guard** — failed data-plane authentications are counted per
  peer IP in a rolling one-minute window; past `auth_max_failures` (new
  config knob, default 20, `0` disables) further attempts receive
  `429 auth_rate_limited` (OpenAI shape) *before* further key checks —
  including otherwise-valid keys — until the window drains. Audited as
  `auth.fail` (backoff events included). Tests: exact threshold, valid-key
  backoff, disabled mode.
- **`aivault doctor`** — one-command vault health report, no unlock needed
  (the analogue of pi-llm-gateway's `-check` preflight): config parse +
  knobs, meta/vault-file agreement (dangling entries, ghost files), file
  permissions, proxy keys (active/revoked), audit chain verification with
  entry counts, key ages vs `key_max_age_days`, and the live gateway state.
  `PASS`/`WARN`/`FAIL` verdict line; FAIL exits non-zero for scripts.

### Changed

- `aivault serve` prints the egress-allowlist state at startup and verifies
  file permissions before listeners come up.

### Docs

- README (EN + JA): `doctor` in the backup/audit section, the two new
  config knobs in the config reference, and egress/permissions/brute-force
  in the security model. CHANGELOG entries for this release.

## [v1.1.0] — 2026-09-30

Hardening batch A, applied after studying the
[pi-llm-gateway](https://github.com/trork-code/pi-llm-gateway) project.

### Added

- **Model aliases in `GET /v1/models`** — gateway aliases from `meta.json`
  now appear next to the real provider catalogs as
  `{"id": "<alias>", "owned_by": "alias"}`, sorted. An alias is listed only
  when the requesting proxy key's provider scope covers **every** link of
  its failover chain (matching the per-chain scope enforcement in routing).
  Clients (pi's native model picker) can thereby offer provider switches
  with zero client-config changes: virtual names resolve gateway-side.
  (`b94371d`, tests `TestModelsEndpointAliases`, `TestModelsEndpointAliasesScopedOut`)
- **Tamper-evident audit log** — audit entries are now hash-chained:
  each entry carries `prev` (the previous logged entry's ID) and
  `id = SHA-256(prev + canonical entry content)`. Edits or deletions break
  the chain. Pre-v1.1 entries are carried as **legacy** (no ID) and the
  chain starts at the first chained entry, so existing logs verify cleanly.
  In-process writes are mutex-serialized; cross-process interleaving (CLI
  while the server writes) is documented and reported as a detected break.
  (`a073e85`)
- **`aivault audit --verify`** — walks the full log, reports
  `entries / chained / legacy` and `OK`, and exits non-zero on the first
  broken link (tamper/deletion). (`a073e85`)
- **Key-age warnings** — new `key_max_age_days` config knob (default `90`,
  `0` disables): `aivault status` prints a rotation warning per provider
  whose stored key is older than the limit (based on the key's meta
  `UpdatedAt`; `none`-kind providers are skipped). Rotating a key resets
  the clock. (`d2074d1`)
- **gitleaks in CI** — full-history secret scanning now runs on every push
  and PR alongside vet/tests/staticcheck/govulncheck. (`d8f702b`)

### Security

- **Core dumps disabled at `serve` startup** — unix sets `RLIMIT_CORE=0`
  before listeners come up (warning, non-fatal, on failure); Windows is a
  documented no-op (WER-policy territory). Closes the crash-dump path for
  keyring memory ahead of the memguard milestone (SPEC 8.3). (`bfe88c6`)
- Verified (already handled): streaming requests derive the upstream
  context from `r.Context()`, so **client disconnects cancel upstream
  calls** — no billing leak when an SSE consumer goes away.

### Docs

- README (EN + JA) updated: aliases in `/v1/models`, audit-chain section
  with `audit --verify`, `key_max_age_days` in the config reference, core
  dumps + gitleaks in the security model. (`1e7e309`)

## [v1.0.1] — 2026-09-30

### Added

- **Per-provider model listing** — `aivault providers models <id>` (or the
  `--provider` flag) fetches and prints one provider's **full** live model
  catalog, one id per line; without an argument the cross-provider summary
  table (with a 3-model sample per provider) is unchanged. Argument and
  flag must agree; unknown/unkeyed providers fail with a clear error before
  any network call. (`5e10a54`)
- **Version machinery** — `internal/version` is the single source of truth
  (stampable via `-ldflags -X` with commit/date); `aivault version` and
  `aivault --version` print it; `aivault status` shows a version line for
  diagnostics. (`ad7ad84`)

### Changed

- Installed-binaries are now built with stripped symbols
  (`-ldflags "-s -w"`): 9.0 MB, down from 12.7 MB.

### Fixed

- **Provider probes now surface redacted upstream error bodies** — a failed
  `providers test`/`providers models` prints the provider's own error text
  (capped and redacted through the SPEC 8.4 filter, including
  runtime-registered literal keys), making server-side rejections such as
  tokenharbor's `email_verification_required` 403 diagnosable without
  leaking the stored credential. (`a61b796`, pre-release commit carried
  into v1.0.0/v1.0.1 binaries)

## [v1.0.0] — 2026-09-16

First stable release: all six v1.0 implementation milestones complete and
verified end-to-end (SPEC §9 acceptance, including a real-provider E2E
against NVIDIA NIM: 81 models listed, real chat completion + SSE stream,
lock → 503, revoke → 401).

### Added

- **Crypto core** — Argon2id KEK (m=64 MiB t=3 p=4, 16 B salt) + verifier
  blob: wrong master passphrases are rejected constant-time *before* any
  vault file is decrypted; one age-scrypt file per provider; zxcvbn
  passphrase policy (12+ chars, score ≥ 3); best-effort zeroization.
- **Vault CLI** — `init`, `keys add/list/show/remove/rotate`
  (`--key-stdin` / hidden prompt / env var, never as an argument),
  `passwd` (all-files-verified-then-re-encrypted), `providers add/list`.
- **Gateway server** — `aivault serve`: AF_UNIX admin plane
  (status/unlock/lock/audit) with fail-safe unlock (a partial decrypt never
  swaps the keyring), idle auto-lock (default 15 min; only keyring-using
  requests reset the timer), lock on `aivault lock`/SIGHUP/shutdown.
- **Data plane** — OpenAI-compatible gateway on loopback:8317: proxy-key
  auth (SHA-256 digests, constant-time, scope → 403, revoke-effective
  immediately), `POST /v1/chat/completions` (SSE + non-stream),
  `/v1/responses`, `/v1/embeddings`, `GET /v1/models`; `<provider>/<model>`
  routing with first-slash split, credential rewrite, custom header
  forwarding, upstream error normalization, 16 MiB cap, 120 s non-stream
  deadline.
- **Hardening** — per-proxy-key RPM (rolling window) and daily USD spend
  caps (usage-based estimate, `[spend]` price table); alias chains with
  opt-in failover on 429/5xx/timeout (`failover = true`); redaction filter
  on every error/display path; age-encrypted `backup`/`restore` of the
  whole vault home; `providers test <id>` live credential checks;
  append-only JSONL audit log.
- **Docs** — full command reference + gateway cookbook in
  [README.md](README.md) and Japanese [README.ja.md](README.ja.md).
- **CI** — go vet, build, tests, staticcheck, govulncheck (SPEC 8.9).

### Deliberate limitations (documented)

- `aivault lock` returns **`503 gateway_locked`** (not the "401"
  literally written in SPEC 9's acceptance line) — the proxy key stays
  valid, so 503 is semantically right.
- Loopback-only binds until TLS (SPEC 8.7); native anthropic/gemini
  protocols are vault-only until the v1.1 shims (SPEC 10); no OAuth, ever
  (static API keys only).

[v1.2.0]: https://github.com/ZN9-KYANT/aivault/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/ZN9-KYANT/aivault/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/ZN9-KYANT/aivault/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/ZN9-KYANT/aivault/releases/tag/v1.0.0