# aivault

[English](README.md) | [日本語](README.ja.md)

プロバイダーごとの暗号化クレデンシャルストレージを備えた、OpenAI 互換 API ゲートウェイ。

`aivault` は LLM プロバイダーの API キーを age で暗号化されたローカル vault
(`~/.aivault`) に保存し、OpenAI 互換ゲートウェイを通じて下流アプリへ公開します。
クライアントはアプリごとのプロキシキーで認証するため、実際のクレデンシャルは
決して見えません。サーバーと CLI は 1 つの Go バイナリにまとまっています。

**ステータス:** v1.0 — 実装完了。設計の詳細は [SPEC.md](SPEC.md) を参照
(コードコメントでは `SPEC <n>` として該当節を参照しています)。

---

## なぜ aivault か

- アプリやスクリプトはプロバイダーキーを必要としますが、`sk-…` キーを設定
  ファイルやシェル、CI に貼り付けると漏洩します。
- aivault は各キーを独立した age 暗号化ファイルに保存し、ゲートウェイの
  アンロック中だけメモリに復号し、クライアントには本物のクレデンシャルでは
  なく**失効可能なプロキシキー** (`vk-…`) を渡します。
- キーごとのレート制限と日次支出上限、エイリアスフェイルオーバーチェーン、
  追記型監査ログ、すべてのエラー経路でのシークレット墨消し (redaction)。

## 機能

- **暗号化 vault** — プロバイダーごとに 1 ファイルの `age` v1 (scrypt)。
  マスターパスフレーズでアンロック (Argon2id m=64 MiB t=3 p=4 のベリファイア
  ブロブ。パスフレーズは vault ファイルに触る**前**に検証されます)。
- **OpenAI 互換ゲートウェイ** — `/v1/chat/completions` (ストリーミング +
  非ストリーミング)、`/v1/responses`、`/v1/embeddings`、`/v1/models`。
  ループバック限定。
- **プロキシキー** — SHA-256 ハッシュで保存される下流クレデンシャル。
  プロバイダースコープ、キーごとの RPM、日次 USD 上限つき。失効は即時。
- **フェイルオーバーつきエイリアス** — 仮想モデル名をプロバイダーチェーンに
  マッピング。429/5xx/タイムアウトで次のエントリをリトライ (オプトイン)。
- **ハードニング** — エラーテキストと監査出力での全体シークレット墨消し、
  アイドル自動ロック (既定 15 分)、上流 `usage` ブロックによる支出推定、
  暗号化バックアップ/リストア。
- **OAuth 非対応** — vault は静的 API キーのみを扱います (設計方針)。

## ビルド

```bash
go build -o aivault ./cmd/aivault        # Windows: aivault.exe
```

必要な Go バージョンは `go.mod` を参照。CI では `go vet`・テスト・
`staticcheck`・`govulncheck` を実行します (SPEC 8.9)。

## クイックスタート

```bash
# 1. vault を作成 (マスターパスフレーズを設定: 12 文字以上・zxcvbn >= 3)
aivault init

# 2. プロバイダーキーを保存 — 隠蔽プロンプト / --key-stdin / 環境変数のいずれか
#    (引数で渡すことはできません)
aivault keys add openai
# 非対話の代替 (stdin 全消費):
printf '%s' "$OPENAI_API_KEY" | aivault keys add openai --key-stdin

# 3. アプリ用プロキシキーを発行 (平文は 1 回だけ表示)
aivault proxykey create --name myapp --providers openai --rpm 60 --max-usd/day 5

# 4. ゲートウェイを起動 (ループバック限定・既定ポート 8317) してアンロック
aivault serve &
aivault unlock          # マスターパスフレーズをプロンプトで入力

# 5. OpenAI と同じように使う — モデル ID は provider/model 形式
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-YOURPROXYKEY" \
  -d '{"model":"openai/gpt-5","messages":[{"role":"user","content":"hello"}]}'

# 6. 使い終わったらロック (キーリングはゼロ化。再アンロックまで 503 を返す)
aivault lock
```

## CLI リファレンス

グローバルフラグ: `--home <dir>` で `~/.aivault` の代わりのホームを指定
(テスト用)。シークレットは隠蔽プロンプト、`--key-stdin`、
`$AIVAULT_<PROVIDER>_KEY` (大文字のプロバイダー ID、警告を表示) のいずれかで
のみ受け付けます。**コマンドライン引数では絶対に渡しません。**

### Vault とセッション

| コマンド | 目的 |
|---|---|
| `aivault init` | vault を作成し、マスターパスフレーズを設定 |
| `aivault passwd` | マスターパスフレーズを変更 (全 vault ファイルを再暗号化) |
| `aivault serve [--port 8317]` | ゲートウェイを起動。管理プレーンは `~/.aivault/aivault.sock` |
| `aivault unlock` | パスフレーズを検証し、有効な全プロバイダーをサーバーのキーリングへ復号 |
| `aivault lock` | サーバーのキーリングを即座にゼロ化 |
| `aivault status` | vault 状態 + ゲートウェイのライブ状態 (ロック状態・プロバイダー・ソケット) |

`passwd` は書き込む**前に**すべての vault ファイルを復号します。不正な
ファイルがあれば変更なしで中断します。自動ロックのアイドルタイムアウトは
既定 15 分 (`config.toml` の `auto_lock_minutes`、`0` で無効)。キーリングを
使うリクエストのみアイドルタイマーをリセットするため、status/audit の
ポーリングで vault がアンロック状態に固定されることはありません。

### キー

| コマンド | 目的 |
|---|---|
| `aivault keys add <provider>` | API キーを保存/置換 (既定は隠蔽プロンプト) |
| `aivault keys list` | `meta.json` からの表表示 — ヒントのみ、**アンロック不要** |
| `aivault keys show <provider>` | キーヒントを表示。`--reveal` で復号して全キーを表示 |
| `aivault keys rotate <provider>` | ベース URL とカスタムヘッダーを保したままキーを置換 |
| `aivault keys remove <provider>` | 保存済みキーを削除 (y/N 確認。カスタムプロバイダーは登録も削除) |

```bash
aivault keys add deepseek                          # 隠蔽プロンプト
printf '%s' "$KEY" | aivault keys add deepseek --key-stdin
AIVAULT_DEEPSEEK_KEY="sk-..." aivault keys add deepseek   # 環境変数 (警告あり)
aivault keys show openrouter                       # ヒントのみ
aivault keys show openrouter --reveal              # 全キー (復号)
aivault keys rotate nvidia                         # プロバイダー設定はそのままにキーを交換
```

### プロバイダー

| コマンド | 目的 |
|---|---|
| `aivault providers list` | `meta.json` から登録済みプロバイダーを表示 (アンロック不要) |
| `aivault providers add <id> --base-url <url>` | カスタムプロバイダーを登録 (組み込み ID は予約済み) |
| `aivault providers test <id>` | 保存済みクレデンシャルで `GET /models` を実行。モデル数を報告 |
| `aivault providers models` | 有効な OpenAI 互換プロバイダーごとにモデルカタログを取得 |

```bash
aivault providers add myprovider --base-url https://api.myprovider.com/v1
aivault keys add myprovider
aivault providers test nvidia        # "nvidia: OK — https://… reachable, 82 models"
aivault providers models             # プロバイダー横断のモデルカタログ
```

登録済みだが**未キー登録**のカスタムプロバイダーは kind `none` になり、
**クレデンシャルなし**でルーティングされます。OpenAI 互換のローカルサーバー
に便利です (例: `aivault providers add local-ollama --base-url http://localhost:11434/v1`)。

プロバイダー ID は `[a-z0-9][a-z0-9-]{0,31}` に一致します。

### プロキシキー (下流クライアント)

| コマンド | 目的 |
|---|---|
| `aivault proxykey create --name <name> [--providers …] [--rpm N] [--max-usd/day N]` | プロキシキーを発行 (`vk-<48 hex>`、平文は 1 回だけ表示) |
| `aivault proxykey list` | ハッシュのみ表示 — 平文は二度と取り出せません |
| `aivault proxykey revoke <id-or-name>` | 即時失効、**アンロック不要** (リクエストごとに再読込) |

```bash
aivault proxykey create --name ci --providers openai,openrouter --rpm 120 --max-usd/day 2
aivault proxykey list
aivault proxykey revoke ci
```

`--providers` を空にすると登録済み全プロバイダーがスコープになります。RPM は
スライディングウィンドウ (拒否されたリクエストはカウントしない)。支出上限は
UTC 日単位で、上流の `usage` があればそれを、無ければ `chars/4` (非ストリー
ミング) / `bytes/4` (ストリーミング) を `[spend]` テーブルの単価で概算します。
上限はサーバー再起動でリセットされます。

### エイリアスとフェイルオーバー

```bash
# 仮想モデル名 -> 順番に試行する provider/model チェーン
aivault alias create best --chain "openai/gpt-5,openrouter/openai/gpt-5:free"
aivault alias create cheap --chain "groq/llama-3.3-70b-versatile,openrouter/meta-llama/llama-3.3-70b-instruct:free"
aivault alias list
aivault alias remove cheap
```

`"model":"best"` は名前空間分割の**前に**チェーンを解決します。フェイルオー
バー (429/5xx/タイムアウト時と事前エラー時に次のエントリへ) には
`config.toml` の `failover = true` が必要です (既定は **オフ**)。ヘッダー送信
後のストリーミング応答はリトライされません。プロキシキーのプロバイダースコー
プはチェーンの全エントリに対して強制されます。

### バックアップ・リストア・監査ログ

```bash
aivault backup --out vault-backup.age   # ホーム全体を 1 つの age 暗号化アーカイブに
aivault restore vault-backup.age        # 確認 + パスフレーズ。上書きは拒否
aivault restore vault-backup.age --force
aivault audit --tail 50                 # 追記型監査ログ (表示時に墨消し)
aivault audit --tail 100 --json         # 生 JSONL
```

バックアップはマスターパスフレーズで暗号化されます (書き込み前に検証)。
リストアは `--force` なしでは既存ファイルの上書きを拒否します。リストア後の
vault はバックアップ時のパスフレーズを使います。監査イベント: `unlock`、
`lock`、`key.add`、`key.remove`、`key.rotate`、`key.use`、`proxykey.create`、
`provider.add`、`passwd`、`auth.fail`。

## ゲートウェイ API

ベース URL: `http://127.0.0.1:8317` (ループバック限定。非ループバック
バインド向けの TLS は予定 — SPEC 8.7)。認証: `Authorization: Bearer vk-…`。

| エンドポイント | 備考 |
|---|---|
| `POST /v1/chat/completions` | ストリーミング (SSE、チャンクフラッシュ) + 非ストリーミング |
| `POST /v1/responses` | OpenAI Responses API パススルー |
| `POST /v1/embeddings` | |
| `GET /v1/models` | プロバイダーごとのカタログ。ID は `provider/model` 形式。10 分キャッシュ (アンロック時にクリア) |

```bash
# 非ストリーミング
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/gpt-5","messages":[{"role":"user","content":"hi"}]}'

# ストリーミング
curl -N http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# エンベディング
curl http://127.0.0.1:8317/v1/embeddings \
  -H "Authorization: Bearer vk-..." \
  -d '{"model":"openai/text-embedding-3-small","input":"hello"}'

# モデル一覧 ("openai/gpt-5"、"nvidia/gpt-oss-20b" などの名前空間付き ID)
curl http://127.0.0.1:8317/v1/models -H "Authorization: Bearer vk-..."
```

ルーティング: `<provider>/<model>` は**最初の**スラッシュで分割
(openrouter 形式のネストした ID は残りを保持)。ボディの `model` は素の
モデル ID に書き換えられ、`Authorization` は解決されたプロバイダーの本物の
クレデンシャルに置き換えられ、カスタムヘッダーは転送されます。

### エラー形式

| ステータス | 意味 |
|---|---|
| `401` | 不明・不正形式・失効済みプロキシキー (OpenAI エラー形式) |
| `403` | プロキシキーが解決されたプロバイダーのスコープ外 |
| `429` `rate_limit_error` | プロキシキーの RPM 超過 (拒否分はカウントしない) |
| `429` `spend_cap_reached` | プロキシキーの日次 USD 上限到達 (転送前に判定) |
| `503` `gateway_locked` | vault がロック中 — アンロックして再試行 |
| `4xx/5xx` | 上流エラー。OpenAI 形式ならそのまま透過、違えばラップ
  (`upstream_request_error` / `api_error`) |

ボディ上限は 16 MiB。非ストリーミングは 120 秒のデッドライン。ネイティブの
anthropic/gemini プロトコルは未対応 (v1.1 の翻訳シムで対応予定) で `400` を
返します。ただしキーの保存・ローテーションは vault で問題なく行えます。

## 設定 (`~/.aivault/config.toml`)

```toml
port = 8317
auto_lock_minutes = 15
failover = false          # 429/5xx/タイムアウト時に次のエイリアスチェーンを試行

[spend]                   # プロキシキー支出上限のコスト概算
input_usd_per_1m = 0.5
output_usd_per_1m = 1.5

[[spend.model_prices]]    # プレフィックス別の上書き。最初に一致したものが優先
prefix = "openai/gpt-5"
input_usd_per_1m = 1.25
output_usd_per_1m = 10.0
```

それ以外の項目 (KDF パラメータ、ベリファイアブロブ、admin トークン) は
aivault が管理するため手動編集しないでください。

## セキュリティモデル

- プロバイダーごとの age v1 (scrypt レシピエント、マスターパスフレーズ)。
  ペイロードは JSON。アンロック時にメモリへ丸ごと復号。
- Argon2id (m=64 MiB、t=3、p=4、16 バイトソルト) で KEK を導出し、ランダムな
  ベリファイアブロブをラップ。誤ったパスフレーズは vault ファイルを復号する
  **前**に定数時間で拒否されます。
- アトミック書き込み (`O_EXCL` tmp + rename)、全ファイル `0600`、ホーム `0700`。
- プロキシキーは SHA-256 ダイジェストのみ保存、定数時間比較。
- redaction フィルタ (SPEC 8.4) が `Bearer`/`sk-`/`vk-`/`nvapi-`/`AIza`/`gsk_`/`xai-`
  パターンと実行時登録されたリテラルキーを、すべてのエラーメッセージと監査
  表示から除去 — プロバイダーのエラーボディは墨消し表示されます。
- アイドル自動ロック、SIGHUP/シャットダウンでのロック、シークレットバッファの
  ベストエフォート・ゼロ化。シークレットは決してログに残りません。
- `.gitignore` が `*.age`、`*.key`、`.env` をブロック。OAuth は意図的に
  非対応 (静的 API キーのみ)。

## vault ホームのレイアウト

```
~/.aivault/
├── config.toml        # サーバー設定 + KDF パラメータ + ベリファイアブロブ (0600)
├── meta.json          # 平文インデックス: プロバイダー、ヒント、エイリアス (シークレットなし)
├── proxykeys.json     # プロキシキーの SHA-256 ダイジェスト (0600)
├── audit.log          # 追記型 JSONL (0600)
├── aivault.sock       # AF_UNIX 管理ソケット (すべての終了経路で削除)
└── vault/
    ├── openai.json.age
    ├── nvidia.json.age
    └── …              # プロバイダーごとに 1 つの age ファイル
```

## 組み込みプロバイダー

| ID | ベース URL | ゲートウェイ対応 |
|---|---|---|
| `openai` | `api.openai.com/v1` | はい |
| `grok` | `api.x.ai/v1` | はい |
| `deepseek` | `api.deepseek.com/v1` | はい |
| `openrouter` | `openrouter.ai/api/v1` | はい |
| `moonshot` | `api.moonshot.ai/v1` | はい |
| `minimax` | `api.minimax.io/v1` | はい |
| `nvidia` | `integrate.api.nvidia.com/v1` | はい |
| `ollama-cloud` | `ollama.com/v1` | はい |
| `anthropic` | `api.anthropic.com` | v1.1 シムまで vault のみ |
| `gemini` | `generativelanguage.googleapis.com` | v1.1 シムまで vault のみ |
| *(カスタム)* | `providers add` で定義 | OpenAI 互換の任意ベース URL |

## 開発

```
go build ./... && go vet ./...
go test ./...        # vault テストは ~24 秒かかります (age scrypt wf>=18) — 正常です
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

| パス | 責務 (SPEC) |
|---|---|
| `cmd/aivault` | エントリポイント、単一バイナリ (§1) |
| `internal/vault` | プロバイダーごとの age 暗号化ファイル + meta.json インデックス (§3) |
| `internal/kdf` | Argon2id KEK + config.toml ベリファイアブロブ (§4.1) |
| `internal/keyring` | メモリ内復号クレデンシャルストア (§4.2) |
| `internal/config` | config.toml の読み書き (§3.1) |
| `internal/proxykey` | ハッシュ化された下流キー、スコープ、上限 (§4.4) |
| `internal/audit` | 追記型 JSONL 監査ログ (§4.5) |
| `internal/provider` | 組み込みプロバイダーレジストリ (§5) |
| `internal/redact` | シークレット墨消しフィルタ (§8.4) |
| `internal/server` | ゲートウェイデータプレーン + 管理プレーン (§6) |
| `internal/cli` | コマンドツリー (§7) |

## ステータスとロードマップ

v1.0 は機能完成です (SPEC §9 の受け入れ基準、実プロバイダーでの E2E 含む)。
既知の意図的な後回し項目: TCP 管理プレーン、管理プレーン CRUD エンドポイント、
ベストエフォート・ゼロ化を超えた mlock/メモリ衛生、非ループバックバインド向け
TLS、`keys --clipboard`、ネイティブ anthropic/gemini シム (v1.1)、エイリアス以
外のリクエストのフェイルオーバー、サーバー再起動を跨ぐ支出上限の永続化。

ロードマップ (SPEC §10): v1.1 翻訳シム + 使用量/コストダッシュボード、
v1.2 OS キーチェーンのパスフレーズ/自動アンロック/YubiKey、
v2.0 マルチユーザー vault。