# 変更履歴

aivault の主な変更点をここに記録します。書式は
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) に従い、
[SemVer](https://semver.org/) でバージョン管理しています
(`aivault version` / `--version` で表示)。英語版: [CHANGELOG.md](CHANGELOG.md)。

## [Unreleased]

計画中のバックログ (pi-llm-gateway との比較から学んだ項目 — 詳細は
`HANDOFF.md` のセッション記録を参照):

- memguard によるキーリング保護 (SPEC 8.3)。既存のコアダンプ対策の上に
  実メモリガードを重ねる
- ループバック以外のバインド向け TLS/mTLS (SPEC 8.7)。総当たり防御と
  組み合わせて複数マシン運用を可能にする
- オプションのヘッドレスアンロック (v1.2 議論: age X25519 レシピエントを
  追加し、identity をファイル/env/シークレットマネージャコマンドから供給)
- ネイティブ anthropic/gemini 翻訳シム (SPEC 10)

## [v1.2.0] — 2026-09-30

pi-llm-gateway 比較から学んだ、中途負荷のハードニング項目を適用した Batch B。

### 追加

- **エグレス許可リスト** — 新設 `internal/egress`: 上流プロバイダーへの接続
  をダイヤル層で登録済みホスト名に固定します (`meta.json` のベース URL と、
  復号済みペイロードが上書きするベース URL。サーバー起動時とアンロックのた
  びに再構築)。HTTP リダイレクトも毎回のダイヤルがガードを通るため再検証さ
  れます。CLI の `providers test` / `providers models` も同様に固定。改ざん
  された設定や不正なベース URL が本物のクレデンシャルを外部へ持ち出すこと
  を遮断します。新設定 `egress_allowlist` (既定 `true`)。テスト: 拒否/許可/
  リダイレクト再検証/無効化/失敗時の状態保全、ゲートウェイ全体での流出遮断
  テスト。
- **起動時の権限検証** — `vault.CheckPerms` (POSIX。Windows は Stat から
  NTFS ACL を見えないため対象外と文書化) が、vault ホーム・そのファイル・
  `vault/` 配下にグループ/他人の権限ビットがある場合、`serve`・`unlock`・
  `doctor` を拒否します。エラーは各該当パスと chmod のヒントを列挙します。
- **総当たり防御** — データプレーンの認証失敗をピア IP ごとに 1 分のローリン
  グウィンドウで集計。`auth_max_failures` (新設定、既定 20、`0` で無効) を
  超えると、さらなるキー検査の**前に** `429 auth_rate_limited` (OpenAI 形式)
  を返します — ウィンドウが流れるまで有効なキーも含まれます。`auth.fail` と
  して監査記録されます (バックオフ事象を含む)。テスト: 厳密なしきい値、有効
  キーへの作用、無効化モード。
- **`aivault doctor`** — アンロック不要の 1 コマンド・ヘルスレポート
  (pi-llm-gateway の `gateway -check` に相当するプリフライト): 設定の解析と
  各値、meta/ファイル整合 (未対応ファイル・孤立ファイル)、ファイル権限、
    プロキシキー (有効/失効数)、監査チェーン検証と件数、`key_max_age_days`
  に対するキー経過、ゲートウェイのライブ状態。判定行は `PASS`/`WARN`/`FAIL`
  で、FAIL 時はスクリプト向けに非ゼロで終了します。

### 変更

- `aivault serve` は起動時にエグレス許可リストの状態を表示し、リスナーを
  開く前にファイル権限を検証します。

### ドキュメント

- README (英語 + 日本語): `doctor` を backup/audit 節に、2 つの新設定を設定
  リファレンスに、エグレス/権限/総当たり防御をセキュリティモデルに追記。
  本リリースの CHANGELOG 項目を追加。

## [v1.1.0] — 2026-09-30

[pi-llm-gateway](https://github.com/trork-code/pi-llm-gateway) の調査の後に
適用したハードニング Batch A。

### 追加

- **`GET /v1/models` でのエイリアス公開** — `meta.json` のゲートウェイ別名
  が実カタログの横に `{"id": "<別名>", "owned_by": "alias"}` として現れます
  (ソート済み)。プロキシキーのプロバイダースコープがフェイルオーバーチェー
  ンの**すべて**のリンクをカバーする場合のみ表示されます (ルーティング側の
  チェーンごとのスコープ強制と一致)。クライアント (pi のネイティブモデル
  ピッカー) は設定変更なしでプロバイダーを切り替えられます: 仮想名は
  ゲートウェイ側で解決されます。(`b94371d`、テスト
  `TestModelsEndpointAliases` / `TestModelsEndpointAliasesScopedOut`)
- **改ざん検知可能な監査ログ** — 監査エントリがハッシュチェーンで連結され
  ます: 各エントリは `prev` (直前エントリの ID) と
  `id = SHA-256(prev + 正規化エントリ内容)` を持ちます。編集や削除でチェー
  ンは切断されます。v1.1 未満のエントリは**レガシー** (ID なし) として扱わ
  れ、チェーンは最初の ID 付きエントリから始まるため、既存ログも検証をパス
  します。同一プロセス内の書き込みはミューテックスで直列化。CLI とサーバー
  の同時書き込み交錯は文書化済みで、検証では「検出された切断」として報告さ
  れます。(`a073e85`)
- **`aivault audit --verify`** — ログ全体を辿り、`entries / chained / legacy`
  と `OK` を報告。最初の切断箇所で非ゼロ終了 (改ざん/削除)。(`a073e85`)
- **キー経過の警告** — 新設定 `key_max_age_days` (既定 `90`、`0` で無効):
  `aivault status` が制限より古い保存済みキーのプロバイダーにローテーション
  警告を出します (meta の `UpdatedAt` 基準。`none` 種別は対象外)。ローテー
  ションで時計はリセット。(`d2074d1`)
- **CI の gitleaks** — 全履歴シークレットスキャンが vet/tests/staticcheck/
  govulncheck に加わり、push と PR ごとに実行されます。(`d8f702b`)

### セキュリティ

- **`serve` 起動時のコアダンプ無効化** — unix はリスナー起動前に
  `RLIMIT_CORE=0` を設定 (失敗時は警告のみで非致命)。Windows は文書化済みの
  対象外 (WER ポリシーの管轄)。memguard マイルストーン (SPEC 8.3) に先立つ
  クラッシュダンプ経路の遮断です。(`bfe88c6`)
- 既存動作の検証 (対処不要): ストリーミングリクエストの上流側コンテキストは
  `r.Context()` 由来のため、**クライアント切断で上流呼び出しも中断**されま
  す — SSE の受信者が消失しても課金リークは発生しません。

### ドキュメント

- README (EN + JA): `/v1/models` のエイリアス、`audit --verify` を含む監査
  チェーン節、設定リファレンスの `key_max_age_days`、セキュリティモデルの
  コアダンプと gitleaks。(`1e7e309`)

## [v1.0.1] — 2026-09-30

### 追加

- **プロバイダー別モデル一覧** — `aivault providers models <id>` (または
  `--provider` フラグ) が 1 プロバイダーの**完全な**ライブモデルカタログを
  1 行 1 モデルで出力。引数なしでは従来通りの横断サマリ表 (1 プロバイダー
  3 モデルのサンプル)。引数とフラグが不一致のときはエラー。未知/未キー登
  録のプロバイダーはネットワーク呼び出し前に明快なエラーを返します。
  (`5e10a54`)
- **バージョン基盤** — `internal/version` を単一の情報源に (`-ldflags -X`
  で commit/date を埋め込み可能)。`aivault version` と `aivault --version`
  が表示し、`aivault status` にもバージョン行を追加して診断性を向上。
  (`ad7ad84`)

### 変更

- インストール済みバイナリはシンボルを除去したビルドに
  (`-ldflags "-s -w"`)。12.7 MB → 9.0 MB。

### 修正

- **プロバイダープローブが上流エラーボディを墨消し付きで表示** —
  `providers test` / `providers models` の失敗時に、プロバイダー自身のエラ
  ーメッセージを含めて返します (SPEC 8.4 フィルタで上限・墨消し。実行時登
  録のリテラルキーも対象)。tokenharbor の `email_verification_required` 403
  のような上流側の拒否が、クレデンシャルを漏らさずに診断できるようになり
  ました。(`a61b796`、リリース前コミットとして v1.0.0/v1.0.1 のバイナリに
  含まれる)

## [v1.0.0] — 2026-09-16

初の安定リリース。v1.0 の実装マイルストーン 6 件すべてが完了し、SPEC §9 の
受け入れ基準 (実プロバイダー NVIDIA NIM での E2E: 81 モデル列挙、実チャット
完了 + SSE ストリーム、lock → 503、revoke → 401) をクリア済み。

### 追加

- **暗号コア** — Argon2id KEK (m=64 MiB t=3 p=4、16 バイトソルト) + ベリファ
  イアブロブ: 誤ったマスターパスフレーズは vault ファイルを復号する**前**に
  定数時間で拒否。プロバイダーごとの age-scrypt ファイル。zxcvbn パスフレー
  ズポリシー (12 文字以上・スコア ≥ 3)。ベストエフォートのメモリゼロ化。
- **Vault CLI** — `init`、`keys add/list/show/remove/rotate` (`--key-stdin` /
  隠蔽プロンプト / 環境変数のみ。引数では絶対に渡さない)、`passwd` (全ファ
  イル検証後に一括再暗号化)、`providers add/list`。
- **ゲートウェイサーバー** — `aivault serve`: AF_UNIX 管理プレーン
  (status/unlock/lock/audit)。部分的な復号は決してキーリングを差し替えない
  フェイルセーフ設計。アイドル自動ロック (既定 15 分。キーリングを使うリク
  エストのみタイマーをリセット)。`aivault lock` / SIGHUP / シャットダウンで
  ロック。
- **データプレーン** — ループバック:8317 の OpenAI 互換ゲートウェイ: プロキ
  シキー認証 (SHA-256 ダイジェスト、定数時間比較、スコープ外は 403、失効は
  即時有効)、`POST /v1/chat/completions` (SSE + 非ストリーミング)、
  `/v1/responses`、`/v1/embeddings`、`GET /v1/models`。`<provider>/<model>`
  形式の最初のスラッシュ分割ルーティング、認証ヘッダー差し替え、カスタム
  ヘッダー転送、上流エラーの正規化、16 MiB 上限、非ストリーミング 120 秒の
  デッドライン。
- **ハードニング** — プロキシキーごとの RPM (スライディングウィンドウ) と
  日次 USD 支出上限 (usage ベース概算、`[spend]` 価格テーブル)。別名チェー
  ンによるオプトインのフェイルオーバー (429/5xx/タイムアウト時、
  `failover = true`)。全エラー・表示経路の墨消しフィルタ。vault ホーム全体
  の age 暗号化 `backup`/`restore`。`providers test <id>` の実クレデンシャ
  ル検証。追記型 JSONL 監査ログ。
- **ドキュメント** — 英語 [README.md](README.md) と日本語
  [README.ja.md](README.ja.md) の完全なコマンドリファレンスとゲートウェイ
  ガイド。
- **CI** — go vet、ビルド、テスト、staticcheck、govulncheck (SPEC 8.9)。

### 意図した制限 (文書化済み)

- `aivault lock` は **`503 gateway_locked`** を返します (SPEC 9 の受け入れ行
  に文字通りある "401" ではなく) — プロキシキー自体は有効なため 503 が意味
  的に正しい。
- ループバック限定バインド (TLS は SPEC 8.7 で対応予定)。ネイティブの
  anthropic/gemini プロトコルは v1.1 シムまで vault 専用 (SPEC 10)。OAuth
  は意図的に非対応 (静的 API キーのみ)。

[v1.2.0]: https://github.com/ZN9-KYANT/aivault/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/ZN9-KYANT/aivault/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/ZN9-KYANT/aivault/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/ZN9-KYANT/aivault/releases/tag/v1.0.0