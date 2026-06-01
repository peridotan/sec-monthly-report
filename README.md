# sec-monthly-report

[![test](https://github.com/peridotan/sec-monthly-report/actions/workflows/test.yml/badge.svg)](https://github.com/peridotan/sec-monthly-report/actions/workflows/test.yml)

`sec-monthly-report` は、CISA KEV、FIRST EPSS、必要に応じてNVD情報を使って月次の脆弱性確認候補レポートを生成する最小版Python CLIです。
customer mode は影響判断済みの経営報告書ではなく、現場担当者が対象製品の利用有無、外部公開有無、対応状況を確認するための確認候補レポートです。
月次の確認候補レポートでは、新規脆弱性の確認と、継続的に悪用される既知脆弱性の確認の両方を扱います。
確認候補はCVE公開日だけでなく、KEV追加日、EPSS、CLIの抽出条件にも基づいて整理します。

外部APIの取得に失敗した場合でも、`samples/sample_vulnerabilities.csv` を使って動作確認できます。
サンプルCSVへフォールバックした場合の出力はレポート形式確認用であり、実際の月次脆弱性状況を示すものではありません。

## 使い方

推奨実行:

```bash
python main.py --mode customer --recent-days 30 --top 20 --with-nvd --output output
```

簡易実行:

```bash
python main.py --mode customer --recent-days 30 --top 20 --output output
```

結果は既定で `output/` 配下に出力されます。
通常運用では `--with-nvd` の利用を推奨します。NVDなしの簡易実行は、候補抽出を速く確認したい場合、ネットワーク制約がある場合、またはスモークテストで使います。
現在の推奨運用は `customer` mode です。`internal` mode は初期検討用として残っていますが、現在は推奨運用ではなく、今後削除または再設計する可能性があります。
外部データ取得に失敗した場合はサンプルCSVを使って出力を継続し、レポート冒頭にサンプルデータ利用中であることを表示します。

## CLIオプション

- `--recent-days`: 直近何日分を対象にするか。既定は `30`
- `--with-nvd`: 選択されたCVEにNVD情報を補足する。通常運用では指定を推奨します。取得できた場合、CSVに `cvss` / `nvd_summary` を追加し、Markdown本文ではNVD概要全文を出さず、取得件数とCVSS上位候補のみを表示します。
- `--top`: Markdownレポート本文に含める最大件数。既定は `20`。CSVには抽出条件に該当した全候補を出力します。
- `--mode`: `customer` または `internal`。現在の推奨運用は `customer` です。`internal` は非推奨で、今後削除または再設計する可能性があります。
- `--output`: 出力ディレクトリ。既定は `output`

## レポートの考え方

- CISA KEVは「悪用確認済み」として扱います。
- FIRST EPSSは「今後30日以内に悪用活動が観測される確率の推定」として扱います。
- EPSSは優先順位付けの参考情報です。EPSSだけでリスク判断せず、資産の利用状況、外部公開有無、事業影響、補完統制、パッチ適用状況とあわせて確認します。
- NVDは任意の補足情報です。`--with-nvd` 指定時に取得できた場合、CSVに `cvss` / `nvd_summary` を出力し、Markdownでは取得件数とCVSS上位候補を補足表示します。
- CSVの `required_action` はCISA KEVカタログ由来の推奨対応です。顧客環境での対応指示ではなく、利用有無、外部公開有無、未対応有無を確認したうえで判断するための参考情報として扱います。

## 出力

例:

```text
output/2026-06-01_customer_monthly_report_with_nvd.md
output/2026-06-01_customer_monthly_report_with_nvd.csv
output/2026-06-01_customer_monthly_report.md
output/2026-06-01_customer_monthly_report.csv
```

推奨実行の `--with-nvd` 指定時は `_with_nvd` 付きのファイル名になります。NVDなしの簡易実行時は従来の通常ファイル名になります。

顧客向けレポートは、現場担当者が対象製品の利用有無、外部公開有無、対応状況を確認するための月次脆弱性確認候補レポートです。
`customer` mode は経営者向け報告書ではなく、情報システム部門・セキュリティ管理者・IT運用責任者向けの顧客向け実務レポートです。
構成は「このレポートの使い方 → 確認対象一覧 → 補足」の順です。
抽出条件該当件数が20件程度の場合は、customer では `--top 20` を指定してMarkdownにも全候補を掲載することを推奨します。
顧客向けレポートの「一次確認区分」は対応指示ではなく、利用有無、外部公開有無、未対応有無を確認する順序の目安です。

`internal` mode は初期検討用として残っていますが、現在は非推奨です。提案テーマ、確認観点、ベンダー集中度を含む内部向け出力が必要な場合のみ互換目的で利用してください。

CSVにはCVE、ベンダー、製品、KEV、EPSS、CISA由来の `required_action` などを出力します。`--with-nvd` 指定時にNVD情報を取得できた場合は、`cvss` と `nvd_summary` に補足情報を出力します。
CSVには詳細作業用の列として `short_description`、`required_action`、`cvss`、`nvd_summary` などを残します。Markdownでは確認候補の一覧性を優先し、長文の補足情報はCSVで確認します。
Markdownレポート本文は `--top` による上位件数のみを掲載し、CSVには抽出条件に該当した全候補を出力します。
サンプルCSV利用時は古いCVEが含まれる場合があります。レポート内の「抽出条件」はCLIで指定した抽出条件を示すものであり、サンプル出力が実際の直近月次状況を表すことを意味しません。

## テスト

```bash
python -m pytest
python -m py_compile main.py generate_monthly_report.py
```

主なテスト対象:

- customer Markdown の主要見出し
- NVDあり/なしのデータ表示
- CVE概要列
- 脆弱性種別の日本語ラベル化
- ベンダー名と製品名の重複回避
- Drupal Core などの表示名補正

## Codexでの月次レポート生成

通常運用では `--with-nvd` を付けた customer レポート生成を推奨します。NVDなし版は、高速確認、ネットワーク制約時、スモークテスト用の簡易実行です。

Codexでは、レポート生成、出力確認、`py_compile`、`git status` 確認まで行います。原則として、Codexにはコミットさせず、コミットはユーザーが確認後に行います。

Codexへ貼る定型プロンプト:

```text
月次脆弱性確認候補レポートを生成してください。

作業内容:

1. 作業ツリーを確認してください。
   git status --short

2. 通常運用として、NVD補足ありの customer レポートを生成してください。
   python main.py --mode customer --recent-days 30 --top 20 --with-nvd --output output

3. 必要に応じて、簡易確認用としてNVDなし版も生成してください。
   python main.py --mode customer --recent-days 30 --top 20 --output output

4. 生成されたファイルを確認してください。
   - output/YYYY-MM-DD_customer_monthly_report_with_nvd.md
   - output/YYYY-MM-DD_customer_monthly_report_with_nvd.csv
   - output/YYYY-MM-DD_customer_monthly_report.md
   - output/YYYY-MM-DD_customer_monthly_report.csv

5. NVDあり版Markdownについて、以下を確認してください。
   - タイトルが「月次脆弱性確認候補レポート（顧客向け）」になっている
   - 抽出対象期間が表示されている
   - データ行が「CISA KEV / FIRST EPSS / NVD」になっている
   - 確認対象一覧に全候補が掲載されている
   - 表に「概要」列があり、CVEの内容が短く分かる
   - NVD概要全文がMarkdownに長文表示されていない
   - CVSS高めの候補が「CVSS取得済みの上位5件」として表示されている

6. CSVについて、以下を確認してください。
   - cvss 列がある
   - nvd_summary 列がある
   - short_description や required_action など、詳細作業用列が残っている

7. Python構文チェックを実行してください。
   python -m py_compile main.py generate_monthly_report.py

8. git diff --stat と git status --short を確認してください。

9. コード変更はしないでください。必要な改善点があれば、変更せずに提案だけしてください。

最後に以下を要約してください。
- 生成されたファイル名
- NVDあり版とNVDなし版の出力状況
- Markdownの内容が確認候補レポートとして適切か
- CSVに詳細確認用データが入っているか
- 改善提案があるか
```

## Codex Skill

このリポジトリ用のCodex Skillを以下に配置しています。

```text
codex-skills/sec-monthly-report/SKILL.md
```

Codexで本ツールのレポート生成、出力レビュー、顧客向け/内部向けの書き分け確認を行うときに利用できます。

使い方例:

```text
Use $sec-monthly-report to review the generated customer and internal reports.
Use $sec-monthly-report to regenerate reports and check README consistency.
```

## License

MIT License
