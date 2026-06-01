# sec-monthly-report

`sec-monthly-report` は、CISA KEV、FIRST EPSS、必要に応じてNVD情報を使って月次の脆弱性レポートを生成する最小版Python CLIです。
月次レポートでは、新規脆弱性の確認と、継続的に悪用される既知脆弱性の確認の両方を扱います。
確認候補はCVE公開日だけでなく、KEV追加日、EPSS、CLIの抽出条件にも基づいて整理します。

外部APIの取得に失敗した場合でも、`samples/sample_vulnerabilities.csv` を使って動作確認できます。
サンプルCSVへフォールバックした場合の出力はレポート形式確認用であり、実際の月次脆弱性状況を示すものではありません。

## 使い方

```bash
python main.py --mode customer --recent-days 30 --top 20
python main.py --mode internal --recent-days 30 --top 20 --with-nvd
```

結果は既定で `output/` 配下に出力されます。
外部データ取得に失敗した場合はサンプルCSVを使って出力を継続し、レポート冒頭にサンプルデータ利用中であることを表示します。

## CLIオプション

- `--recent-days`: 直近何日分を対象にするか。既定は `30`
- `--with-nvd`: 選択されたCVEにNVD情報を補足する。取得できた場合のみ、CVSSや概要をCSV/レポート補足に反映します。
- `--top`: Markdownレポート本文に含める最大件数。既定は `20`。CSVには抽出条件に該当した全候補を出力します。
- `--mode`: `customer` または `internal`
- `--output`: 出力ディレクトリ。既定は `output`

## レポートの考え方

- CISA KEVは「悪用確認済み」として扱います。
- FIRST EPSSは「今後30日以内に悪用活動が観測される確率の推定」として扱います。
- EPSSは優先順位付けの参考情報です。EPSSだけでリスク判断せず、資産の利用状況、外部公開有無、事業影響、補完統制、パッチ適用状況とあわせて確認します。
- NVDは任意の補足情報です。`--with-nvd` 指定時に取得できた場合のみ、CVSSや概要をCSVおよびレポート補足に反映します。
- CSVの `required_action` はCISA KEVカタログ由来の推奨対応です。顧客環境での対応指示ではなく、利用有無、外部公開有無、未対応有無を確認したうえで判断するための参考情報として扱います。

## 出力

例:

```text
output/2026-06-01_customer_monthly_report.md
output/2026-06-01_customer_monthly_report.csv
```

顧客向けレポートは、現場担当者が対象製品の利用有無、外部公開有無、対応状況を確認するための月次脆弱性確認候補レポートです。
`customer` mode は経営者向け報告書ではなく、情報システム部門・セキュリティ管理者・IT運用責任者向けの顧客向け実務レポートです。
構成は「このレポートの使い方 → 確認対象一覧 → 補足」の順です。
抽出条件該当件数が20件程度の場合は、customer では `--top 20` を指定してMarkdownにも全候補を掲載することを推奨します。
顧客向けレポートの「一次確認区分」は対応指示ではなく、利用有無、外部公開有無、未対応有無を確認する順序の目安です。

内部向けレポートは、提案テーマ、確認観点、ベンダー集中度を含めます。

CSVにはCVE、ベンダー、製品、KEV、EPSS、CISA由来の `required_action` などを出力します。`--with-nvd` 指定時にNVD情報を取得できた場合は、`cvss` と `nvd_summary` に補足情報を出力します。
Markdownレポート本文は `--top` による上位件数のみを掲載し、CSVには抽出条件に該当した全候補を出力します。
サンプルCSV利用時は古いCVEが含まれる場合があります。レポート内の「抽出条件」はCLIで指定した抽出条件を示すものであり、サンプル出力が実際の直近月次状況を表すことを意味しません。

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
