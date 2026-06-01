# sec-monthly-report

`sec-monthly-report` は、CISA KEV、FIRST EPSS、必要に応じてNVD情報を使って月次の脆弱性レポートを生成する最小版Python CLIです。

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
- `--top`: レポートに含める最大件数。既定は `20`
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

顧客向けレポートは、経営層にも読みやすい表現で、利用有無や外部公開有無の確認を中心に記載します。

内部向けレポートは、提案テーマ、確認観点、ベンダー集中度を含めます。

CSVにはCVE、ベンダー、製品、KEV、EPSS、CISA由来の `required_action` などを出力します。`--with-nvd` 指定時にNVD情報を取得できた場合は、`cvss` と `nvd_summary` に補足情報を出力します。
サンプルCSV利用時は古いCVEが含まれる場合があります。レポート内の「抽出条件」はCLIで指定した抽出条件を示すものであり、サンプル出力が実際の直近月次状況を表すことを意味しません。

## 将来のCodex Skill化

将来的に `codex-skills/sec-monthly-report/` を追加しやすいよう、CLIエントリポイントとレポート生成処理を分離しています。

想定構成:

```text
codex-skills/
  sec-monthly-report/
    SKILL.md
```

Skill側では、本CLIの実行手順、出力確認観点、顧客向け/内部向けの説明ルールを記述する想定です。
