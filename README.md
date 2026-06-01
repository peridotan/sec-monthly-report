# sec-monthly-report

`sec-monthly-report` は、CISA KEV、FIRST EPSS、必要に応じてNVD情報を使って月次の脆弱性レポートを生成する最小版Python CLIです。

外部APIの取得に失敗した場合でも、`samples/sample_vulnerabilities.csv` を使って動作確認できます。

## 使い方

```bash
python main.py --mode customer --recent-days 30 --top 20
python main.py --mode internal --recent-days 30 --top 20 --with-nvd
```

結果は既定で `output/` 配下に出力されます。

## CLIオプション

- `--recent-days`: 直近何日分を対象にするか。既定は `30`
- `--with-nvd`: 選択されたCVEにNVD情報を補足する
- `--top`: レポートに含める最大件数。既定は `20`
- `--mode`: `customer` または `internal`
- `--output`: 出力ディレクトリ。既定は `output`

## レポートの考え方

- CISA KEVは「悪用確認済み」として扱います。
- FIRST EPSSは「今後30日程度の悪用可能性の推定」として扱います。
- EPSSは優先順位付けの参考情報です。EPSSだけでリスク判断せず、資産の利用状況、外部公開有無、事業影響、補完統制、パッチ適用状況とあわせて確認します。

## 出力

例:

```text
output/2026-06-01_customer_monthly_report.md
output/2026-06-01_customer_monthly_report.csv
```

顧客向けレポートは、経営層にも読みやすい表現で、利用有無や外部公開有無の確認を中心に記載します。

内部向けレポートは、提案テーマ、確認観点、ベンダー集中度を含めます。

## 将来のCodex Skill化

将来的に `codex-skills/sec-monthly-report/` を追加しやすいよう、CLIエントリポイントとレポート生成処理を分離しています。

想定構成:

```text
codex-skills/
  sec-monthly-report/
    SKILL.md
```

Skill側では、本CLIの実行手順、出力確認観点、顧客向け/内部向けの説明ルールを記述する想定です。
