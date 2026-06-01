---
name: sec-monthly-report
description: Use when working with the sec-monthly-report Python CLI to generate, review, or explain monthly vulnerability reports using CISA KEV, FIRST EPSS, optional NVD enrichment, customer-facing reports, internal advisory reports, sample CSV fallback behavior, and output handling.
---

# sec-monthly-report

## Purpose

Use this skill to operate and review the `sec-monthly-report` repository consistently.

The tool is a defensive Python CLI that generates monthly vulnerability reports from CISA KEV, FIRST EPSS, and optional NVD data. It supports two audiences:

- Customer-facing reports for calm confirmation and prioritization guidance.
- Internal reports for advisory follow-up, proposal themes, and review points.

Do not use this skill for exploitation, unauthorized scanning, intrusion guidance, or offensive vulnerability use.

## Standard Workflow

1. Inspect the repository state before changing files.
2. Generate the requested report mode with `main.py`.
3. Review both Markdown and CSV outputs under `output/`.
4. Confirm whether live data or sample CSV fallback was used.
5. Check wording for customer/internal audience fit.
6. Validate Python changes with `python -m py_compile main.py generate_monthly_report.py`.
7. Review `git diff` before summarizing changes.

Do not commit unless the user explicitly asks.

## Representative Commands

Generate a customer-facing report:

```bash
python main.py --mode customer --recent-days 30 --top 20 --output output
```

Generate an internal report with optional NVD enrichment:

```bash
python main.py --mode internal --recent-days 30 --top 20 --with-nvd --output output
```

Generate a small smoke-test output:

```bash
python main.py --mode customer --recent-days 30 --top 3 --output output
python main.py --mode internal --recent-days 30 --top 3 --output output
python -m py_compile main.py generate_monthly_report.py
```

## Report Audience Guidance

For customer-facing reports:

- Use calm wording focused on confirmation, not alarm.
- State that the report is a priority confirmation list, not evidence of compromise or impact in the customer's environment.
- Put executive-readable summary content early: count, KEV count, top vendors, and first actions.
- Make the first actions `利用有無`, `外部公開有無`, and `未対応有無` confirmation.
- Avoid treating CISA `required_action` as a direct instruction to the customer without environment confirmation.

For internal reports:

- Include vendor concentration.
- Include proposal and support themes.
- Include confirmation points for customer follow-up.
- Mark assumptions and data limits explicitly.
- Keep advisory angles grounded in the generated data.

## KEV, EPSS, and NVD Interpretation

- CISA KEV means the vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog and should be treated as generally known exploited.
- KEV does not mean the customer's environment is affected, exposed, or compromised.
- FIRST EPSS estimates the probability that exploitation activity will be observed within the next 30 days.
- EPSS is a prioritization signal, not a complete risk score.
- Do not present EPSS as measuring business impact, asset exposure, exploitability in a specific environment, compensating controls, or patch status.
- NVD is optional supplemental data. When `--with-nvd` is specified and data can be retrieved, CVSS and NVD summaries may be reflected in CSV and report supplements.
- Absence of NVD data in output does not mean a CVE has no impact.

## Sample CSV and Fallback Handling

The tool can fall back to `samples/sample_vulnerabilities.csv` when external data fetches fail or return no rows. This allows format and workflow checks even without live API data.

When sample data or fallback data is used:

- Make the report clearly say `サンプルデータ利用中`.
- Include the note: `この出力はレポート形式確認用であり、実際の月次脆弱性状況を示すものではありません`.
- Expect old CVEs to appear even when `--recent-days 30` is specified, depending on sample content.
- Treat the output as a formatting and workflow check only.

The report label `抽出条件: 直近 N 日` means the CLI filter condition that was applied. It does not guarantee that the output represents the actual vulnerability situation for the latest month, especially when sample CSV fallback is used.

## Output Handling

Generated files are written under `output/` by default. Do not add generated report outputs to Git. Keep `output/.gitkeep` only.

CSV outputs are useful for detailed review. The `required_action` column is CISA KEV catalog text and should be explained as CISA-derived recommended action, not as a customer-specific mandate.

The sample CSV under `samples/` is intentionally kept so the tool can be tested without live external data.
