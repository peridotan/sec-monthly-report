from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from generate_monthly_report import render_customer_report, summary_cell


def sample_rows() -> list[dict[str, str]]:
    return [
        {
            "cve_id": "CVE-2026-0001",
            "date_added": "2026-05-20",
            "vendor": "Microsoft",
            "product": "Windows",
            "kev": "true",
            "epss": "0.95",
            "epss_percentile": "0.99",
            "short_description": "Microsoft Windows allows remote attackers to execute arbitrary code.",
            "nvd_summary": "",
        },
        {
            "cve_id": "CVE-2026-0002",
            "date_added": "2026-05-21",
            "vendor": "Drupal",
            "product": "Core",
            "kev": "true",
            "epss": "0.50",
            "epss_percentile": "0.90",
            "short_description": "Drupal Core contains a SQL injection vulnerability.",
            "nvd_summary": "",
        },
    ]


def render_customer(with_nvd: bool = False) -> str:
    rows = sample_rows()
    return render_customer_report(
        rows=rows,
        candidate_rows=rows,
        recent_days=30,
        period_start=date(2026, 5, 2),
        period_end=date(2026, 6, 1),
        top=20,
        source_count=2,
        candidate_count=2,
        csv_count=2,
        generated_at=datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc),
        used_sample=False,
        with_nvd=with_nvd,
    )


def test_customer_markdown_contains_main_headings() -> None:
    markdown = render_customer()

    assert "# 月次脆弱性確認候補レポート（顧客向け）" in markdown
    assert "## 1. このレポートの使い方" in markdown
    assert "## 2. 確認対象一覧" in markdown
    assert "## 3. 補足" in markdown


def test_customer_markdown_data_label_without_nvd() -> None:
    markdown = render_customer(with_nvd=False)

    assert "- データ: CISA KEV / FIRST EPSS" in markdown
    assert "- データ: CISA KEV / FIRST EPSS / NVD" not in markdown


def test_customer_markdown_data_label_with_nvd() -> None:
    markdown = render_customer(with_nvd=True)

    assert "- データ: CISA KEV / FIRST EPSS / NVD" in markdown


def test_customer_markdown_table_has_summary_column() -> None:
    markdown = render_customer()

    assert "| CVE | CVE公開年 | KEV追加日 | ベンダー | 製品 | 概要 | KEV該当 | EPSS | 一次確認区分 | 抽出理由 |" in markdown


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("This vulnerability allows remote code execution.", "Windows のリモートコード実行"),
        ("Authentication bypass in the target product.", "Windows の認証バイパス"),
        ("The product contains a SQL injection vulnerability.", "Windows のSQL Injection"),
        ("Cross-site scripting in a web page.", "Windows のクロスサイトスクリプティング"),
        ("Privilege escalation is possible locally.", "Windows の権限昇格"),
        ("Denial of service vulnerability.", "Windows のサービス拒否"),
        ("A supply chain attack published a malicious package.", "Windows のサプライチェーン攻撃"),
    ],
)
def test_summary_cell_maps_vulnerability_types(text: str, expected: str) -> None:
    row = {
        "vendor": "Microsoft",
        "product": "Windows",
        "nvd_summary": text,
        "short_description": "",
    }

    assert summary_cell(row) == expected


def test_summary_cell_deduplicates_same_vendor_and_product() -> None:
    row = {
        "vendor": "Microsoft",
        "product": "Microsoft",
        "nvd_summary": "Cross-site scripting vulnerability.",
        "short_description": "",
    }

    assert summary_cell(row) == "Microsoft のクロスサイトスクリプティング"
    assert "Microsoft Microsoft" not in summary_cell(row)


def test_summary_cell_uses_vendor_and_product_for_core() -> None:
    row = {
        "vendor": "Drupal",
        "product": "Core",
        "nvd_summary": "SQL injection vulnerability.",
        "short_description": "",
    }

    assert summary_cell(row) == "Drupal Core のSQL Injection"
