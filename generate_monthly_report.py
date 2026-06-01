from __future__ import annotations

import csv
import json
import math
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SAMPLE_CSV = Path("samples/sample_vulnerabilities.csv")


@dataclass
class ReportResult:
    report_path: Path
    csv_path: Path
    used_sample: bool


def generate_monthly_report(
    recent_days: int,
    with_nvd: bool,
    top: int,
    mode: str,
    output_dir: Path,
) -> ReportResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc)

    rows, used_sample = load_live_rows(recent_days=recent_days)
    if not rows:
        rows = load_sample_rows()
        used_sample = True

    rows = filter_recent(rows, recent_days=recent_days, today=generated_at.date())
    rows = sorted(rows, key=sort_key, reverse=True)[:top]

    if with_nvd:
        enrich_with_nvd(rows)

    stem = f"{generated_at.date().isoformat()}_{mode}_monthly_report"
    csv_path = output_dir / f"{stem}.csv"
    report_path = output_dir / f"{stem}.md"

    write_rows_csv(rows, csv_path)
    report_path.write_text(
        render_report(
            rows,
            mode=mode,
            recent_days=recent_days,
            generated_at=generated_at,
            used_sample=used_sample,
            with_nvd=with_nvd,
        ),
        encoding="utf-8",
    )
    return ReportResult(report_path=report_path, csv_path=csv_path, used_sample=used_sample)


def load_live_rows(recent_days: int) -> tuple[list[dict[str, str]], bool]:
    try:
        kev_payload = fetch_json(CISA_KEV_URL)
        kev_items = kev_payload.get("vulnerabilities", [])
        rows = [normalize_kev_item(item) for item in kev_items]
        rows = [row for row in rows if row.get("cve_id")]
        rows = filter_recent(rows, recent_days=recent_days, today=date.today())
        add_epss(rows)
        return rows, False
    except Exception:
        return [], True


def fetch_json(url: str, timeout: int = 20) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "sec-monthly-report/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_kev_item(item: dict) -> dict[str, str]:
    return {
        "cve_id": value(item, "cveID"),
        "vendor": value(item, "vendorProject"),
        "product": value(item, "product"),
        "vulnerability_name": value(item, "vulnerabilityName"),
        "date_added": value(item, "dateAdded"),
        "short_description": value(item, "shortDescription"),
        "required_action": value(item, "requiredAction"),
        "due_date": value(item, "dueDate"),
        "known_ransomware_campaign_use": value(item, "knownRansomwareCampaignUse"),
        "kev": "true",
        "epss": "",
        "epss_percentile": "",
        "cvss": "",
        "nvd_summary": "",
    }


def value(item: dict, key: str) -> str:
    raw = item.get(key, "")
    return "" if raw is None else str(raw)


def add_epss(rows: list[dict[str, str]]) -> None:
    cves = [row["cve_id"] for row in rows if row.get("cve_id")]
    for chunk in chunks(cves, 100):
        query = urllib.parse.urlencode({"cve": ",".join(chunk)})
        payload = fetch_json(f"{FIRST_EPSS_URL}?{query}")
        by_cve = {item.get("cve"): item for item in payload.get("data", [])}
        for row in rows:
            epss_item = by_cve.get(row.get("cve_id"))
            if epss_item:
                row["epss"] = str(epss_item.get("epss", ""))
                row["epss_percentile"] = str(epss_item.get("percentile", ""))


def enrich_with_nvd(rows: list[dict[str, str]]) -> None:
    for row in rows:
        cve_id = row.get("cve_id")
        if not cve_id:
            continue
        try:
            query = urllib.parse.urlencode({"cveId": cve_id})
            payload = fetch_json(f"{NVD_CVE_URL}?{query}")
            vulns = payload.get("vulnerabilities", [])
            if not vulns:
                continue
            cve = vulns[0].get("cve", {})
            descriptions = cve.get("descriptions", [])
            row["nvd_summary"] = next(
                (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
                "",
            )
            row["cvss"] = extract_cvss(cve)
        except Exception:
            continue


def extract_cvss(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            score = items[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return str(score)
    return ""


def load_sample_rows() -> list[dict[str, str]]:
    if not SAMPLE_CSV.exists():
        return []
    with SAMPLE_CSV.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def filter_recent(rows: list[dict[str, str]], recent_days: int, today: date) -> list[dict[str, str]]:
    if recent_days <= 0:
        return rows
    cutoff = today - timedelta(days=recent_days)
    filtered = []
    for row in rows:
        row_date = parse_date(row.get("date_added") or row.get("published_date") or "")
        if row_date is None or row_date >= cutoff:
            filtered.append(row)
    return filtered


def parse_date(raw: str) -> date | None:
    if not raw:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw[:10], fmt).date()
        except ValueError:
            continue
    return None


def sort_key(row: dict[str, str]) -> tuple[int, float, float]:
    return (
        1 if row.get("kev", "").lower() == "true" else 0,
        safe_float(row.get("epss")),
        safe_float(row.get("epss_percentile")),
    )


def safe_float(raw: str | None) -> float:
    try:
        number = float(raw or "")
        return number if math.isfinite(number) else 0.0
    except ValueError:
        return 0.0


def write_rows_csv(rows: list[dict[str, str]], path: Path) -> None:
    fieldnames = [
        "cve_id",
        "vendor",
        "product",
        "vulnerability_name",
        "date_added",
        "kev",
        "epss",
        "epss_percentile",
        "cvss",
        "known_ransomware_campaign_use",
        "required_action",
        "due_date",
        "short_description",
        "nvd_summary",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def render_report(
    rows: list[dict[str, str]],
    mode: str,
    recent_days: int,
    generated_at: datetime,
    used_sample: bool,
    with_nvd: bool,
) -> str:
    if mode == "internal":
        return render_internal_report(rows, recent_days, generated_at, used_sample, with_nvd)
    return render_customer_report(rows, recent_days, generated_at, used_sample, with_nvd)


def render_customer_report(
    rows: list[dict[str, str]], recent_days: int, generated_at: datetime, used_sample: bool, with_nvd: bool
) -> str:
    lines = [
        "# 月次脆弱性レポート（顧客向け）",
        "",
        f"- 作成日時: {generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}",
        f"- 抽出条件: 直近 {recent_days} 日",
        f"- 掲載件数: {len(rows)} 件",
        f"- データ: {'サンプルCSV' if used_sample else 'CISA KEV / FIRST EPSS'}",
        *sample_data_notice_lines(used_sample),
        "",
        "## 1. サマリ",
        "",
        "### 経営向け要約",
        "",
        f"- 対象件数: {len(rows)} 件",
        f"- KEV該当件数: {kev_count(rows)} 件",
        f"- ベンダー上位: {top_vendors_text(rows)}",
        "- まず実施すべきこと: 利用有無、外部公開有無、未対応有無の確認",
        "",
        "本レポートは、一般に悪用が確認されている脆弱性と、今後30日以内に悪用活動が観測される確率が相対的に高い脆弱性を確認するためのものです。まずは対象製品の利用有無、外部公開有無、適用済みパッチの確認を推奨します。",
        "",
        "> 注記: 本レポートは一般に悪用が確認・予測される脆弱性の優先確認リストであり、貴社環境で悪用や影響が確認されたことを示すものではありません。",
        "",
        "## 2. 今回確認すべきポイント",
        "",
        "- CISA KEVは「悪用確認済み」の脆弱性として扱います。",
        "- FIRST EPSSは「今後30日以内に悪用活動が観測される確率の推定」として扱います。",
        "- EPSSは優先順位付けの参考情報であり、EPSSだけでリスク判断は行いません。実際の影響は資産の利用状況、外部公開、重要度、代替対策によって変わります。",
        "- NVDは任意の補足情報です。--with-nvd 指定時に取得できた場合のみ、CVSSや概要をCSVおよびレポート補足に反映します。",
        "",
        "## 3. 個別CVE確認表",
        "",
        vulnerability_table(rows),
        "",
        "## 4. 推奨アクション",
        "",
        "- 対象製品の利用有無を確認する。",
        "- インターネット公開、認証基盤、リモートアクセス、セキュリティ機器に関係する資産を優先して確認する。",
        "- ベンダー情報とパッチ適用状況を確認し、影響範囲を切り分ける。",
        "",
        "## 5. NVD補足",
        "",
        nvd_supplement(rows, with_nvd),
    ]
    return "\n".join(lines) + "\n"


def render_internal_report(
    rows: list[dict[str, str]], recent_days: int, generated_at: datetime, used_sample: bool, with_nvd: bool
) -> str:
    lines = [
        "# 月次脆弱性レポート（内部向け）",
        "",
        f"- 作成日時: {generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}",
        f"- 抽出条件: 直近 {recent_days} 日",
        f"- 掲載件数: {len(rows)} 件",
        f"- データ: {'サンプルCSV' if used_sample else 'CISA KEV / FIRST EPSS'}",
        *sample_data_notice_lines(used_sample),
        "",
        "## 1. 今月の傾向",
        "",
        f"- KEV該当: {kev_count(rows)} 件",
        f"- EPSS 0.7以上: {sum(1 for row in rows if safe_float(row.get('epss')) >= 0.7)} 件",
        "",
        "## 2. 高EPSS/KEVの集中ベンダー",
        "",
        vendor_summary(rows),
        "",
        "## 3. 提案・支援テーマ",
        "",
        "- 顧客環境での利用有無確認と資産台帳突合の支援",
        "- 外部公開資産、認証基盤、リモートアクセス製品の優先確認",
        "- パッチ適用状況、代替緩和策、例外運用の棚卸し",
        "",
        "## 4. 確認観点",
        "",
        "- KEVは悪用確認済みとして優先確認対象にする。",
        "- EPSSは今後30日以内に悪用活動が観測される確率の推定であり、単独のリスクスコアとして扱わない。",
        "- 顧客固有の露出状況、重要資産、補完統制、保守状態を必ず確認する。",
        "- NVDは任意補足として扱う。--with-nvd 指定時に取得できた場合のみ、CVSSや概要をCSVおよびレポート補足に反映する。",
        "",
        "## 5. 個別CVE",
        "",
        vulnerability_table(rows),
        "",
        "## 6. NVD補足",
        "",
        nvd_supplement(rows, with_nvd),
    ]
    return "\n".join(lines) + "\n"


def vulnerability_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "対象データはありません。"
    lines = [
        "| CVE | ベンダー | 製品 | KEV | EPSS | 確認ポイント |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for row in rows:
        epss = format_score(row.get("epss"))
        check = "利用有無、外部公開有無、パッチ適用状況を確認"
        lines.append(
            f"| {cell(row.get('cve_id'))} | {cell(row.get('vendor'))} | {cell(row.get('product'))} | {cell(row.get('kev'))} | {epss} | {check} |"
        )
    return "\n".join(lines)


def vendor_summary(rows: list[dict[str, str]]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        vendor = row.get("vendor") or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1
    if not counts:
        return "対象データはありません。"
    lines = ["| ベンダー | 件数 |", "| --- | ---: |"]
    for vendor, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"| {cell(vendor)} | {count} |")
    return "\n".join(lines)


def kev_count(rows: list[dict[str, str]]) -> int:
    return sum(1 for row in rows if row.get("kev", "").lower() == "true")


def top_vendors_text(rows: list[dict[str, str]], limit: int = 3) -> str:
    counts = vendor_counts(rows)
    if not counts:
        return "対象データなし"
    items = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    return "、".join(f"{vendor} {count}件" for vendor, count in items)


def vendor_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        vendor = row.get("vendor") or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def nvd_supplement(rows: list[dict[str, str]], with_nvd: bool) -> str:
    if not with_nvd:
        return "NVD補足は未取得です。必要に応じて --with-nvd を指定すると、取得できたCVSSや概要をCSVおよび本補足に反映します。"

    enriched = [row for row in rows if row.get("cvss") or row.get("nvd_summary")]
    if not enriched:
        return "NVD補足を取得しましたが、対象CVEに反映できるCVSSや概要はありませんでした。"

    lines = [
        "| CVE | CVSS | NVD概要 |",
        "| --- | ---: | --- |",
    ]
    for row in enriched:
        lines.append(
            f"| {cell(row.get('cve_id'))} | {cell(row.get('cvss'))} | {cell(row.get('nvd_summary'))} |"
        )
    return "\n".join(lines)


def sample_data_notice_lines(used_sample: bool) -> list[str]:
    if not used_sample:
        return []
    return [
        "- 注記: サンプルデータ利用中。この出力はレポート形式確認用であり、"
        "実際の月次脆弱性状況を示すものではありません。"
    ]


def format_score(raw: str | None) -> str:
    score = safe_float(raw)
    return f"{score:.3f}" if score else ""


def cell(raw: str | None) -> str:
    return (raw or "").replace("|", "\\|").replace("\n", " ")


def chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
