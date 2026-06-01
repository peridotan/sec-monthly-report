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

    rows, used_sample, source_count = load_live_rows(recent_days=recent_days)
    if not rows:
        rows = load_sample_rows()
        used_sample = True
        source_count = len(rows)

    rows = filter_recent(rows, recent_days=recent_days, today=generated_at.date())
    candidate_count = len(rows)
    candidate_rows = sorted(rows, key=sort_key, reverse=True)
    report_rows = candidate_rows[:top]

    if with_nvd:
        enrich_with_nvd(candidate_rows)

    nvd_suffix = "_with_nvd" if with_nvd else ""
    stem = f"{generated_at.date().isoformat()}_{mode}_monthly_report{nvd_suffix}"
    csv_path = output_dir / f"{stem}.csv"
    report_path = output_dir / f"{stem}.md"

    write_rows_csv(candidate_rows, csv_path)
    report_path.write_text(
        render_report(
            report_rows,
            candidate_rows=candidate_rows,
            mode=mode,
            recent_days=recent_days,
            period_start=period_start(generated_at.date(), recent_days),
            period_end=generated_at.date(),
            top=top,
            source_count=source_count,
            candidate_count=candidate_count,
            csv_count=len(candidate_rows),
            generated_at=generated_at,
            used_sample=used_sample,
            with_nvd=with_nvd,
        ),
        encoding="utf-8",
    )
    return ReportResult(report_path=report_path, csv_path=csv_path, used_sample=used_sample)


def load_live_rows(recent_days: int) -> tuple[list[dict[str, str]], bool, int]:
    try:
        kev_payload = fetch_json(CISA_KEV_URL)
        kev_items = kev_payload.get("vulnerabilities", [])
        rows = [normalize_kev_item(item) for item in kev_items]
        rows = [row for row in rows if row.get("cve_id")]
        source_count = len(rows)
        rows = filter_recent(rows, recent_days=recent_days, today=date.today())
        add_epss(rows)
        return rows, False, source_count
    except Exception:
        return [], True, 0


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


def period_start(today: date, recent_days: int) -> date:
    if recent_days <= 0:
        return today
    return today - timedelta(days=recent_days)


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
        "cve_year",
        "kev_date_added",
        "vendor",
        "product",
        "vulnerability_name",
        "date_added",
        "kev",
        "epss",
        "epss_percentile",
        "initial_check_category",
        "extraction_reason",
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
        for row in rows:
            output_row = dict(row)
            output_row["cve_year"] = cve_year(row)
            output_row["kev_date_added"] = row.get("date_added", "")
            output_row["initial_check_category"] = initial_check_category(row)
            output_row["extraction_reason"] = extraction_reason(row)
            writer.writerow(output_row)


def render_report(
    rows: list[dict[str, str]],
    candidate_rows: list[dict[str, str]],
    mode: str,
    recent_days: int,
    period_start: date,
    period_end: date,
    top: int,
    source_count: int,
    candidate_count: int,
    csv_count: int,
    generated_at: datetime,
    used_sample: bool,
    with_nvd: bool,
) -> str:
    if mode == "internal":
        return render_internal_report(
            rows, recent_days, top, source_count, candidate_count, csv_count, generated_at, used_sample, with_nvd
        )
    return render_customer_report(
        rows,
        candidate_rows,
        recent_days,
        period_start,
        period_end,
        top,
        source_count,
        candidate_count,
        csv_count,
        generated_at,
        used_sample,
        with_nvd,
    )


def render_customer_report(
    rows: list[dict[str, str]],
    candidate_rows: list[dict[str, str]],
    recent_days: int,
    period_start: date,
    period_end: date,
    top: int,
    source_count: int,
    candidate_count: int,
    csv_count: int,
    generated_at: datetime,
    used_sample: bool,
    with_nvd: bool,
) -> str:
    lines = [
        "# 月次脆弱性確認候補レポート（顧客向け）",
        "",
        f"- 作成日時: {generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}",
        f"- 抽出条件: 直近 {recent_days} 日",
        f"- 抽出対象期間: {period_start.isoformat()} 〜 {period_end.isoformat()}",
        f"- 取得件数: {source_count} 件",
        f"- 抽出条件該当件数: {candidate_count} 件",
        f"- Markdown掲載件数: {len(rows)} 件",
        f"- CSV出力件数: {csv_count} 件",
        count_note(len(rows), csv_count, top),
        f"- データ: {data_source_label(used_sample, with_nvd)}",
        *sample_data_notice_lines(used_sample),
        "",
        "## 1. このレポートの使い方",
        "",
        "- 本レポートは、外部情報に基づく月次の脆弱性確認候補リストです。",
        "- 貴社環境での利用有無、影響有無、対応状況を判定したものではありません。",
        "- 現場担当者は2章の一覧をもとに、対象製品の利用有無、外部公開有無、パッチ適用状況を確認してください。",
        "",
        "## 2. 確認対象一覧",
        "",
        "読み方:",
        "",
        f"- {table_scope_note(len(rows), csv_count, top)}",
        "- 一次確認区分は、KEVおよびEPSSに基づく確認順序の目安です。",
        "- 実際の対応要否は、利用有無、外部公開有無、重要度、補完統制、パッチ適用状況を確認したうえで判断してください。",
        "- 各候補について、対象製品の利用有無、外部公開・リモートアクセス・重要領域との関係、パッチ適用・回避策・補完統制の有無を確認してください。",
        "- NVD情報は詳細確認用の補足情報です。--with-nvd 指定時はCVSSやNVD概要をCSVに出力し、Markdownでは取得件数とCVSS上位候補のみを表示します。",
        "",
        vulnerability_table(rows),
        "",
        "## 3. 補足",
        "",
        "- CISA KEVは「悪用確認済み」の脆弱性として扱います。",
        "- FIRST EPSSは「今後30日以内に悪用活動が観測される確率の推定」として扱います。",
        "- EPSSだけでリスク判断せず、資産の利用状況、外部公開有無、事業影響、補完統制、パッチ適用状況とあわせて確認します。",
        "- 古いCVEでも、KEV追加日が新しいものやEPSSが高いものは確認対象になります。",
        f"- NVDは任意の補足情報です。{nvd_supplement(rows, with_nvd)}",
    ]
    return "\n".join(lines) + "\n"


def render_internal_report(
    rows: list[dict[str, str]],
    recent_days: int,
    top: int,
    source_count: int,
    candidate_count: int,
    csv_count: int,
    generated_at: datetime,
    used_sample: bool,
    with_nvd: bool,
) -> str:
    lines = [
        "# 月次脆弱性レポート（内部向け）",
        "",
        f"- 作成日時: {generated_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')}",
        f"- 抽出条件: 直近 {recent_days} 日",
        f"- 取得件数: {source_count} 件",
        f"- 抽出条件該当件数: {candidate_count} 件",
        f"- Markdown掲載件数: {len(rows)} 件",
        f"- CSV出力件数: {csv_count} 件",
        f"- 注記: Markdown本文にはCLIオプション --top により、上位 {top} 件までを掲載しています。抽出条件に該当した全候補はCSV出力を確認してください。",
        "- 注記: 抽出条件該当件数は取得データのうち指定条件に該当した確認候補の件数、Markdown掲載件数は --top による表示上限です。",
        f"- データ: {data_source_label(used_sample, with_nvd)}",
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
        "- 高EPSSの継続確認、新規KEV追加、CVE公開年が新しいもの、顧客資産との照合を分けて確認する。",
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
        "| CVE | CVE公開年 | KEV追加日 | ベンダー | 製品 | KEV該当 | EPSS | 一次確認区分 | 抽出理由 |",
        "| --- | ---: | --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for row in rows:
        epss = format_score(row.get("epss"))
        lines.append(
            f"| {cell(row.get('cve_id'))} | {cve_year(row)} | {kev_added_date(row)} | {cell(row.get('vendor'))} | {cell(row.get('product'))} | {kev_label(row)} | {epss} | {initial_check_category(row)} | {extraction_reason(row)} |"
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


def top_vendors_text(rows: list[dict[str, str]], limit: int = 3, include_other: bool = False) -> str:
    counts = vendor_counts(rows)
    if not counts:
        return "対象データなし"
    items = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    parts = [f"{vendor} {count}件" for vendor, count in items]
    if include_other:
        other_count = sum(counts.values()) - sum(count for _, count in items)
        if other_count:
            parts.append(f"その他 {other_count}件")
    return "、".join(parts)


def vendor_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        vendor = row.get("vendor") or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def nvd_supplement(rows: list[dict[str, str]], with_nvd: bool) -> str:
    if not with_nvd:
        return "今回はNVD補足情報を取得していません。必要に応じて --with-nvd を指定すると、取得できたCVSSや概要を追加し、詳細確認に利用できます。"

    enriched = [row for row in rows if row.get("cvss") or row.get("nvd_summary")]
    missing_count = len(rows) - len(enriched)
    if not enriched:
        return "NVD補足を取得しましたが、対象CVEに反映できるCVSSや概要はありませんでした。"

    lines = [
        f"NVD補足情報を取得しました。取得済み {len(enriched)} 件、未取得 {missing_count} 件です。詳細なCVSSとNVD概要はCSVを確認してください。",
    ]
    cvss_rows = sorted(
        [row for row in enriched if row.get("cvss")],
        key=lambda row: safe_float(row.get("cvss")),
        reverse=True,
    )
    if not cvss_rows:
        lines.extend(["", "CVSSを取得できた候補はありません。詳細はCSVを確認してください。"])
    else:
        lines.extend(
            [
                "",
                "CVSS高めの候補（CVSS取得済みの上位5件）:",
                "",
                "| CVE | CVSS | ベンダー | 製品 |",
                "| --- | ---: | --- | --- |",
            ]
        )
        for row in cvss_rows[:5]:
            lines.append(
                f"| {cell(row.get('cve_id'))} | {cell(row.get('cvss'))} | {cell(row.get('vendor'))} | {cell(row.get('product'))} |"
            )
    return "\n".join(lines)

def count_note(markdown_count: int, csv_count: int, top: int) -> str:
    if markdown_count == csv_count:
        return (
            "- 注記: 抽出条件該当件数は取得データのうち指定条件に該当した確認候補の件数です。"
            "今回はMarkdown本文とCSVの両方に全候補を掲載しています。"
        )
    return (
        f"- 注記: 抽出条件該当件数は取得データのうち指定条件に該当した確認候補の件数です。"
        f"Markdown本文には --top により上位 {top} 件までを掲載し、抽出条件に該当した全候補はCSVに出力しています。"
    )


def table_scope_note(markdown_count: int, csv_count: int, top: int) -> str:
    if markdown_count == csv_count:
        return "本表には、抽出条件に該当した全候補を掲載しています。CSVにも同じ全候補を出力しています。"
    return f"本表は --top による上位 {top} 件のみを掲載しています。抽出条件に該当した全候補はCSV出力を確認してください。"


def target_areas_text(rows: list[dict[str, str]]) -> str:
    areas: list[str] = []
    text = " ".join(f"{row.get('vendor', '')} {row.get('product', '')}".lower() for row in rows)
    if any(keyword in text for keyword in ("windows", "internet explorer", "directx", "defender")):
        areas.append("レガシーOS/ブラウザ/端末")
    if "adobe" in text or "acrobat" in text or "reader" in text:
        areas.append("Adobe製品")
    if any(keyword in text for keyword in ("cisco", "palo alto", "pan-os", "ivanti", "sd-wan")):
        areas.append("ネットワーク機器/リモートアクセス")
    if any(keyword in text for keyword in ("drupal", "langflow", "litespeed", "cpanel", "tanstack", "litellm")):
        areas.append("公開Web/開発・検証環境")
    if any(keyword in text for keyword in ("trend micro", "apex one", "security")):
        areas.append("セキュリティ製品")
    return "、".join(areas) if areas else "対象製品の利用有無確認"


def monthly_focus_section(rows: list[dict[str, str]], recent_days: int, today: date) -> str:
    recent_rows = recent_focus_rows(rows, recent_days, today)
    if recent_rows is None:
        return "現時点では新規追加日の情報がないため、抽出理由とCVE公開年を表示します。"

    if not recent_rows:
        return "今回の掲載範囲では、直近のKEV追加日を持つCVEはありません。抽出理由とCVE公開年を確認してください。"
    return compact_cve_list(recent_rows)


def recent_focus_rows(rows: list[dict[str, str]], recent_days: int, today: date) -> list[dict[str, str]] | None:
    dated_rows = [(row, parse_date(row.get("date_added") or "")) for row in rows]
    if not any(row_date for _, row_date in dated_rows):
        return None

    cutoff = today - timedelta(days=recent_days)
    return [row for row, row_date in dated_rows if row_date and row_date >= cutoff]


def recent_focus_cves(rows: list[dict[str, str]], recent_days: int, today: date) -> set[str]:
    recent_rows = recent_focus_rows(rows, recent_days, today)
    if not recent_rows:
        return set()
    return {row.get("cve_id", "") for row in recent_rows}


def continuing_high_epss_section(rows: list[dict[str, str]], exclude_cves: set[str] | None = None) -> str:
    exclude_cves = exclude_cves or set()
    high_epss_rows = [
        row for row in rows if safe_float(row.get("epss")) >= 0.9 and row.get("cve_id", "") not in exclude_cves
    ]
    if not high_epss_rows:
        return "今回の掲載範囲では、直近条件で抽出された注目候補と重複しないEPSS 0.9以上の継続確認候補はありません。"
    return compact_cve_list(high_epss_rows)


def compact_cve_list(rows: list[dict[str, str]], limit: int = 5) -> str:
    lines = []
    for row in rows[:limit]:
        lines.append(
            f"- {cell(row.get('cve_id'))}: {cell(row.get('vendor'))} {cell(row.get('product'))}、{extraction_reason(row)}、一次確認区分 {initial_check_category(row)}"
        )
    if len(rows) > limit:
        lines.append(f"- ほか {len(rows) - limit} 件は個別CVE確認表を参照してください。")
    return "\n".join(lines)


def sample_data_notice_lines(used_sample: bool) -> list[str]:
    if not used_sample:
        return []
    return [
        "- 注記: サンプルデータ利用中。この出力はレポート形式確認用であり、"
        "実際の月次脆弱性状況を示すものではありません。"
    ]


def data_source_label(used_sample: bool, with_nvd: bool) -> str:
    if used_sample:
        return "サンプルCSV"
    if with_nvd:
        return "CISA KEV / FIRST EPSS / NVD"
    return "CISA KEV / FIRST EPSS"


def is_kev(row: dict[str, str]) -> bool:
    return row.get("kev", "").lower() == "true"


def kev_label(row: dict[str, str]) -> str:
    return "該当" if is_kev(row) else "非該当"


def initial_check_category(row: dict[str, str]) -> str:
    if is_kev(row) and safe_float(row.get("epss")) >= 0.9:
        return "優先確認"
    if is_kev(row) and safe_float(row.get("epss")) >= 0.7:
        return "早期確認"
    return "通常確認"


def extraction_reason(row: dict[str, str]) -> str:
    if is_kev(row) and safe_float(row.get("epss")) >= 0.9:
        return "KEV該当・高EPSS"
    if is_kev(row) and safe_float(row.get("epss")) >= 0.7:
        return "KEV該当・中EPSS"
    if is_kev(row):
        return "KEV該当"
    return "EPSS確認候補"


def cve_year(row: dict[str, str]) -> str:
    cve_id = row.get("cve_id") or ""
    parts = cve_id.split("-")
    if len(parts) >= 3 and parts[0].upper() == "CVE" and parts[1].isdigit():
        return parts[1]
    return ""


def kev_added_date(row: dict[str, str]) -> str:
    return cell(row.get("date_added"))


def format_score(raw: str | None) -> str:
    score = safe_float(raw)
    return f"{score:.3f}" if score else ""


def cell(raw: str | None) -> str:
    return (raw or "").replace("|", "\\|").replace("\n", " ")


def chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
