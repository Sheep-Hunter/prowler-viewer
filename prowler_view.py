#!/usr/bin/env python3
"""
prowler-view: turn Prowler CSV output into a browsable HTML report.

Prowler writes one CSV row per (check, resource) pair, so a single misconfiguration
affecting 400 buckets becomes 400 near-identical rows. This script regroups that data
into a Scout Suite style tree:

    service  ->  finding (one per check)  ->  affected resources

Every row for a given check carries identical DESCRIPTION / RISK / REMEDIATION_* text,
so we keep it once on the finding and keep only the genuinely per-resource fields
(RESOURCE_UID, REGION, ACCOUNT_UID, STATUS_EXTENDED) in the resource table.

Output is a single self-contained HTML file: no server, no dependencies, no network.

Usage:
    python prowler_view.py ./output/                    # whole directory
    python prowler_view.py scan.csv -o report.html      # one file
    python prowler_view.py ./output/ --include-pass     # keep PASS results too
    python prowler_view.py scan.csv --doctor            # inspect schema, print no findings

Standard library only. Tested against Prowler 5.42.0 CSV output (raw CLI and dashboard).
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.0.0"

# --------------------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------------------

# Columns emitted by CSV.transform() in prowler/lib/outputs/csv/csv.py as of 5.42.0.
# We resolve by NAME, never by position, because the `prowler dashboard` layer prepends
# DATE, appends ASSESSMENT_TIME and moves FINDING_UID to the front. Order is not stable;
# names are.
EXPECTED_COLUMNS = [
    "AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
    "FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE", "STATUS",
    "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME", "SEVERITY",
    "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME", "RESOURCE_DETAILS",
    "RESOURCE_TAGS", "PARTITION", "REGION", "DESCRIPTION", "RISK", "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT", "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC", "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_CLI", "REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES",
    "DEPENDS_ON", "RELATED_TO", "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS",
    "ACCOUNT_OU_UID", "ACCOUNT_OU_NAME",
]

# Added by `prowler dashboard`, not by the CLI writer. Known, not warned about.
DASHBOARD_COLUMNS = ["DATE", "ASSESSMENT_TIME"]

# Columns that must exist for the file to be a findings CSV at all. Prowler also writes
# per-framework compliance CSVs with a completely different schema into output/compliance/,
# and we skip those rather than crashing on them.
REQUIRED_COLUMNS = ["CHECK_ID", "STATUS", "SEVERITY"]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

STATUS_ORDER = ["FAIL", "MANUAL", "PASS"]


# --------------------------------------------------------------------------------------
# CSV reading
# --------------------------------------------------------------------------------------

def find_csv_files(paths):
    """Expand the given files/directories into a sorted list of .csv paths."""
    found = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found.extend(sorted(p.rglob("*.csv")))
        elif p.is_file():
            found.append(p)
        else:
            print(f"warning: no such file or directory: {p}", file=sys.stderr)
    # Deduplicate while preserving order; a user may pass both a dir and a file in it.
    seen, unique = set(), []
    for p in found:
        key = str(p.resolve()).lower()
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def sniff_delimiter(sample_line):
    """Prowler writes ';' but users re-export as ',' from Excel often enough to matter."""
    counts = {d: sample_line.count(d) for d in (";", ",", "\t", "|")}
    best = max(counts, key=counts.get)
    return best if counts[best] > 0 else ";"


def open_text(path):
    """Read a file as text, tolerating a BOM and the odd non-UTF-8 byte."""
    try:
        return path.open("r", encoding="utf-8-sig", newline="")
    except UnicodeDecodeError:
        return path.open("r", encoding="latin-1", newline="")


def normalise_header(name):
    return (name or "").strip().lstrip("\ufeff").upper()


def read_csv_file(path):
    """
    Yield (rows, header) for one CSV. Rows are dicts keyed by normalised column name.

    Returns (None, header) if the file does not look like a Prowler findings CSV, so the
    caller can skip compliance exports and unrelated CSVs without failing the whole run.
    """
    with open_text(path) as fh:
        first = fh.readline()
        if not first.strip():
            return None, []
        delimiter = sniff_delimiter(first)
        fh.seek(0)

        reader = csv.reader(fh, delimiter=delimiter)
        try:
            header = [normalise_header(h) for h in next(reader)]
        except StopIteration:
            return None, []

        if not all(col in header for col in REQUIRED_COLUMNS):
            return None, header

        rows = []
        width = len(header)
        for raw in reader:
            if not raw or (len(raw) == 1 and not raw[0].strip()):
                continue
            # Pad or trim defensively: a stray unescaped delimiter should not abort the run.
            if len(raw) < width:
                raw = raw + [""] * (width - len(raw))
            elif len(raw) > width:
                raw = raw[:width]
            rows.append(dict(zip(header, raw)))
        return rows, header


def load_rows(paths):
    """Read every findings CSV under `paths`. Returns (rows, per_file_report)."""
    # RESOURCE_DETAILS and RESOURCE_TAGS can hold very large embedded JSON blobs.
    try:
        csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    except OverflowError:
        csv.field_size_limit(2**31 - 1)

    all_rows, report = [], []
    for path in find_csv_files(paths):
        try:
            rows, header = read_csv_file(path)
        except Exception as exc:  # a single bad file should not lose the whole scan
            report.append({"path": str(path), "status": "error", "detail": str(exc)})
            continue

        if rows is None:
            missing = [c for c in REQUIRED_COLUMNS if c not in header]
            report.append({
                "path": str(path),
                "status": "skipped",
                "detail": f"not a findings CSV (missing {', '.join(missing) or 'header'})",
                "columns": header,
            })
            continue

        all_rows.extend(rows)
        report.append({
            "path": str(path), "status": "read", "rows": len(rows), "columns": header,
        })
    return all_rows, report


# --------------------------------------------------------------------------------------
# Field access helpers
# --------------------------------------------------------------------------------------

def get(row, column, default=""):
    value = row.get(column)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def as_bool(value):
    return str(value).strip().lower() in ("true", "1", "yes")


def split_list(value, separators=("|", ",")):
    """COMPLIANCE and CATEGORIES are delimited strings whose separator varies by field."""
    if not value:
        return []
    parts = [value]
    for sep in separators:
        nxt = []
        for part in parts:
            nxt.extend(part.split(sep))
        parts = nxt
    return [p.strip() for p in parts if p.strip()]


def normalise_severity(value):
    value = (value or "").strip().lower()
    return value if value in SEVERITY_RANK else "informational"


# --------------------------------------------------------------------------------------
# Model building
# --------------------------------------------------------------------------------------

def build_model(rows, include_pass=False, include_muted=True):
    """Collapse per-resource rows into per-check findings grouped by service."""
    findings = {}
    accounts, regions, providers = {}, set(), set()
    scan_times, prowler_versions = set(), set()
    dropped = Counter()

    for row in rows:
        status = get(row, "STATUS", "UNKNOWN").upper()
        muted = as_bool(get(row, "MUTED", "False"))

        if status == "PASS" and not include_pass:
            dropped["PASS"] += 1
            continue
        if muted and not include_muted:
            dropped["MUTED"] += 1
            continue

        provider = get(row, "PROVIDER", "aws").lower()
        check_id = get(row, "CHECK_ID", "unknown_check")
        key = f"{provider}::{check_id}"

        if key not in findings:
            findings[key] = {
                "id": key,
                "checkId": check_id,
                "provider": provider,
                "title": get(row, "CHECK_TITLE", check_id),
                "service": get(row, "SERVICE_NAME", "other").lower(),
                "subservice": get(row, "SUBSERVICE_NAME"),
                "severity": normalise_severity(get(row, "SEVERITY")),
                "resourceType": get(row, "RESOURCE_TYPE"),
                "description": get(row, "DESCRIPTION"),
                "risk": get(row, "RISK"),
                "remediationText": get(row, "REMEDIATION_RECOMMENDATION_TEXT"),
                "remediationUrl": get(row, "REMEDIATION_RECOMMENDATION_URL"),
                "codeCli": get(row, "REMEDIATION_CODE_CLI"),
                "codeTerraform": get(row, "REMEDIATION_CODE_TERRAFORM"),
                "codeIac": get(row, "REMEDIATION_CODE_NATIVEIAC"),
                "codeOther": get(row, "REMEDIATION_CODE_OTHER"),
                "urls": [],
                "compliance": split_list(get(row, "COMPLIANCE"), separators=("|",)),
                "categories": split_list(get(row, "CATEGORIES")),
                "notes": get(row, "NOTES"),
                "resources": [],
            }
            # RELATED_URL is a single link; ADDITIONAL_URLS is a delimited list.
            for url in [get(row, "RELATED_URL")] + split_list(get(row, "ADDITIONAL_URLS")):
                if url.startswith("http") and url not in findings[key]["urls"]:
                    findings[key]["urls"].append(url)

        finding = findings[key]

        account_uid = get(row, "ACCOUNT_UID", "unknown")
        region = get(row, "REGION", "global")
        regions.add(region)
        providers.add(provider)
        if account_uid not in accounts:
            accounts[account_uid] = {
                "uid": account_uid,
                "name": get(row, "ACCOUNT_NAME"),
                "ou": get(row, "ACCOUNT_OU_NAME"),
                "organization": get(row, "ACCOUNT_ORGANIZATION_NAME"),
            }

        for column in ("ASSESSMENT_TIME", "DATE", "TIMESTAMP"):
            stamp = get(row, column)
            if stamp:
                scan_times.add(stamp)
                break
        version = get(row, "PROWLER_VERSION")
        if version:
            prowler_versions.add(version)

        finding["resources"].append({
            "uid": get(row, "RESOURCE_UID"),
            "name": get(row, "RESOURCE_NAME"),
            "region": region,
            "account": account_uid,
            "status": status,
            "reason": get(row, "STATUS_EXTENDED"),
            "muted": muted,
            "tags": get(row, "RESOURCE_TAGS"),
        })

    # A check can legitimately return different severities across resources in rare cases;
    # roll the finding up to its worst severity so nothing hides under a low badge.
    for finding in findings.values():
        statuses = {r["status"] for r in finding["resources"]}
        finding["status"] = (
            "FAIL" if "FAIL" in statuses
            else "MANUAL" if "MANUAL" in statuses
            else "PASS"
        )
        finding["muted"] = all(r["muted"] for r in finding["resources"])
        finding["failCount"] = sum(1 for r in finding["resources"] if r["status"] == "FAIL")
        finding["resourceCount"] = len(finding["resources"])
        finding["accounts"] = sorted({r["account"] for r in finding["resources"]})
        finding["regions"] = sorted({r["region"] for r in finding["resources"]})
        finding["resources"].sort(key=lambda r: (r["status"] != "FAIL", r["region"], r["uid"]))

    ordered = sorted(
        findings.values(),
        key=lambda f: (
            SEVERITY_RANK[f["severity"]],
            STATUS_ORDER.index(f["status"]) if f["status"] in STATUS_ORDER else 9,
            -f["resourceCount"],
            f["title"].lower(),
        ),
    )

    services = build_service_index(ordered)

    return {
        "meta": {
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "scanTime": sorted(scan_times)[-1] if scan_times else "unknown",
            "prowlerVersion": ", ".join(sorted(prowler_versions)) or "unknown",
            "toolVersion": __version__,
            "providers": sorted(providers),
            "accounts": [accounts[k] for k in sorted(accounts)],
            "regions": sorted(regions),
            "includePass": include_pass,
            "totalRows": len(rows),
            "droppedPass": dropped["PASS"],
            "findingCount": len(ordered),
            "severityCounts": count_by_severity(ordered),
        },
        "services": services,
        "findings": ordered,
    }


def build_service_index(findings):
    """Sidebar data: one entry per service with its severity breakdown."""
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding["service"]].append(finding)

    services = []
    for name, items in grouped.items():
        services.append({
            "name": name,
            "findingCount": len(items),
            "resourceCount": sum(f["resourceCount"] for f in items),
            "severityCounts": count_by_severity(items),
            "worst": min(SEVERITY_RANK[f["severity"]] for f in items),
        })
    services.sort(key=lambda s: (s["worst"], -s["findingCount"], s["name"]))
    return services


def count_by_severity(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


# --------------------------------------------------------------------------------------
# Doctor mode
# --------------------------------------------------------------------------------------

def run_doctor(paths):
    """
    Print schema diagnostics only: column names, counts and low-cardinality enum values.

    Deliberately prints no finding text, resource identifiers, account IDs or ARNs, so the
    output is safe to share out of a restricted environment when something needs debugging.
    """
    rows, report = load_rows(paths)

    print(f"prowler-view {__version__} doctor")
    print("=" * 70)

    for entry in report:
        name = Path(entry["path"]).name
        if entry["status"] == "read":
            print(f"  [read]    {name}  ({entry['rows']} rows, {len(entry['columns'])} columns)")
        elif entry["status"] == "skipped":
            print(f"  [skipped] {name}  {entry['detail']}")
        else:
            print(f"  [ERROR]   {name}  {entry['detail']}")

    header = next((e["columns"] for e in report if e["status"] == "read"), [])
    if not header:
        print("\nNo readable findings CSV. Nothing further to report.")
        return 1

    known = set(EXPECTED_COLUMNS) | set(DASHBOARD_COLUMNS)
    missing = [c for c in EXPECTED_COLUMNS if c not in header]
    unexpected = [c for c in header if c not in known]

    print(f"\nColumns found: {len(header)}")
    print(f"  Expected columns missing : {', '.join(missing) if missing else 'none'}")
    print(f"  Unrecognised columns     : {', '.join(unexpected) if unexpected else 'none'}")
    if unexpected:
        print("  ^ these are ignored by the report. Send this list if you want them used.")

    print(f"\nTotal rows across all files: {len(rows)}")
    for column in ("STATUS", "SEVERITY", "PROVIDER", "MUTED"):
        counts = Counter(get(r, column, "(empty)") for r in rows)
        rendered = ", ".join(f"{v}={n}" for v, n in counts.most_common())
        print(f"  {column:<9}: {rendered}")

    services = Counter(get(r, "SERVICE_NAME", "(empty)") for r in rows)
    print(f"\nServices present ({len(services)}):")
    print("  " + ", ".join(f"{s}({n})" for s, n in services.most_common()))

    empties = [c for c in header if all(not get(r, c) for r in rows)]
    if empties:
        print(f"\nColumns empty in every row: {', '.join(empties)}")

    print("\nThis output contains no finding text, resource names or account identifiers.")
    return 0


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------

def render_html(model, title):
    payload = json.dumps(model, separators=(",", ":"), ensure_ascii=False)
    # The payload sits inside a <script> block, so no raw '<' may survive. Escaping it as
    # \u003c is valid JSON and cannot terminate the tag early.
    payload = payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return HTML_TEMPLATE.replace("__TITLE__", escape_text(title)).replace("__DATA__", payload)


def escape_text(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="prowler-view",
        description="Turn Prowler CSV output into a browsable single-file HTML report.",
    )
    parser.add_argument("paths", nargs="+", help="CSV file(s) or directory to read")
    parser.add_argument("-o", "--output", default="prowler-report.html",
                        help="output HTML path (default: prowler-report.html)")
    parser.add_argument("--include-pass", action="store_true",
                        help="keep PASS results (default: FAIL and MANUAL only)")
    parser.add_argument("--exclude-muted", action="store_true",
                        help="drop muted findings entirely")
    parser.add_argument("--title", default="Prowler Findings",
                        help="report title shown in the header")
    parser.add_argument("--doctor", action="store_true",
                        help="print schema diagnostics only; writes no report")
    parser.add_argument("--version", action="version", version=f"prowler-view {__version__}")
    args = parser.parse_args(argv)

    if args.doctor:
        return run_doctor(args.paths)

    rows, report = load_rows(args.paths)

    for entry in report:
        if entry["status"] == "skipped":
            print(f"skipping {Path(entry['path']).name}: {entry['detail']}", file=sys.stderr)
        elif entry["status"] == "error":
            print(f"error reading {Path(entry['path']).name}: {entry['detail']}", file=sys.stderr)

    if not rows:
        print("No findings rows read. Run with --doctor to inspect the input.", file=sys.stderr)
        return 1

    model = build_model(
        rows,
        include_pass=args.include_pass,
        include_muted=not args.exclude_muted,
    )

    if not model["findings"]:
        print("Every row was filtered out. Try --include-pass.", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.write_text(render_html(model, args.title), encoding="utf-8")

    meta = model["meta"]
    sev = meta["severityCounts"]
    size_mb = output.stat().st_size / (1024 * 1024)

    files_read = sum(1 for e in report if e["status"] == "read")
    print(f"Read {meta['totalRows']} rows from {files_read} file(s).")
    if meta["droppedPass"]:
        print(f"Filtered out {meta['droppedPass']} PASS rows (use --include-pass to keep them).")
    print(f"Grouped into {meta['findingCount']} findings across {len(model['services'])} services.")
    print("  " + "  ".join(f"{s}: {sev[s]}" for s in SEVERITY_ORDER if sev[s]))
    print(f"Wrote {output.resolve()} ({size_mb:.1f} MB)")
    return 0


# --------------------------------------------------------------------------------------
# HTML template
# --------------------------------------------------------------------------------------
# Single self-contained page. No external fonts, scripts or stylesheets: restricted
# environments block CDNs, and a report that only renders online is useless offline.

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --panel-2: #1c222b; --border: #2b3240;
    --text: #e6edf3; --muted: #8b949e; --accent: #4493f8;
    --critical: #f85149; --high: #ff8c42; --medium: #e3b341; --low: #4493f8; --informational: #8b949e;
    --fail: #f85149; --pass: #3fb950; --manual: #a371f7;
  }
  [data-theme="light"] {
    --bg: #ffffff; --panel: #f6f8fa; --panel-2: #eaeef2; --border: #d0d7de;
    --text: #1f2328; --muted: #656d76; --accent: #0969da;
    --critical: #cf222e; --high: #bc4c00; --medium: #9a6700; --low: #0969da; --informational: #656d76;
    --fail: #cf222e; --pass: #1a7f37; --manual: #8250df;
  }
  * { box-sizing: border-box; }
  /* Full-height flex column: the topbar is a plain flex item and the row below it fills the
     rest. The sidebar and findings list then scroll independently, and nothing needs to know
     how tall the topbar is - it wraps to more rows as the window narrows. */
  body {
    margin: 0; background: var(--bg); color: var(--text);
    height: 100vh; overflow: hidden; display: flex; flex-direction: column;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }

  /* ---- top bar ---- */
  .topbar {
    display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
    padding: 12px 20px; background: var(--panel); border-bottom: 1px solid var(--border);
    flex: none; z-index: 20;
  }
  .brand { font-size: 16px; font-weight: 600; margin-right: 4px; }
  .brand small { display: block; font-size: 11px; font-weight: 400; color: var(--muted); }
  .totals { display: flex; gap: 8px; flex-wrap: wrap; }
  .pill {
    display: inline-flex; align-items: baseline; gap: 6px; padding: 3px 10px;
    border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border);
    font-size: 12px; cursor: pointer; user-select: none;
  }
  .pill.off { opacity: 0.35; }
  .pill b { font-size: 13px; }
  .pill .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .spacer { flex: 1; }
  .topbar input[type="search"] {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    padding: 7px 12px; border-radius: 6px; width: 300px; font-size: 13px;
  }
  .topbar input[type="search"]:focus { outline: none; border-color: var(--accent); }
  button.ghost {
    background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;
  }
  button.ghost:hover { border-color: var(--accent); }
  select {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    padding: 6px 10px; border-radius: 6px; font-size: 12px; max-width: 220px;
  }

  /* ---- layout ---- */
  .layout { display: flex; flex: 1; min-height: 0; overflow: hidden; }
  .sidebar {
    width: 260px; flex: none; border-right: 1px solid var(--border);
    overflow-y: auto; background: var(--panel); padding: 12px 0;
  }
  /* Dark-theme scrollbars; the browser default cuts a bright strip down the page. */
  .sidebar, .table-wrap, pre { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
  .sidebar::-webkit-scrollbar, .table-wrap::-webkit-scrollbar, pre::-webkit-scrollbar {
    width: 10px; height: 10px;
  }
  .sidebar::-webkit-scrollbar-thumb, .table-wrap::-webkit-scrollbar-thumb,
  pre::-webkit-scrollbar-thumb { background: var(--border); border-radius: 5px; }
  .sidebar::-webkit-scrollbar-track, .table-wrap::-webkit-scrollbar-track,
  pre::-webkit-scrollbar-track { background: transparent; }
  .side-item {
    display: block; width: 100%; text-align: left; background: none; border: none;
    color: var(--text); padding: 8px 16px; cursor: pointer; border-left: 3px solid transparent;
  }
  .side-item:hover { background: var(--panel-2); }
  .side-item.active { background: var(--panel-2); border-left-color: var(--accent); }
  .side-name { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; }
  .side-name strong { font-weight: 600; font-size: 13px; }
  .side-name span { color: var(--muted); font-size: 11px; }
  .sevbar { display: flex; gap: 2px; margin-top: 5px; height: 4px; border-radius: 2px; overflow: hidden; }
  .sevbar i { display: block; height: 100%; }
  .side-head {
    padding: 10px 16px 6px; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--muted); font-weight: 600;
  }

  .main { flex: 1; min-width: 0; overflow-y: auto; padding: 20px 24px 80px; }
  .main-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 4px; }
  .main-head h1 { font-size: 20px; margin: 0; }
  .main-head .count { color: var(--muted); font-size: 13px; }
  .subhead { color: var(--muted); font-size: 12px; margin-bottom: 18px; }

  /* ---- finding cards ---- */
  .finding {
    border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px;
    background: var(--panel); overflow: hidden;
  }
  .finding-head {
    display: flex; align-items: center; gap: 12px; padding: 12px 14px;
    cursor: pointer; border-left: 4px solid var(--border);
  }
  .finding-head:hover { background: var(--panel-2); }
  .finding.critical .finding-head { border-left-color: var(--critical); }
  .finding.high     .finding-head { border-left-color: var(--high); }
  .finding.medium   .finding-head { border-left-color: var(--medium); }
  .finding.low      .finding-head { border-left-color: var(--low); }
  .finding.informational .finding-head { border-left-color: var(--informational); }
  .chev { color: var(--muted); flex: none; width: 12px; transition: transform 0.12s; }
  .finding.open .chev { transform: rotate(90deg); }
  .badge {
    flex: none; font-size: 10px; font-weight: 700; letter-spacing: 0.05em;
    text-transform: uppercase; padding: 3px 8px; border-radius: 4px; color: #fff; min-width: 68px;
    text-align: center;
  }
  .badge.critical { background: var(--critical); }
  .badge.high { background: var(--high); }
  .badge.medium { background: var(--medium); color: #1a1a1a; }
  .badge.low { background: var(--low); }
  .badge.informational { background: var(--informational); }
  .finding-title { flex: 1; min-width: 0; }
  .finding-title strong { font-weight: 500; display: block; }
  .finding-title .checkid { color: var(--muted); font-size: 11px; }
  .rescount {
    flex: none; font-size: 12px; color: var(--muted); background: var(--panel-2);
    border: 1px solid var(--border); padding: 3px 10px; border-radius: 999px; white-space: nowrap;
  }
  .rescount b { color: var(--text); }
  .tag {
    font-size: 10px; padding: 2px 6px; border-radius: 3px;
    border: 1px solid var(--border); color: var(--muted);
  }
  .tag.muted-tag { border-color: var(--manual); color: var(--manual); }

  .finding-body { display: none; padding: 4px 16px 18px 44px; border-top: 1px solid var(--border); }
  .finding.open .finding-body { display: block; }
  .section { margin-top: 16px; }
  .section h3 {
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted); margin: 0 0 6px;
  }
  .section p { margin: 0 0 8px; max-width: 90ch; }
  pre {
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; overflow-x: auto; font-size: 12px; margin: 0 0 8px;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 5px; }
  .chip {
    font-size: 11px; padding: 2px 8px; border-radius: 4px;
    background: var(--panel-2); border: 1px solid var(--border); color: var(--muted);
  }
  a { color: var(--accent); }

  /* ---- resource table ---- */
  .res-tools { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
  .res-tools input {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    padding: 5px 10px; border-radius: 5px; font-size: 12px; width: 260px;
  }
  /* Own scroll container, so the sticky <th> pins to the table rather than the viewport. */
  .table-wrap {
    overflow: auto; max-height: 60vh;
    border: 1px solid var(--border); border-radius: 6px;
  }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  th {
    text-align: left; padding: 7px 10px; background: var(--panel-2);
    border-bottom: 1px solid var(--border); font-weight: 600; white-space: nowrap;
    position: sticky; top: 0; cursor: pointer; user-select: none;
  }
  th:hover { color: var(--accent); }
  td { padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  td.uid { font-family: ui-monospace, Consolas, monospace; font-size: 11px; word-break: break-all; max-width: 380px; }
  .st { font-weight: 600; font-size: 11px; }
  .st.FAIL { color: var(--fail); } .st.PASS { color: var(--pass); } .st.MANUAL { color: var(--manual); }
  .more-row { padding: 8px 10px; color: var(--muted); font-size: 12px; background: var(--panel-2); }
  .more-row button { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 12px; }

  .empty { color: var(--muted); padding: 60px 0; text-align: center; }

  @media print {
    :root { --bg:#fff; --panel:#fff; --panel-2:#f6f8fa; --border:#d0d7de; --text:#000; --muted:#555; }
    .sidebar, .topbar .spacer, .topbar input, .topbar button, .topbar select, .res-tools { display: none !important; }
    /* Undo the fixed-height app shell so the whole report flows across printed pages. */
    body { height: auto; overflow: visible; display: block; }
    .layout { display: block; overflow: visible; min-height: 0; }
    .main { overflow: visible; padding: 0; }
    .sidebar { display: none; }
    .finding-body { display: block !important; }
    .finding { break-inside: avoid; }
    .table-wrap { max-height: none; overflow: visible; }
    th { position: static; }
  }
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">__TITLE__<small id="meta-line"></small></div>
  <div class="totals" id="sev-filters"></div>
  <div class="spacer"></div>
  <select id="account-filter"><option value="">All accounts</option></select>
  <select id="region-filter"><option value="">All regions</option></select>
  <input type="search" id="search" placeholder="Search findings and resources...">
  <button class="ghost" id="expand-all">Expand all</button>
  <button class="ghost" id="theme-toggle">Light</button>
</div>

<div class="layout">
  <aside class="sidebar" id="sidebar"></aside>
  <main class="main">
    <div class="main-head"><h1 id="view-title">All findings</h1><span class="count" id="view-count"></span></div>
    <div class="subhead" id="view-sub"></div>
    <div id="findings"></div>
  </main>
</div>

<script type="application/json" id="report-data">__DATA__</script>
<script>
(function () {
  "use strict";

  var DATA = JSON.parse(document.getElementById("report-data").textContent);
  var SEVERITIES = ["critical", "high", "medium", "low", "informational"];
  var RESOURCE_PAGE = 200;   // rows rendered before the "show all" link

  var state = {
    service: null,                      // null = all services
    severities: new Set(SEVERITIES),
    account: "",
    region: "",
    query: "",
    open: new Set(),
    shownAll: new Set()
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }

  // ---- filtering -------------------------------------------------------------------

  function matchesQuery(f, q) {
    if (!q) return true;
    if ((f.title + " " + f.checkId + " " + f.description + " " + f.risk +
         " " + f.service + " " + f.compliance.join(" ")).toLowerCase().indexOf(q) !== -1) {
      return true;
    }
    // Also search resource identifiers, so you can paste an ARN and find its findings.
    return f.resources.some(function (r) {
      return (r.uid + " " + r.name + " " + r.reason).toLowerCase().indexOf(q) !== -1;
    });
  }

  function visibleResources(f) {
    return f.resources.filter(function (r) {
      if (state.account && r.account !== state.account) return false;
      if (state.region && r.region !== state.region) return false;
      return true;
    });
  }

  function filtered() {
    var q = state.query.trim().toLowerCase();
    var out = [];
    for (var i = 0; i < DATA.findings.length; i++) {
      var f = DATA.findings[i];
      if (state.service && f.service !== state.service) continue;
      if (!state.severities.has(f.severity)) continue;
      if (!matchesQuery(f, q)) continue;
      // An account/region filter must hide findings with nothing left to show.
      if ((state.account || state.region) && visibleResources(f).length === 0) continue;
      out.push(f);
    }
    return out;
  }

  // ---- rendering -------------------------------------------------------------------

  function renderMeta() {
    var m = DATA.meta;
    var bits = ["Scanned " + m.scanTime, "Prowler " + m.prowlerVersion,
                plural(m.accounts.length, "account")];
    if (!m.includePass) bits.push("FAIL/MANUAL only");
    document.getElementById("meta-line").textContent = bits.join("  \u00b7  ");

    var acct = document.getElementById("account-filter");
    m.accounts.forEach(function (a) {
      var o = document.createElement("option");
      o.value = a.uid;
      o.textContent = a.name ? a.name + " (" + a.uid + ")" : a.uid;
      acct.appendChild(o);
    });
    var reg = document.getElementById("region-filter");
    m.regions.forEach(function (r) {
      var o = document.createElement("option");
      o.value = r; o.textContent = r;
      reg.appendChild(o);
    });
  }

  function renderSeverityFilters() {
    var counts = DATA.meta.severityCounts;
    document.getElementById("sev-filters").innerHTML = SEVERITIES.map(function (s) {
      if (!counts[s]) return "";
      var on = state.severities.has(s);
      return '<span class="pill' + (on ? "" : " off") + '" data-sev="' + s + '">' +
             '<span class="dot" style="background:var(--' + s + ')"></span>' +
             '<b>' + counts[s] + '</b> ' + s + '</span>';
    }).join("");
  }

  function renderSidebar() {
    var total = DATA.meta.findingCount;
    var html = '<div class="side-head">Overview</div>' +
      '<button class="side-item' + (state.service === null ? " active" : "") + '" data-service="">' +
        '<span class="side-name"><strong>All findings</strong><span>' + total + '</span></span>' +
      '</button>' +
      '<div class="side-head">Services (' + DATA.services.length + ')</div>';

    html += DATA.services.map(function (s) {
      var bar = SEVERITIES.map(function (sev) {
        var n = s.severityCounts[sev];
        if (!n) return "";
        var pct = (n / s.findingCount) * 100;
        return '<i style="width:' + pct + '%;background:var(--' + sev + ')"></i>';
      }).join("");
      return '<button class="side-item' + (state.service === s.name ? " active" : "") +
             '" data-service="' + esc(s.name) + '">' +
             '<span class="side-name"><strong>' + esc(s.name) + '</strong>' +
             '<span>' + s.findingCount + '</span></span>' +
             '<span class="sevbar">' + bar + '</span></button>';
    }).join("");

    document.getElementById("sidebar").innerHTML = html;
  }

  function resourceTable(f) {
    var rows = visibleResources(f);
    var showAll = state.shownAll.has(f.id);
    var slice = showAll ? rows : rows.slice(0, RESOURCE_PAGE);

    var body = slice.map(function (r) {
      return "<tr>" +
        '<td class="uid">' + esc(r.uid || r.name || "-") + "</td>" +
        "<td>" + esc(r.name || "-") + "</td>" +
        "<td>" + esc(r.region) + "</td>" +
        "<td>" + esc(r.account) + "</td>" +
        '<td class="st ' + esc(r.status) + '">' + esc(r.status) + "</td>" +
        "<td>" + esc(r.reason || "") + "</td>" +
      "</tr>";
    }).join("");

    var more = "";
    if (rows.length > slice.length) {
      more = '<div class="more-row">Showing ' + slice.length + " of " + rows.length +
             ' resources. <button data-showall="' + f.id + '">Show all</button></div>';
    }

    return '<div class="res-tools">' +
             '<input type="text" placeholder="Filter these resources..." data-resfilter="' + f.id + '">' +
             '<span class="chip">' + plural(rows.length, "resource") + '</span>' +
           "</div>" +
           '<div class="table-wrap"><table data-restable="' + f.id + '"><thead><tr>' +
             "<th>Resource</th><th>Name</th><th>Region</th><th>Account</th><th>Status</th><th>Reason</th>" +
           "</tr></thead><tbody>" + body + "</tbody></table>" + more + "</div>";
  }

  function codeBlock(label, code) {
    if (!code) return "";
    return '<div class="section"><h3>' + label + "</h3><pre>" + esc(code) + "</pre></div>";
  }

  function findingBody(f) {
    var html = "";
    if (f.description) html += '<div class="section"><h3>Description</h3><p>' + esc(f.description) + "</p></div>";
    if (f.risk) html += '<div class="section"><h3>Risk</h3><p>' + esc(f.risk) + "</p></div>";

    if (f.remediationText || f.remediationUrl || f.urls.length) {
      html += '<div class="section"><h3>Remediation</h3>';
      if (f.remediationText) html += "<p>" + esc(f.remediationText) + "</p>";
      var links = f.urls.slice();
      if (f.remediationUrl && links.indexOf(f.remediationUrl) === -1) links.unshift(f.remediationUrl);
      if (links.length) {
        html += '<div class="chips">' + links.map(function (u) {
          return '<a class="chip" href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u) + "</a>";
        }).join("") + "</div>";
      }
      html += "</div>";
    }

    html += codeBlock("Fix &mdash; CLI", f.codeCli);
    html += codeBlock("Fix &mdash; Terraform", f.codeTerraform);
    html += codeBlock("Fix &mdash; IaC", f.codeIac);
    html += codeBlock("Fix &mdash; other", f.codeOther);

    html += '<div class="section"><h3>Affected resources</h3>' + resourceTable(f) + "</div>";

    var meta = ['<span class="chip">' + esc(f.checkId) + "</span>"];
    if (f.resourceType) meta.push('<span class="chip">' + esc(f.resourceType) + "</span>");
    f.categories.forEach(function (c) { meta.push('<span class="chip">' + esc(c) + "</span>"); });
    html += '<div class="section"><h3>Metadata</h3><div class="chips">' + meta.join("") + "</div></div>";

    if (f.compliance.length) {
      html += '<div class="section"><h3>Compliance</h3><div class="chips">' +
        f.compliance.map(function (c) { return '<span class="chip">' + esc(c) + "</span>"; }).join("") +
      "</div></div>";
    }
    return html;
  }

  function renderFindings() {
    var list = filtered();
    document.getElementById("view-title").textContent = state.service || "All findings";
    document.getElementById("view-count").textContent =
      plural(list.length, "finding") + " \u00b7 " +
      plural(list.reduce(function (n, f) { return n + visibleResources(f).length; }, 0), "affected resource");

    var sub = [];
    if (state.account) sub.push("account " + state.account);
    if (state.region) sub.push("region " + state.region);
    if (state.query) sub.push('matching "' + state.query + '"');
    document.getElementById("view-sub").textContent = sub.length ? "Filtered to " + sub.join(", ") : "";

    var host = document.getElementById("findings");
    if (!list.length) {
      host.innerHTML = '<div class="empty">No findings match the current filters.</div>';
      return;
    }

    host.innerHTML = list.map(function (f) {
      var open = state.open.has(f.id);
      var n = visibleResources(f).length;
      var tags = "";
      if (f.muted) tags += ' <span class="tag muted-tag">muted</span>';
      if (f.status === "MANUAL") tags += ' <span class="tag">manual</span>';
      if (f.status === "PASS") tags += ' <span class="tag">pass</span>';

      return '<div class="finding ' + f.severity + (open ? " open" : "") + '" id="f-' + esc(f.id) + '">' +
        '<div class="finding-head" data-toggle="' + esc(f.id) + '">' +
          '<span class="chev">&#9656;</span>' +
          '<span class="badge ' + f.severity + '">' + f.severity + "</span>" +
          '<span class="finding-title"><strong>' + esc(f.title) + tags + "</strong>" +
            '<span class="checkid">' + esc(f.service) + " &middot; " + esc(f.checkId) + "</span></span>" +
          '<span class="rescount"><b>' + n + "</b> " + (n === 1 ? "resource" : "resources") + "</span>" +
        "</div>" +
        '<div class="finding-body">' + (open ? findingBody(f) : "") + "</div>" +
      "</div>";
    }).join("");
  }

  function render() {
    renderSeverityFilters();
    renderSidebar();
    renderFindings();
  }

  // ---- events ----------------------------------------------------------------------

  document.getElementById("sev-filters").addEventListener("click", function (e) {
    var pill = e.target.closest("[data-sev]");
    if (!pill) return;
    var sev = pill.getAttribute("data-sev");
    if (state.severities.has(sev)) state.severities.delete(sev); else state.severities.add(sev);
    render();
  });

  document.getElementById("sidebar").addEventListener("click", function (e) {
    var btn = e.target.closest("[data-service]");
    if (!btn) return;
    state.service = btn.getAttribute("data-service") || null;
    location.hash = state.service ? "service=" + state.service : "";
    render();
    document.querySelector(".main").scrollTop = 0;
  });

  document.getElementById("findings").addEventListener("click", function (e) {
    var showAll = e.target.closest("[data-showall]");
    if (showAll) {
      state.shownAll.add(showAll.getAttribute("data-showall"));
      renderFindings();
      return;
    }
    var head = e.target.closest("[data-toggle]");
    if (!head) return;
    var id = head.getAttribute("data-toggle");
    if (state.open.has(id)) state.open.delete(id); else state.open.add(id);
    renderFindings();
    // Keep the card you just opened in view; .main is the scroller, not the window.
    var el = document.getElementById("f-" + id);
    if (el && state.open.has(id)) {
      var main = document.querySelector(".main");
      var offset = el.getBoundingClientRect().top - main.getBoundingClientRect().top;
      if (offset < 0) main.scrollTop += offset - 10;
    }
  });

  // Per-finding resource filter, applied without re-rendering the whole page.
  document.getElementById("findings").addEventListener("input", function (e) {
    var input = e.target.closest("[data-resfilter]");
    if (!input) return;
    var q = input.value.toLowerCase();
    var table = document.querySelector('[data-restable="' + input.getAttribute("data-resfilter") + '"]');
    if (!table) return;
    Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
      row.style.display = row.textContent.toLowerCase().indexOf(q) !== -1 ? "" : "none";
    });
  });

  // Sort a resource table by clicking its header.
  document.getElementById("findings").addEventListener("click", function (e) {
    var th = e.target.closest("th");
    if (!th) return;
    var table = th.closest("table");
    if (!table) return;
    var idx = Array.prototype.indexOf.call(th.parentNode.cells, th);
    var dir = th.dataset.dir === "asc" ? -1 : 1;
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (c) { delete c.dataset.dir; });
    th.dataset.dir = dir === 1 ? "asc" : "desc";
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function (a, b) {
      var x = a.cells[idx].textContent.trim().toLowerCase();
      var y = b.cells[idx].textContent.trim().toLowerCase();
      return x < y ? -dir : x > y ? dir : 0;
    });
    rows.forEach(function (r) { body.appendChild(r); });
  });

  var searchTimer;
  document.getElementById("search").addEventListener("input", function (e) {
    clearTimeout(searchTimer);
    var value = e.target.value;
    searchTimer = setTimeout(function () { state.query = value; renderFindings(); }, 150);
  });

  document.getElementById("account-filter").addEventListener("change", function (e) {
    state.account = e.target.value; renderFindings();
  });
  document.getElementById("region-filter").addEventListener("change", function (e) {
    state.region = e.target.value; renderFindings();
  });

  document.getElementById("expand-all").addEventListener("click", function (e) {
    var list = filtered();
    if (state.open.size >= list.length && list.length) {
      state.open.clear();
      e.target.textContent = "Expand all";
    } else {
      list.forEach(function (f) { state.open.add(f.id); });
      e.target.textContent = "Collapse all";
    }
    renderFindings();
  });

  document.getElementById("theme-toggle").addEventListener("click", function (e) {
    var light = document.documentElement.getAttribute("data-theme") === "light";
    document.documentElement.setAttribute("data-theme", light ? "dark" : "light");
    e.target.textContent = light ? "Light" : "Dark";
  });

  // Deep links: #service=s3 opens that service on load.
  if (location.hash.indexOf("service=") === 1) {
    state.service = decodeURIComponent(location.hash.slice("#service=".length)) || null;
  }

  renderMeta();
  render();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
