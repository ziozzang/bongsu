#!/bin/bash
# Download FIRST EPSS daily scores and convert to Bongsu JSONL.
# Usage: ./download-epss.sh [output_file] [date]
# Date defaults to today with a seven-day fallback for publication lag.

set -euo pipefail

OUTPUT="${1:-epss.jsonl}"
REQUESTED_DATE="${2:-}"
BASE_URL="${EPSS_CSV_BASE_URL:-https://epss.empiricalsecurity.com}"
OUTPUT_TMP="${OUTPUT}.tmp.$$"
trap 'rm -f "${OUTPUT_TMP}"' EXIT

echo "Downloading FIRST EPSS data..."

python3 << PYEOF
import csv
import datetime as dt
import gzip
import io
import json
import sys
import urllib.request

output = "${OUTPUT_TMP}"
requested_date = "${REQUESTED_DATE}".strip()
base_url = "${BASE_URL}".rstrip("/")

def candidate_dates():
    if requested_date:
        yield requested_date
        return
    today = dt.date.today()
    for days_back in range(0, 7):
        yield (today - dt.timedelta(days=days_back)).isoformat()

def fetch(date):
    url = f"{base_url}/epss_scores-{date}.csv.gz"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Bongsu/0.1 EPSS Downloader")
    with urllib.request.urlopen(req, timeout=240) as resp:
        return gzip.decompress(resp.read()).decode("utf-8", errors="replace"), url

last_error = None
content = ""
selected_date = ""
selected_url = ""
for date in candidate_dates():
    try:
        content, selected_url = fetch(date)
        selected_date = date
        break
    except Exception as exc:
        last_error = exc
        print(f"  EPSS {date} unavailable: {exc}", file=sys.stderr)

if not content:
    print(f"ERROR: failed to download EPSS CSV: {last_error}", file=sys.stderr)
    sys.exit(1)

lines = [line for line in content.splitlines() if line and not line.startswith("#")]
reader = csv.DictReader(io.StringIO("\n".join(lines)))
required = {"cve", "epss", "percentile"}
if not required.issubset(set(reader.fieldnames or [])):
    print(f"ERROR: EPSS CSV missing required columns: {reader.fieldnames}", file=sys.stderr)
    sys.exit(1)

written = 0
with open(output, "w", encoding="utf-8") as out:
    for row in reader:
        cve = (row.get("cve") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        try:
            epss_score = float(row.get("epss") or "0")
            percentile = float(row.get("percentile") or "0")
        except ValueError:
            continue
        entry = {
            "vulnerability_id": cve,
            "source": "epss",
            "category": "general-cve",
            "severity": "",
            "cvss_score": 0,
            "cvss_vector": "",
            "epss_score": epss_score,
            "epss_percentile": percentile,
            "title": "",
            "description": f"FIRST EPSS score {epss_score:.5f}, percentile {percentile:.5f} for {selected_date}",
            "published_date": selected_date + "T00:00:00Z",
            "modified_date": selected_date + "T00:00:00Z",
            "affected_products": "[]",
            "references": json.dumps([{"url": "https://www.first.org/epss/", "source": "FIRST EPSS"}]),
            "raw_data": json.dumps({
                "id": cve,
                "source": "epss",
                "epss": epss_score,
                "percentile": percentile,
                "date": selected_date,
                "url": selected_url,
            }),
        }
        out.write(json.dumps(entry) + "\n")
        written += 1

if written == 0:
    print("ERROR: EPSS conversion produced no CVE entries", file=sys.stderr)
    sys.exit(1)
print(f"Total: {written} EPSS entries for {selected_date} written to {output}", file=sys.stderr)
PYEOF

mv "${OUTPUT_TMP}" "${OUTPUT}"
trap - EXIT
TOTAL=$(wc -l < "${OUTPUT}")
echo "Output: ${OUTPUT} (${TOTAL} entries)"
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=epss' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:5677/api/admin/cve-db/import"
