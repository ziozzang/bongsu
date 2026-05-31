#!/bin/bash
# Download NVD CVE data via API 2.0 and convert to Bongsu import format (JSONL)
# Usage: ./download-nvd.sh [output_file] [year_or_range]
# Examples:
#   ./download-nvd.sh nvd-2026.jsonl 2026
#   ./download-nvd.sh nvd-recent.jsonl 2024,2025,2026
# API docs: https://nvd.nist.gov/developers/vulnerabilities

set -euo pipefail

OUTPUT="${1:-nvd-cve.jsonl}"
YEARS="${2:-$(date +%Y)}"
API_KEY="${NVD_API_KEY:-}"
OUTPUT_TMP="${OUTPUT}.tmp.$$"
trap 'rm -f "${OUTPUT_TMP}"' EXIT

echo "Downloading NVD CVE data for: ${YEARS}"
> "${OUTPUT_TMP}"

python3 << PYEOF
import json, urllib.request, time, sys

output = "${OUTPUT_TMP}"
api_key = "${API_KEY}" or None
years = [y.strip() for y in "${YEARS}".split(",")]

total_written = 0

for year in years:
    quarters = [
        (f"{year}-01-01", f"{year}-03-31"),
        (f"{year}-04-01", f"{year}-06-30"),
        (f"{year}-07-01", f"{year}-09-30"),
        (f"{year}-10-01", f"{year}-12-31"),
    ]
    for q_start, q_end in quarters:
        print(f"  {year} {q_start[:10]} to {q_end[:10]}...", file=sys.stderr)
        start_index = 0
        page = 0

        while True:
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?pubStartDate={q_start}T00:00:00.000"
                f"&pubEndDate={q_end}T23:59:59.999"
                f"&resultsPerPage=2000&startIndex={start_index}"
            )

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Bongsu/0.1 CVE Downloader")
            if api_key:
                req.add_header("apiKey", api_key)

            data = {}
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=180) as resp:
                        data = json.loads(resp.read())
                    break
                except Exception as e:
                    if attempt < 2:
                        wait = 30 * (attempt + 1)
                        print(f"    Retry {attempt+1}/3 after {wait}s: {e}", file=sys.stderr)
                        time.sleep(wait)
                    else:
                        print(f"    FAILED after 3 attempts: {e}", file=sys.stderr)
                        sys.exit(1)

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            count = 0
            with open(output, "a") as out:
                for item in vulns:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    severity = ""
                    cvss_score = 0.0
                    cvss_vector = ""
                    for m in cve.get("metrics", {}).get("cvssMetricV31", []):
                        v3 = m.get("cvssData", {})
                        severity = v3.get("baseSeverity", "")
                        cvss_score = v3.get("baseScore", 0.0)
                        cvss_vector = v3.get("vectorString", "")
                        break
                    if not cvss_score:
                        for m in cve.get("metrics", {}).get("cvssMetricV30", []):
                            v3 = m.get("cvssData", {})
                            severity = v3.get("baseSeverity", "")
                            cvss_score = v3.get("baseScore", 0.0)
                            cvss_vector = v3.get("vectorString", "")
                            break

                    published = cve.get("published", "")
                    modified = cve.get("lastModified", "")

                    refs = [{"url": r.get("url", ""), "source": r.get("source", "")} for r in cve.get("references", [])[:20]]

                    products = []
                    seen_p = set()
                    for c in cve.get("configurations", []):
                        for node in c.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                criteria = match.get("criteria", "")
                                if criteria:
                                    parts = criteria.split(":")
                                    if len(parts) >= 5:
                                        key = f"{parts[3]}:{parts[4]}"
                                        if key not in seen_p:
                                            seen_p.add(key)
                                            products.append({"vendor": parts[3], "product": parts[4]})

                    entry = {
                        "vulnerability_id": cve_id,
                        "source": "nvd",
                        "category": "general-cve",
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "title": "",
                        "description": desc[:4000] if desc else "",
                        "published_date": published,
                        "modified_date": modified,
                        "affected_products": json.dumps(products[:50]),
                        "references": json.dumps(refs),
                        "raw_data": json.dumps({"id": cve_id, "severity": severity, "cvss": cvss_score})
                    }
                    out.write(json.dumps(entry) + "\n")
                    count += 1

            total_written += count
            total_results = data.get("totalResults", 0)
            print(f"      Page {page}: {count} entries ({total_written}/{total_results})", file=sys.stderr)

            if len(vulns) < 2000:
                break

            start_index += 2000
            page += 1
            time.sleep(6 if not api_key else 1)

print(f"Total: {total_written} CVE entries written to {output}", file=sys.stderr)
if total_written == 0:
    print("ERROR: NVD download produced no CVE entries", file=sys.stderr)
    sys.exit(1)
PYEOF

mv "${OUTPUT_TMP}" "${OUTPUT}"
trap - EXIT
TOTAL=$(wc -l < "${OUTPUT}")
echo "Output: ${OUTPUT} (${TOTAL} entries)"
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=nvd' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:8080/api/admin/cve-db/import"
