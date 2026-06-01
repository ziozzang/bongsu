#!/bin/bash
# Download CISA Known Exploited Vulnerabilities and convert to Bongsu JSONL.
# Usage: ./download-cisa-kev.sh [output_file]

set -euo pipefail

OUTPUT="${1:-cisa-kev.jsonl}"
FEED_URL="${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
OUTPUT_TMP="${OUTPUT}.tmp.$$"
trap 'rm -f "${OUTPUT_TMP}"' EXIT

echo "Downloading CISA KEV data..."

python3 << PYEOF
import json
import sys
import urllib.request

feed_url = "${FEED_URL}"
output = "${OUTPUT_TMP}"

def rfc3339_date(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if "T" in value:
        return value
    return value + "T00:00:00Z"

req = urllib.request.Request(feed_url)
req.add_header("User-Agent", "Bongsu/0.1 CISA KEV Downloader")

try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read())
except Exception as exc:
    print(f"ERROR: failed to download CISA KEV feed: {exc}", file=sys.stderr)
    sys.exit(1)

items = data.get("vulnerabilities")
if not isinstance(items, list) or not items:
    print("ERROR: CISA KEV feed produced no vulnerabilities", file=sys.stderr)
    sys.exit(1)

written = 0
with open(output, "w", encoding="utf-8") as out:
    for item in items:
        cve_id = str(item.get("cveID", "")).strip()
        if not cve_id.startswith("CVE-"):
            continue
        vendor = str(item.get("vendorProject", "")).strip()
        product = str(item.get("product", "")).strip()
        name = str(item.get("vulnerabilityName", "")).strip()
        short_desc = str(item.get("shortDescription", "")).strip()
        required_action = str(item.get("requiredAction", "")).strip()
        notes = str(item.get("notes", "")).strip()
        date_added = str(item.get("dateAdded", "")).strip()
        due_date = str(item.get("dueDate", "")).strip()
        known_ransomware = str(item.get("knownRansomwareCampaignUse", "")).strip()

        title = name or f"{vendor} {product} known exploited vulnerability".strip()
        description_parts = [p for p in [
            short_desc,
            f"Required action: {required_action}" if required_action else "",
            f"CISA KEV date added: {date_added}" if date_added else "",
            f"CISA KEV due date: {due_date}" if due_date else "",
            f"Known ransomware campaign use: {known_ransomware}" if known_ransomware else "",
            notes,
        ] if p]

        refs = [{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "source": "CISA KEV"}]
        entry = {
            "vulnerability_id": cve_id,
            "source": "cisa-kev",
            "category": "general-cve",
            "severity": "",
            "cvss_score": 0,
            "cvss_vector": "",
            "title": title[:512],
            "description": "\n".join(description_parts)[:4000],
            "published_date": rfc3339_date(date_added),
            "modified_date": rfc3339_date(due_date or date_added),
            "affected_products": json.dumps([{
                "vendor": vendor,
                "product": product,
                "known_exploited": True,
                "date_added": date_added,
                "due_date": due_date,
                "known_ransomware_campaign_use": known_ransomware,
            }]),
            "references": json.dumps(refs),
            "raw_data": json.dumps({
                "id": cve_id,
                "source": "cisa-kev",
                "dateAdded": date_added,
                "dueDate": due_date,
                "knownRansomwareCampaignUse": known_ransomware,
            }),
        }
        out.write(json.dumps(entry) + "\n")
        written += 1

if written == 0:
    print("ERROR: CISA KEV conversion produced no CVE entries", file=sys.stderr)
    sys.exit(1)
print(f"Total: {written} CISA KEV entries written to {output}", file=sys.stderr)
PYEOF

mv "${OUTPUT_TMP}" "${OUTPUT}"
trap - EXIT
TOTAL=$(wc -l < "${OUTPUT}")
echo "Output: ${OUTPUT} (${TOTAL} entries)"
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=cisa-kev' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:5677/api/admin/cve-db/import"
