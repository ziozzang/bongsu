#!/bin/bash
# Download OSV.dev vulnerability data and convert to Bongsu import format (JSONL)
# Usage: ./download-osv.sh [output_file] [ecosystems]
# Example: ./download-osv.sh osv-all.jsonl
# Ecosystems with spaces: "Red Hat", "Rocky Linux", "Oracle Linux"

set -euo pipefail

OUTPUT="${1:-osv-cve.jsonl}"
ECOSYSTEMS="${2:-PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,Alpine,Debian,SUSE,AlmaLinux,Chainguard}"
OUTPUT_TMP="${OUTPUT}.tmp.$$"

TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
WORKDIR=$(mktemp -d "${TMP_PARENT%/}/bongsu-osv.XXXXXX")
trap 'rm -rf "${WORKDIR}"; rm -f "${OUTPUT_TMP}"' EXIT

echo "Downloading OSV.dev data for: ${ECOSYSTEMS}"

TOTAL=0
FAILED_ECOSYSTEMS=()
> "${OUTPUT_TMP}"

IFS=',' read -ra ECO_ARRAY <<< "${ECOSYSTEMS}"
for eco in "${ECO_ARRAY[@]}"; do
    eco=$(echo "$eco" | xargs)  # trim whitespace
    echo "  Downloading ${eco}..."
    # URL-encode spaces for curl
    encoded_eco=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${eco}'))")
    if ! curl -fsSL "https://osv-vulnerabilities.storage.googleapis.com/${encoded_eco}/all.zip" -o "${WORKDIR}/${eco}.zip"; then
        echo "  ERROR: ${eco} download failed"
        FAILED_ECOSYSTEMS+=("${eco}:download")
        continue
    fi
    if [ ! -s "${WORKDIR}/${eco}.zip" ]; then
        echo "  ERROR: ${eco} download was empty"
        FAILED_ECOSYSTEMS+=("${eco}:empty-zip")
        continue
    fi

    mkdir -p "${WORKDIR}/${eco}"
    if ! unzip -q -o "${WORKDIR}/${eco}.zip" -d "${WORKDIR}/${eco}"; then
        echo "  ERROR: ${eco} zip extraction failed"
        FAILED_ECOSYSTEMS+=("${eco}:unzip")
        continue
    fi

    COUNT=$(python3 << PYEOF
import json, os, glob, re

eco_dir = "${WORKDIR}/${eco}"
count = 0
with open("${OUTPUT_TMP}", "a") as out:
    for f in sorted(glob.glob(os.path.join(eco_dir, "*.json"))):
        try:
            data = json.load(open(f))
        except:
            continue

        vuln_id = data.get("id", "")
        if not vuln_id:
            continue

        aliases = data.get("aliases", [])
        cve_id = ""
        for a in aliases:
            if a.startswith("CVE-"):
                cve_id = a
                break
        if not cve_id:
            cve_id = vuln_id

        severity = ""
        cvss_score = 0.0
        cvss_vector = ""

        # Try severity array first (most reliable for OSV)
        for s in data.get("severity", []):
            if "CVSS" in s.get("type", ""):
                cvss_vector = s.get("score", "")
                # Extract score from CVSS vector string
                if cvss_vector:
                    # Use database_specific or ecosystem_specific for numeric score
                    break

        # Try database_specific for numeric score
        ds = data.get("database_specific", {})
        if ds.get("severity"):
            severity = ds["severity"].upper()
        raw_score = ds.get("cvss", {})
        if isinstance(raw_score, dict):
            raw_score = raw_score.get("v3", 0.0) or raw_score.get("v2", 0.0)
        if raw_score:
            try:
                cvss_score = float(raw_score)
            except (ValueError, TypeError):
                cvss_score = 0.0

        # Try ecosystem_specific as fallback
        if not severity:
            es = data.get("ecosystem_specific", {})
            if es.get("severity"):
                severity = es["severity"].upper()

        # Normalize severity from score if missing
        if not severity and cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        summary = data.get("summary", "")
        details = data.get("details", "")

        published = data.get("published", "")
        modified = data.get("modified", "")

        refs = []
        for r in data.get("references", []):
            refs.append({"url": r.get("url", ""), "type": r.get("type", "")})

        affected = []
        for a in data.get("affected", []):
            pkg = a.get("package", {})
            entry = {"name": pkg.get("name", ""), "ecosystem": pkg.get("ecosystem", "")}
            ranges = a.get("ranges", [])
            if ranges:
                entry["ranges"] = ranges
            else:
                entry["versions"] = a.get("versions", [])
            # Extract fixed version for quick reference
            fixed_versions = []
            for r in ranges:
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])
            if fixed_versions:
                entry["fixed"] = fixed_versions
            affected.append(entry)

        entry = {
            "vulnerability_id": cve_id,
            "source": "osv",
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score else 0.0,
            "cvss_vector": cvss_vector,
            "title": summary,
            "description": details[:4000] if details else "",
            "published_date": published,
            "modified_date": modified,
            "affected_products": json.dumps(affected[:20]),
            "references": json.dumps(refs[:20]),
            "raw_data": json.dumps({"id": vuln_id, "aliases": aliases[:5]})
        }
        out.write(json.dumps(entry) + "\n")
        count += 1

print(count)
PYEOF
)
    echo "  ${eco}: ${COUNT} entries"
    TOTAL=$((TOTAL + COUNT))
    if [ "${COUNT}" -eq 0 ]; then
        FAILED_ECOSYSTEMS+=("${eco}:no-entries")
    fi
done

if [ "${#FAILED_ECOSYSTEMS[@]}" -gt 0 ]; then
    echo "ERROR: incomplete OSV download: ${FAILED_ECOSYSTEMS[*]}" >&2
    exit 1
fi
if [ "${TOTAL}" -eq 0 ]; then
    echo "ERROR: OSV download produced no CVE entries" >&2
    exit 1
fi

mv "${OUTPUT_TMP}" "${OUTPUT}"
trap - EXIT
rm -rf "${WORKDIR}"
echo "Total: ${TOTAL} CVE entries written to ${OUTPUT}"
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=osv' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:8080/api/admin/cve-db/import"
