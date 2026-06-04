#!/bin/bash
# Download OSV.dev vulnerability data and convert to Bongsu import format (JSONL)
# Usage: ./download-osv.sh [output_file] [ecosystems]
# Example: ./download-osv.sh osv-all.jsonl
# Ecosystems with spaces: "Red Hat", "Rocky Linux", "Oracle Linux"

set -euo pipefail

OUTPUT="${1:-osv-cve.jsonl}"
ECOSYSTEMS="${2:-${BONGSU_OSV_ECOSYSTEMS:-PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android}}"
OUTPUT_TMP="${OUTPUT}.tmp.$$"

TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
WORKDIR=$(mktemp -d "${TMP_PARENT%/}/bongsu-osv.XXXXXX")
trap 'rm -rf "${WORKDIR}"; rm -f "${OUTPUT_TMP}"' EXIT
OSV_CURL_CONNECT_TIMEOUT="${BONGSU_OSV_CURL_CONNECT_TIMEOUT_SECONDS:-20}"
OSV_CURL_MAX_TIME="${BONGSU_OSV_CURL_MAX_TIME_SECONDS:-1800}"
OSV_CURL_RETRIES="${BONGSU_OSV_CURL_RETRIES:-3}"
OSV_CURL_RETRY_DELAY="${BONGSU_OSV_CURL_RETRY_DELAY_SECONDS:-3}"

echo "Downloading OSV.dev data for: ${ECOSYSTEMS}"

TOTAL=0
SKIPPED_CGA_TOTAL=0
FAILED_ECOSYSTEMS=()
> "${OUTPUT_TMP}"

IFS=',' read -ra ECO_ARRAY <<< "${ECOSYSTEMS}"
for eco in "${ECO_ARRAY[@]}"; do
    eco=$(echo "$eco" | xargs)  # trim whitespace
    echo "  Downloading ${eco}..."
    # URL-encode spaces for curl
    encoded_eco=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${eco}")
    if ! curl -fsSL \
        --connect-timeout "${OSV_CURL_CONNECT_TIMEOUT}" \
        --max-time "${OSV_CURL_MAX_TIME}" \
        --retry "${OSV_CURL_RETRIES}" \
        --retry-delay "${OSV_CURL_RETRY_DELAY}" \
        --retry-connrefused \
        "https://osv-vulnerabilities.storage.googleapis.com/${encoded_eco}/all.zip" \
        -o "${WORKDIR}/${eco}.zip"; then
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

    RESULT=$(python3 << PYEOF
import json, os, glob, re

eco_dir = "${WORKDIR}/${eco}"
count = 0
skipped_cga = 0
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
        if cve_id.startswith("CGA-"):
            skipped_cga += 1
            continue

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
            "affected_products": json.dumps(affected),
            "references": json.dumps(refs),
            "raw_data": json.dumps({"id": vuln_id, "aliases": aliases})
        }
        out.write(json.dumps(entry) + "\n")
        count += 1

print(f"{count}|{skipped_cga}")
PYEOF
)
    COUNT="${RESULT%%|*}"
    SKIPPED_CGA="${RESULT#*|}"
    echo "  ${eco}: ${COUNT} importable entries"
    if [ "${SKIPPED_CGA}" -gt 0 ]; then
        echo "  ${eco}: skipped ${SKIPPED_CGA} CGA-only advisories"
    fi
    TOTAL=$((TOTAL + COUNT))
    SKIPPED_CGA_TOTAL=$((SKIPPED_CGA_TOTAL + SKIPPED_CGA))
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
if [ "${SKIPPED_CGA_TOTAL}" -gt 0 ]; then
    echo "Skipped: ${SKIPPED_CGA_TOTAL} CGA-only advisories without CVE aliases"
fi
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=osv' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:5677/api/admin/cve-db/import"
