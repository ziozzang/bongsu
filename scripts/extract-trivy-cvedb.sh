#!/bin/bash
# Extract CVE data from Trivy's vulnerability database and convert to Bongsu JSONL format
# Requires: trivy binary
# Usage: ./extract-trivy-cvedb.sh [output_file]
# Example: ./extract-trivy-cvedb.sh trivy-cve.jsonl

set -euo pipefail

OUTPUT="${1:-trivy-cve.jsonl}"
TRIVY_BIN="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${BONGSU_TRIVY_CACHE_DIR:-}}"

# Find trivy binary
if [ -z "${TRIVY_BIN}" ]; then
    if command -v trivy &>/dev/null; then
        TRIVY_BIN="trivy"
    elif [ -x /opt/bongsu/bin/trivy ]; then
        TRIVY_BIN="/opt/bongsu/bin/trivy"
    elif [ -x "${PWD}/trivy" ]; then
        TRIVY_BIN="${PWD}/trivy"
    elif [ -x "${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}/../bin/trivy" ]; then
        TRIVY_BIN="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}/../bin/trivy"
    elif [ -x "${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}/trivy" ]; then
        TRIVY_BIN="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}/trivy"
    elif [ -x ./trivy ]; then
        TRIVY_BIN="./trivy"
    else
        echo "ERROR: trivy binary not found. Install trivy or set TRIVY_BIN/BONGSU_TRIVY_PATH."
        exit 1
    fi
fi

echo "Using trivy: ${TRIVY_BIN}"
$TRIVY_BIN --version 2>/dev/null | head -1

# Use trivy's JSON output to list all known vulnerabilities
# We scan a minimal image and extract the CVE metadata
# Alternative: use trivy db commands if available

TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
WORKDIR=$(mktemp -d "${TMP_PARENT%/}/bongsu-trivy-cve.XXXXXX")
trap 'rm -rf "${WORKDIR}"' EXIT

echo "Extracting CVE data from Trivy database..."

if [ -z "${TRIVY_CACHE_DIR}" ]; then
    if [ -n "${XDG_CACHE_HOME:-}" ]; then
        TRIVY_CACHE_DIR="${XDG_CACHE_HOME}/trivy"
    else
        TRIVY_CACHE_DIR="${HOME}/.cache/trivy"
    fi
fi

DB_PATH="${TRIVY_CACHE_DIR}/db/trivy.db"
if [ ! -f "${DB_PATH}" ]; then
    echo "Downloading trivy DB first..."
    ${TRIVY_BIN} image --download-db-only --cache-dir "${TRIVY_CACHE_DIR}" 2>&1 || true
fi

if [ ! -f "${DB_PATH}" ]; then
    echo "ERROR: trivy.db not found at ${DB_PATH}"
    echo "Run: trivy image --download-db-only --cache-dir ${TRIVY_CACHE_DIR}"
    exit 1
fi

echo "Cache: ${TRIVY_CACHE_DIR}"
echo "DB: ${DB_PATH} ($(du -h "${DB_PATH}" | cut -f1))"

python3 << PYEOF
import json, struct, sys

try:
    import boltlib
except ImportError:
    pass

# Parse BoltDB directly using bolt structure
# BoltDB format: page-based, we need to read the bucket structure
# This is complex, so we use a simpler approach: scan known images and collect CVEs

import sqlite3
import os

db_path = "${DB_PATH}"

# Check if it's actually a BoltDB file
with open(db_path, 'rb') as f:
    magic = f.read(8)
    if magic[:4] != b'\\x00\\x00\\x00\\x00':
        # Not standard bolt, try reading anyway
        pass

# Alternative: use trivy's own output
# We'll create a dummy SBOM and scan it to extract all CVEs
print("Using trivy JSON output to extract CVE metadata...", file=sys.stderr)

import subprocess
result = subprocess.run(
    ["${TRIVY_BIN}", "image", "--cache-dir", "${TRIVY_CACHE_DIR}", "--format", "json",
     "--list-all-pkgs", "--scanners", "vuln", "--skip-db-update", "alpine:latest"],
    capture_output=True, text=True, timeout=300
)

if result.returncode != 0:
    print(f"Trivy scan error: {result.stderr[:200]}", file=sys.stderr)
    sys.exit(1)

data = json.loads(result.stdout)

count = 0
seen_cves = set()
with open("${OUTPUT}", "w") as out:
    for result_item in data.get("Results", []):
        target = result_item.get("target", "")
        pkg_type = result_item.get("Type", "")
        for vuln in result_item.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            severity = vuln.get("Severity", "")
            title = vuln.get("Title", "")
            desc = vuln.get("Description", "")
            cvss_score = 0.0
            cvss_vector = ""

            # Extract CVSS from multiple sources
            for source, cvss_data in vuln.get("CVSS", {}).items():
                if cvss_data.get("V3Score"):
                    cvss_score = cvss_data["V3Score"]
                    cvss_vector = cvss_data.get("V3Vector", "")
                elif cvss_data.get("V2Score"):
                    cvss_score = cvss_data["V2Score"]
                    cvss_vector = cvss_data.get("V2Vector", "")

            # Try PrimaryURL for reference
            primary_url = vuln.get("PrimaryURL", "")
            refs = []
            if primary_url:
                refs.append({"url": primary_url, "type": "primary"})
            for r in vuln.get("References", [])[:10]:
                refs.append({"url": r, "type": "web"})

            published = vuln.get("PublishedDate", "")
            modified = vuln.get("LastModifiedDate", "")

            affected = []
            pkg_name = vuln.get("PkgName", "")
            if pkg_name:
                affected.append({"name": pkg_name, "ecosystem": pkg_type})

            entry = {
                "vulnerability_id": cve_id,
                "source": "trivy",
                "severity": severity,
                "cvss_score": float(cvss_score) if cvss_score else 0.0,
                "cvss_vector": cvss_vector,
                "title": title,
                "description": desc[:4000] if desc else "",
                "published_date": published or "",
                "modified_date": modified or "",
                "affected_products": json.dumps(affected),
                "references": json.dumps(refs),
                "raw_data": json.dumps({
                    "id": cve_id,
                    "severity": severity,
                    "title": title,
                    "cvss": vuln.get("CVSS", {}),
                    "references": vuln.get("References", [])[:5]
                })
            }
            out.write(json.dumps(entry) + "\n")
            count += 1

print(f"Extracted {count} unique CVEs from trivy scan", file=sys.stderr)
PYEOF

# The above approach only gets CVEs from one image. For comprehensive extraction,
# we need to scan multiple representative images or use the Go bolt parser.
# Let's scan several common images to maximize coverage.

echo "Scanning additional images for broader CVE coverage..."
IMAGES=(
    "debian:bookworm"
    "ubuntu:22.04"
    "alpine:3.19"
    "node:20-slim"
    "python:3.12-slim"
    "golang:1.22"
    "nginx:latest"
    "redis:7"
    "postgres:16"
)

for img in "${IMAGES[@]}"; do
    echo "  Scanning ${img}..."
    ${TRIVY_BIN} image --cache-dir "${TRIVY_CACHE_DIR}" --format json --scanners vuln --skip-db-update "${img}" > "${WORKDIR}/scan-$(echo ${img} | tr '/:' '-').json" 2>/dev/null || echo "  SKIP: ${img}"
done

# Merge all scan results, deduplicating by CVE ID
echo "Merging scan results..."
python3 << PYEOF
import json, os, glob

seen = set()
# Load existing entries
with open("${OUTPUT}", "r") as f:
    for line in f:
        try:
            e = json.loads(line)
            seen.add(e.get("vulnerability_id", ""))
        except:
            pass

added = 0
with open("${OUTPUT}", "a") as out:
    for scan_file in glob.glob("${WORKDIR}/scan-*.json"):
        try:
            data = json.load(open(scan_file))
        except:
            continue
        for result_item in data.get("Results", []):
            pkg_type = result_item.get("Type", "")
            for vuln in result_item.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID", "")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)

                severity = vuln.get("Severity", "")
                title = vuln.get("Title", "")
                desc = vuln.get("Description", "")
                cvss_score = 0.0
                cvss_vector = ""

                for source, cvss_data in vuln.get("CVSS", {}).items():
                    if cvss_data.get("V3Score"):
                        cvss_score = cvss_data["V3Score"]
                        cvss_vector = cvss_data.get("V3Vector", "")
                    elif cvss_data.get("V2Score"):
                        cvss_score = cvss_data["V2Score"]
                        cvss_vector = cvss_data.get("V2Vector", "")

                refs = []
                if vuln.get("PrimaryURL"):
                    refs.append({"url": vuln["PrimaryURL"], "type": "primary"})
                for r in vuln.get("References", [])[:10]:
                    refs.append({"url": r, "type": "web"})

                affected = []
                pkg_name = vuln.get("PkgName", "")
                if pkg_name:
                    affected.append({"name": pkg_name, "ecosystem": pkg_type})

                entry = {
                    "vulnerability_id": cve_id,
                    "source": "trivy",
                    "severity": severity,
                    "cvss_score": float(cvss_score) if cvss_score else 0.0,
                    "cvss_vector": cvss_vector,
                    "title": title,
                    "description": desc[:4000] if desc else "",
                    "published_date": vuln.get("PublishedDate", "") or "",
                    "modified_date": vuln.get("LastModifiedDate", "") or "",
                    "affected_products": json.dumps(affected),
                    "references": json.dumps(refs),
                    "raw_data": json.dumps({"id": cve_id, "severity": severity, "title": title, "cvss": vuln.get("CVSS", {})})
                }
                out.write(json.dumps(entry) + "\n")
                added += 1

existing = len(seen) - added
print(f"Added {added} new CVEs ({existing} already existed)")
print(f"Total unique CVEs: {len(seen)}")
PYEOF

TOTAL=$(wc -l < "${OUTPUT}")
echo "Total: ${TOTAL} CVE entries written to ${OUTPUT}"
echo "Import: curl -F 'file=@${OUTPUT}' -F 'source=trivy' -H 'X-API-Key: YOUR_KEY' http://YOUR_SERVER:8080/api/admin/cve-db/import"
