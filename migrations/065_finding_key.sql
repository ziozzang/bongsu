-- Phase C: stable finding identity.
--
-- A finding's identity was tied to the per-scan, ephemeral (package_id, scan_id,
-- vulnerability_id) triplet, so the same logical finding (a CVE affecting a
-- package on a host) got a brand-new row and id every scan. finding_key is a
-- stable SHA-256 fingerprint of the scan-independent identity, letting triage and
-- external references bind to a finding that survives re-scans and version bumps.
--
-- The recipe below MUST stay byte-identical to db.ComputeFindingKey (finding_key.go):
--   sha256( lower(trim(host_id)) ⋮ lower(trim(pkg_name)) ⋮ norm(pkg_path) ⋮ trim(vulnerability_id) )
-- with ⋮ = E'\x1f' and norm(pkg_path) mapping '' -> '__HOST__'. (Verified equal
-- against PostgreSQL pgcrypto digest() in the integration tests.)

ALTER TABLE vulnerabilities
  ADD COLUMN IF NOT EXISTS finding_key TEXT,
  ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS last_seen  TIMESTAMPTZ NOT NULL DEFAULT now();

-- Backfill existing rows. pgcrypto is enabled by migration 001.
UPDATE vulnerabilities SET finding_key = encode(digest(
    lower(trim(host_id)) || E'\x1f' ||
    lower(trim(pkg_name)) || E'\x1f' ||
    CASE WHEN trim(coalesce(pkg_path, '')) = '' THEN '__HOST__' ELSE trim(pkg_path) END || E'\x1f' ||
    trim(vulnerability_id)
  , 'sha256'), 'hex')
WHERE finding_key IS NULL;

ALTER TABLE vulnerabilities ALTER COLUMN finding_key SET NOT NULL;

-- finding_key is NOT unique on its own: the per-scan snapshot model keeps one row
-- per (package_id, scan_id, vulnerability_id), so a finding observed across N
-- scans has N rows sharing a finding_key. The index supports triage/外부 lookups
-- and the host-scoped "history of this finding" query.
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_finding_key ON vulnerabilities(finding_key);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_finding_key ON vulnerabilities(host_id, finding_key);
