DELETE FROM cve_reference_keys
WHERE trim(cve_id) = ''
   OR trim(reference_key) = ''
   OR upper(trim(cve_id)) LIKE 'TEMP-%'
   OR upper(trim(reference_key)) LIKE '%TEMP-%'
   OR (
       reference_key LIKE 'repo:github.com/%'
       AND substring(reference_key from length('repo:github.com/') + 1) !~ '^[a-z0-9_.-]+/[a-z0-9_.-]+$'
   );

ALTER TABLE cve_reference_keys
DROP CONSTRAINT IF EXISTS cve_reference_keys_identity_nonempty_check;

ALTER TABLE cve_reference_keys
ADD CONSTRAINT cve_reference_keys_identity_nonempty_check
CHECK (trim(cve_id) <> '' AND trim(reference_key) <> '') NOT VALID;

ALTER TABLE cve_reference_keys
DROP CONSTRAINT IF EXISTS cve_reference_keys_no_temp_identifier_check;

ALTER TABLE cve_reference_keys
ADD CONSTRAINT cve_reference_keys_no_temp_identifier_check
CHECK (upper(trim(cve_id)) NOT LIKE 'TEMP-%' AND upper(trim(reference_key)) NOT LIKE '%TEMP-%') NOT VALID;

ALTER TABLE cve_reference_keys
DROP CONSTRAINT IF EXISTS cve_reference_keys_format_check;

ALTER TABLE cve_reference_keys
ADD CONSTRAINT cve_reference_keys_format_check
CHECK (reference_key ~* '^(cve:CVE-[0-9]{4}-[0-9]{4,}|ghsa:GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|rustsec:RUSTSEC-[0-9]{4}-[0-9]{4,}|pysec:PYSEC-[0-9]{4}-[0-9]+|go:GO-[0-9]{4}-[0-9]{4,}|debian:D(SA|LA)-[0-9]{1,6}(-[0-9]+)?|mal:MAL-[0-9]{4}-[0-9]+|alma:AL(BA|EA|SA)-[0-9]{4}:[0-9]+|suse:(openSUSE|SUSE)-[A-Z]{2}-[0-9]{4}:[0-9]+-[0-9]+|drupal:DRUPAL-[A-Z]+-[0-9]{4}-[0-9]{3,}|dtsa:DTSA-[0-9]+-[0-9]+|osv:OSV-[0-9]{4}-[0-9]+|gsd:GSD-[0-9]{4}-[0-9]+|repo:github\.com/[a-z0-9_.-]+/[a-z0-9_.-]+|vendor:(debian|ubuntu|redhat))$') NOT VALID;
