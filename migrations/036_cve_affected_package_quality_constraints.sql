DELETE FROM cve_affected_packages
WHERE trim(cve_id) = ''
   OR trim(vulnerability_id) = ''
   OR trim(source) = ''
   OR trim(package_name) = ''
   OR trim(ecosystem) = ''
   OR trim(fixed_version) = ''
   OR upper(trim(vulnerability_id)) LIKE 'TEMP-%'
   OR upper(trim(cve_id)) LIKE 'TEMP-%'
   OR fixed_version ~* '^[0-9a-f]{40}$';

ALTER TABLE cve_affected_packages
DROP CONSTRAINT IF EXISTS cve_affected_packages_match_identity_check;

ALTER TABLE cve_affected_packages
ADD CONSTRAINT cve_affected_packages_match_identity_check
CHECK (
    trim(cve_id) <> ''
    AND trim(vulnerability_id) <> ''
    AND trim(source) <> ''
    AND trim(package_name) <> ''
    AND trim(ecosystem) <> ''
    AND trim(fixed_version) <> ''
);

ALTER TABLE cve_affected_packages
DROP CONSTRAINT IF EXISTS cve_affected_packages_no_temp_identifier_check;

ALTER TABLE cve_affected_packages
ADD CONSTRAINT cve_affected_packages_no_temp_identifier_check
CHECK (upper(trim(vulnerability_id)) NOT LIKE 'TEMP-%' AND upper(trim(cve_id)) NOT LIKE 'TEMP-%');

ALTER TABLE cve_affected_packages
DROP CONSTRAINT IF EXISTS cve_affected_packages_fixed_version_not_hash_check;

ALTER TABLE cve_affected_packages
ADD CONSTRAINT cve_affected_packages_fixed_version_not_hash_check
CHECK (fixed_version !~* '^[0-9a-f]{40}$');
