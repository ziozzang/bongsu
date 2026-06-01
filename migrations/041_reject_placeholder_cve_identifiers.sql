DELETE FROM cve_affected_packages
WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
   OR upper(trim(cve_id)) LIKE 'TEMP-%'
   OR upper(trim(vulnerability_id)) LIKE 'CVD-%'
   OR upper(trim(cve_id)) LIKE 'CVD-%';

DELETE FROM cve_reference_keys
WHERE upper(trim(cve_id)) LIKE 'TEMP-%'
   OR upper(trim(reference_key)) LIKE '%TEMP-%'
   OR upper(trim(cve_id)) LIKE 'CVD-%'
   OR upper(trim(reference_key)) LIKE '%CVD-%';

DELETE FROM cve_database
WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
   OR upper(trim(id)) LIKE 'TEMP-%'
   OR upper(trim(vulnerability_id)) LIKE 'CVD-%'
   OR upper(trim(id)) LIKE 'CVD-%';

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_no_temp_identifier_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_no_temp_identifier_check
CHECK (
    upper(trim(vulnerability_id)) NOT LIKE 'TEMP-%'
    AND upper(trim(id)) NOT LIKE 'TEMP-%'
    AND upper(trim(vulnerability_id)) NOT LIKE 'CVD-%'
    AND upper(trim(id)) NOT LIKE 'CVD-%'
);

ALTER TABLE cve_affected_packages
DROP CONSTRAINT IF EXISTS cve_affected_packages_no_temp_identifier_check;

ALTER TABLE cve_affected_packages
ADD CONSTRAINT cve_affected_packages_no_temp_identifier_check
CHECK (
    upper(trim(vulnerability_id)) NOT LIKE 'TEMP-%'
    AND upper(trim(cve_id)) NOT LIKE 'TEMP-%'
    AND upper(trim(vulnerability_id)) NOT LIKE 'CVD-%'
    AND upper(trim(cve_id)) NOT LIKE 'CVD-%'
);

ALTER TABLE cve_reference_keys
DROP CONSTRAINT IF EXISTS cve_reference_keys_no_temp_identifier_check;

ALTER TABLE cve_reference_keys
ADD CONSTRAINT cve_reference_keys_no_temp_identifier_check
CHECK (
    upper(trim(cve_id)) NOT LIKE 'TEMP-%'
    AND upper(trim(reference_key)) NOT LIKE '%TEMP-%'
    AND upper(trim(cve_id)) NOT LIKE 'CVD-%'
    AND upper(trim(reference_key)) NOT LIKE '%CVD-%'
) NOT VALID;
