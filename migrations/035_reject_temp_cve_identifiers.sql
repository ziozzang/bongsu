DELETE FROM cve_database
WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
   OR upper(trim(id)) LIKE 'TEMP-%';

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_no_temp_identifier_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_no_temp_identifier_check
CHECK (upper(trim(vulnerability_id)) NOT LIKE 'TEMP-%' AND upper(trim(id)) NOT LIKE 'TEMP-%');
