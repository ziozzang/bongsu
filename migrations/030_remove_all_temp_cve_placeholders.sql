DELETE FROM cve_database
WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
   OR upper(trim(id)) LIKE 'TEMP-%';
