DELETE FROM cve_database
WHERE upper(trim(vulnerability_id)) ~ '^TEMP-[0-9A-F-]+$'
   OR upper(trim(id)) ~ '^TEMP-[0-9A-F-]+$';
