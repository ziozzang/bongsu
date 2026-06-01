WITH duplicate_ghsa_keys AS (
    SELECT cve_id,
           reference_key,
           row_number() OVER (
               PARTITION BY cve_id, upper(substring(reference_key from length('ghsa:') + 1))
               ORDER BY reference_key
           ) AS rn
    FROM cve_reference_keys
    WHERE reference_key ILIKE 'ghsa:%'
)
DELETE FROM cve_reference_keys rk
USING duplicate_ghsa_keys d
WHERE rk.cve_id = d.cve_id
  AND rk.reference_key = d.reference_key
  AND d.rn > 1;

UPDATE cve_reference_keys
SET reference_key = 'ghsa:' || upper(substring(reference_key from length('ghsa:') + 1))
WHERE reference_key ILIKE 'ghsa:%'
  AND reference_key <> 'ghsa:' || upper(substring(reference_key from length('ghsa:') + 1));

ALTER TABLE cve_reference_keys
DROP CONSTRAINT IF EXISTS cve_reference_keys_ghsa_canonical_case_check;

ALTER TABLE cve_reference_keys
ADD CONSTRAINT cve_reference_keys_ghsa_canonical_case_check
CHECK (reference_key NOT ILIKE 'ghsa:%' OR reference_key ~ '^ghsa:GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$') NOT VALID;
