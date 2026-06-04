DELETE FROM cve_affected_packages
WHERE fixed_version !~ '[0-9]'
   OR fixed_version ~* '^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$'
   OR fixed_version ~* '^(?:https?|git|ssh)://'
   OR fixed_version ~* '^git\+'
   OR fixed_version ~* '^pkg:'
   OR fixed_version ~ '/'
   OR fixed_version ~* '^(?:main|master|trunk|head|latest|stable|unstable|develop|development)$';

ALTER TABLE cve_affected_packages
DROP CONSTRAINT IF EXISTS cve_affected_packages_fixed_version_not_hash_check;

ALTER TABLE cve_affected_packages
ADD CONSTRAINT cve_affected_packages_fixed_version_safe_check
CHECK (
    fixed_version ~ '[0-9]'
    AND fixed_version !~* '^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$'
    AND fixed_version !~* '^(?:https?|git|ssh)://'
    AND fixed_version !~* '^git\+'
    AND fixed_version !~* '^pkg:'
    AND fixed_version !~ '/'
    AND fixed_version !~* '^(?:main|master|trunk|head|latest|stable|unstable|develop|development)$'
);
