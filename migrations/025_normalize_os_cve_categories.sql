UPDATE cve_database
SET category = 'os-package'
WHERE category = 'code-library'
  AND lower(split_part(trim(ecosystem), ':', 1)) IN (
    'debian',
    'ubuntu',
    'alpine',
    'red hat',
    'rhel',
    'suse',
    'almalinux',
    'amazon linux',
    'wolfi',
    'chainguard',
    'rocky linux',
    'oracle linux'
  );
