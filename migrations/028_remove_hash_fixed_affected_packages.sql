DELETE FROM cve_affected_packages
WHERE fixed_version ~* '^[0-9a-f]{40}$';
