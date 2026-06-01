-- Force startup to rebuild the derived affected-package index after matchability rules change.
-- The server rebuilds this index after migrations when it is empty.
DELETE FROM cve_affected_packages;
