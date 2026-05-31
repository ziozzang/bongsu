-- Normalize severity based on CVSS score when there's a mismatch
UPDATE vulnerabilities SET severity = 'CRITICAL' WHERE cvss_score >= 9.0 AND severity != 'CRITICAL';
UPDATE vulnerabilities SET severity = 'HIGH' WHERE cvss_score >= 7.0 AND cvss_score < 9.0 AND severity NOT IN ('CRITICAL', 'HIGH');
UPDATE vulnerabilities SET severity = 'MEDIUM' WHERE cvss_score >= 4.0 AND cvss_score < 7.0 AND severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM');
UPDATE vulnerabilities SET severity = 'LOW' WHERE cvss_score > 0 AND cvss_score < 4.0 AND severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');
