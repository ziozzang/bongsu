UPDATE cve_database
SET cvss_score = LEAST(10, GREATEST(0, cvss_score))
WHERE cvss_score < 0 OR cvss_score > 10;

UPDATE cve_database
SET epss_score = LEAST(1, GREATEST(0, epss_score))
WHERE epss_score < 0 OR epss_score > 1;

UPDATE cve_database
SET epss_percentile = LEAST(1, GREATEST(0, epss_percentile))
WHERE epss_percentile < 0 OR epss_percentile > 1;

UPDATE vulnerabilities
SET cvss_score = LEAST(10, GREATEST(0, cvss_score))
WHERE cvss_score < 0 OR cvss_score > 10;

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_cvss_score_range_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_cvss_score_range_check
CHECK (cvss_score >= 0 AND cvss_score <= 10);

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_epss_score_range_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_epss_score_range_check
CHECK (epss_score >= 0 AND epss_score <= 1);

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_epss_percentile_range_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_epss_percentile_range_check
CHECK (epss_percentile >= 0 AND epss_percentile <= 1);

ALTER TABLE vulnerabilities
DROP CONSTRAINT IF EXISTS vulnerabilities_cvss_score_range_check;

ALTER TABLE vulnerabilities
ADD CONSTRAINT vulnerabilities_cvss_score_range_check
CHECK (cvss_score >= 0 AND cvss_score <= 10);
