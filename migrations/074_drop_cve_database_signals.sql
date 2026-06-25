-- secdb Phase 2b Step 3 (DESTRUCTIVE) — finalize the signal-plane separation.
-- Deploy ONLY after the Step1+2 code (a109253) is live: that code stopped
-- writing KEV/EPSS into cve_database (routing to cve_kev/cve_epss) and stopped
-- reading the epss_score/epss_percentile columns (correlated subquery on
-- cve_epss). With no reader or writer left, the co-mingled signal rows and the
-- double-stored EPSS columns are removed. cve_database is now advisory-only
-- (osv/nvd/trivy/custom). cve_kev / cve_epss are the sole source of truth for
-- the KEV exploited flag and the EPSS score.
--
-- The signal tables were already backfilled by migration 072; this migration
-- only deletes the now-redundant copies. Take a `pg_dump -t cve_database
-- --data-only` backup before applying — there is no in-place rollback.

DELETE FROM cve_database WHERE source IN ('cisa-kev', 'epss');

-- DROP COLUMN cascades to idx_cve_db_epss_score / idx_cve_db_epss_percentile
-- (migration 020) automatically.
ALTER TABLE cve_database
    DROP COLUMN IF EXISTS epss_score,
    DROP COLUMN IF EXISTS epss_percentile;
