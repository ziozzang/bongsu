-- secdb plane separation invariant guard. After Phase 2b, 'cisa-kev' and 'epss'
-- are signal-plane source names, routed exclusively to cve_kev / cve_epss at
-- ingest (see UpsertCveEntriesTx). This constraint makes that a hard DB
-- invariant: a signal row can never re-enter the advisory table cve_database,
-- regardless of code path. It is intentionally NARROW — it forbids only the two
-- reserved signal source names, so custom advisory feeds (any other source name)
-- are unaffected. Must run after migration 074 has removed the existing
-- cisa-kev/epss rows, or the constraint validation would fail.

ALTER TABLE cve_database
    DROP CONSTRAINT IF EXISTS cve_database_no_signal_source;
ALTER TABLE cve_database
    ADD CONSTRAINT cve_database_no_signal_source
    CHECK (source NOT IN ('cisa-kev', 'epss'));
