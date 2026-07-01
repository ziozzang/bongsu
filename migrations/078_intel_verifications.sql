-- Majority-vote adversarial verification (design:
-- docs/redesign-verify-voting-trinity.md). The single-shot `verify` scenario is
-- upgraded to N independent, lens-diverse voters whose verdicts are aggregated by
-- majority. Each voter is a normal, fully-audited intel_runs row (scenario=
-- 'verify', its own session); this table records only the AGGREGATE verdict and
-- links its voter runs by FK. No parent/fake run row is created.

CREATE TABLE IF NOT EXISTS intel_verifications (
    id               BIGSERIAL PRIMARY KEY,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at      TIMESTAMPTZ,

    principal_id     TEXT NOT NULL DEFAULT '',
    scenario         TEXT NOT NULL DEFAULT 'verify',
    params           JSONB NOT NULL DEFAULT '{}'::jsonb,   -- {cve, scan_id, package, ...}

    requested_voters INTEGER NOT NULL,
    min_success      INTEGER NOT NULL,                     -- success quorum (default = majority)
    lenses           JSONB NOT NULL DEFAULT '[]'::jsonb,   -- assigned lens list

    status           TEXT NOT NULL DEFAULT 'running',      -- running|complete|inconclusive|failed
    verdict          TEXT NOT NULL DEFAULT 'inconclusive', -- valid|refuted|inconclusive
    valid            BOOLEAN NOT NULL DEFAULT false,
    confidence       NUMERIC(5,4) NOT NULL DEFAULT 0,

    succeeded_voters INTEGER NOT NULL DEFAULT 0,
    failed_voters    INTEGER NOT NULL DEFAULT 0,
    valid_votes      INTEGER NOT NULL DEFAULT 0,
    refuted_votes    INTEGER NOT NULL DEFAULT 0,

    votes            JSONB NOT NULL DEFAULT '[]'::jsonb,   -- [{index,lens,run_id,status,valid,confidence,error}]

    CONSTRAINT intel_verifications_status_chk
        CHECK (status IN ('running','complete','inconclusive','failed')),
    CONSTRAINT intel_verifications_verdict_chk
        CHECK (verdict IN ('valid','refuted','inconclusive')),
    CONSTRAINT intel_verifications_confidence_chk
        CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_intel_verifications_created_at
    ON intel_verifications (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_verifications_principal_created
    ON intel_verifications (principal_id, created_at DESC);

-- Link each voter run back to its verification (nullable: an ordinary run has none).
ALTER TABLE intel_runs
    ADD COLUMN IF NOT EXISTS verification_id BIGINT REFERENCES intel_verifications(id),
    ADD COLUMN IF NOT EXISTS voter_index SMALLINT,
    ADD COLUMN IF NOT EXISTS voter_lens TEXT;

CREATE INDEX IF NOT EXISTS idx_intel_runs_verification_id
    ON intel_runs (verification_id) WHERE verification_id IS NOT NULL;
