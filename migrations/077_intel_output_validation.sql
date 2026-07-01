-- Structured-termination support: record whether a run's output conformed to its
-- scenario OutputSchema. The runner validates the model's final response against
-- the schema's required fields and, on failure, does one corrective retry; the
-- result is recorded here for audit and for downstream consumers to trust.

ALTER TABLE intel_runs
    ADD COLUMN IF NOT EXISTS output_valid BOOLEAN,
    ADD COLUMN IF NOT EXISTS output_validation_error TEXT NOT NULL DEFAULT '';
