-- Phase A v2 auth audit: persist the security-relevant credential-resolution
-- decisions made by buildPrincipal (internal/server/api/principal.go).
--
-- Only NON-TRIVIAL resolutions are recorded — a request rejected for presenting
-- two distinct identities (rejected=true), one whose first-wins identity was
-- enriched with same-identity RBAC subjects (enriched=true), or one that simply
-- carried more than one identity credential (multi_identity=true). The common
-- single-credential request writes nothing, so this table stays small and the
-- insert never sits on the hot path for normal traffic. The insert is best-effort
-- and asynchronous; an auth decision is never blocked or failed by an audit write
-- error (the structured stderr log line is the fallback).
--
-- `presented` / `decisions` carry the full per-source audit trail as JSONB so an
-- operator can reconstruct exactly which credentials were offered and how each
-- was treated (selected / enriched_same_identity / ignored_same_identity /
-- rejected_identity_mismatch / added_capability / ignored_capability).

CREATE TABLE IF NOT EXISTS auth_events (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id      TEXT NOT NULL DEFAULT '',
    remote_addr     TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',

    final_kind         TEXT NOT NULL DEFAULT '',
    final_id           TEXT NOT NULL DEFAULT '',
    final_admin        BOOLEAN NOT NULL DEFAULT false,
    final_identity_key TEXT NOT NULL DEFAULT '',

    rejected        BOOLEAN NOT NULL DEFAULT false,
    reject_reason   TEXT NOT NULL DEFAULT '',
    multi_identity  BOOLEAN NOT NULL DEFAULT false,
    enriched        BOOLEAN NOT NULL DEFAULT false,

    presented       JSONB NOT NULL DEFAULT '[]'::jsonb,
    decisions       JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_events_rejected ON auth_events (created_at DESC) WHERE rejected;
CREATE INDEX IF NOT EXISTS idx_auth_events_identity_key ON auth_events (final_identity_key) WHERE final_identity_key <> '';
