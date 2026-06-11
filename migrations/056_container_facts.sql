-- Per-container distro identity facts (os-release, release markers) collected
-- from inside each container's rootfs. Unstructured JSONB, like host facts.
ALTER TABLE container_assets ADD COLUMN IF NOT EXISTS facts JSONB NOT NULL DEFAULT '{}'::jsonb;
