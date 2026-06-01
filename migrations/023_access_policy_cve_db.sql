ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_resource_type_check;
ALTER TABLE access_policies ADD CONSTRAINT access_policies_resource_type_check
    CHECK (resource_type IN ('host', 'container', 'image', 'asset_group', 'cve_db', 'all'));
