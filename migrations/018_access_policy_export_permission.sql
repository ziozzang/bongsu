ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_permission_check;
ALTER TABLE access_policies ADD CONSTRAINT access_policies_permission_check
    CHECK (permission IN ('read', 'write', 'admin', 'export'));
