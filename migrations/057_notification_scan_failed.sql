-- Allow the scan.failed notification trigger (scans that finish degraded/failed
-- or with ingest errors).
ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_trigger_event_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_trigger_event_check
    CHECK (trigger_event IN ('', 'vuln.new_critical', 'vuln.new_high', 'sla.breach',
        'scan.completed', 'scan.failed', 'security_db.updated', 'schedule.daily'));
