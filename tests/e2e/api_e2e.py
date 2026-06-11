#!/usr/bin/env python3
"""Bongsu API end-to-end robustness suite.

Exercises the live server API the way an operator/integration would:
positive flows, validation rejections, and cross-feature consistency.

Configuration (environment):
  BONGSU_E2E_BASE_URL       default http://localhost:5677
  BONGSU_E2E_API_KEY        admin API key (required)
  BONGSU_E2E_VIEWER_KEY     optional viewer key for RBAC checks
  BONGSU_E2E_SMTP_SINK_LOG  optional path to SMTP sink capture file;
                            enables email delivery assertions
  BONGSU_E2E_HEAVY=1        include slow tests (security DB bundle export)

Run: python3 tests/e2e/api_e2e.py  (or via scripts/verify-e2e-api.sh)
"""
import json
import os
import sys
import time
import unittest
import uuid

import requests

BASE = os.environ.get('BONGSU_E2E_BASE_URL', 'http://localhost:5677').rstrip('/')
API_KEY = os.environ.get('BONGSU_E2E_API_KEY', '')
VIEWER_KEY = os.environ.get('BONGSU_E2E_VIEWER_KEY', '')
SMTP_SINK_LOG = os.environ.get('BONGSU_E2E_SMTP_SINK_LOG', '')
HEAVY = os.environ.get('BONGSU_E2E_HEAVY', '') == '1'

S = requests.Session()
S.headers['X-API-Key'] = API_KEY


def api(method, path, expect=None, json_body=None, params=None, key=None, timeout=60, stream=False):
    headers = {'X-API-Key': key} if key is not None else None
    r = S.request(method, BASE + path, json=json_body, params=params,
                  headers=headers, timeout=timeout, stream=stream)
    if expect is not None and r.status_code != expect:
        raise AssertionError(f'{method} {path}: expected HTTP {expect}, got {r.status_code}: {r.text[:300]}')
    return r


class Base(unittest.TestCase):
    maxDiff = None


class TestHealthAndAuth(Base):
    def test_health_ok(self):
        body = api('GET', '/api/health', expect=200).json()
        self.assertIn('status', body)
        self.assertIn('version', body)

    def test_bad_api_key_rejected(self):
        api('GET', '/api/hosts', expect=401, key='definitely-wrong-key')

    def test_admin_endpoint_requires_admin(self):
        if not VIEWER_KEY:
            self.skipTest('BONGSU_E2E_VIEWER_KEY not set')
        r = api('POST', '/api/admin/notification-rules', key=VIEWER_KEY,
                json_body={'name': 'x', 'trigger_event': 'scan.completed'})
        self.assertIn(r.status_code, (401, 403))

    def test_security_db_status_shape(self):
        body = api('GET', '/api/admin/security-db/status', expect=200).json()
        for key in ('security_db', 'cve_db_quality', 'cve_affected_package_index'):
            self.assertIn(key, body)
        # sync manager must expose retry/backoff state (consecutive_failures)
        self.assertIn('consecutive_failures', body['security_db'])


class TestTriageAssignee(Base):
    """Per-finding assignee (담당자) lifecycle and filtering."""

    @classmethod
    def setUpClass(cls):
        items = api('GET', '/api/vulnerabilities', expect=200,
                    params={'limit': '1'}).json().get('items') or []
        if not items:
            raise unittest.SkipTest('no vulnerabilities in environment')
        cls.vuln = items[0]
        cls.assignee = f'e2e-{uuid.uuid4().hex[:8]}'

    def triage(self, body, expect=200):
        payload = {
            'vulnerability_id': self.vuln['vulnerability_id'],
            'host_id': self.vuln['host_id'],
            'pkg_name': self.vuln['pkg_name'],
        }
        payload.update(body)
        return api('POST', '/api/vulnerabilities/triage', expect=expect, json_body=payload)

    def test_1_assign_and_filter(self):
        self.triage({'status': 'in_progress', 'assignee': self.assignee})
        items = api('GET', '/api/vulnerabilities', expect=200,
                    params={'assignee': self.assignee, 'limit': '5'}).json().get('items') or []
        self.assertGreaterEqual(len(items), 1, 'assignee filter must return the assigned finding')
        self.assertEqual(items[0].get('triage_assignee'), self.assignee)

    def test_2_unassigned_filter_excludes(self):
        items = api('GET', '/api/vulnerabilities', expect=200,
                    params={'assignee': 'unassigned', 'limit': '200'}).json().get('items') or []
        ids = {(v['vulnerability_id'], v['host_id'], v['pkg_name']) for v in items}
        key = (self.vuln['vulnerability_id'], self.vuln['host_id'], self.vuln['pkg_name'])
        self.assertNotIn(key, ids, 'assigned finding must not appear in unassigned filter')

    def test_3_invalid_status_rejected(self):
        self.triage({'status': 'not-a-status'}, expect=400)

    def test_4_accepted_risk_requires_reason(self):
        self.triage({'status': 'accepted_risk', 'reason': ''}, expect=400)

    def test_9_cleanup(self):
        self.triage({'status': 'open', 'assignee': ''})


class TestNotificationRules(Base):
    created = []

    @classmethod
    def tearDownClass(cls):
        for rid in cls.created:
            api('DELETE', f'/api/admin/notification-rules/{rid}')

    def create(self, body, expect=201):
        r = api('POST', '/api/admin/notification-rules', expect=expect, json_body=body)
        if r.status_code == 201:
            self.created.append(r.json()['id'])
        return r

    def test_webhook_requires_url(self):
        self.create({'name': 'e2e-webhook-nourl', 'trigger_event': 'scan.completed',
                     'channel_type': 'webhook', 'channel_config': {}}, expect=400)

    def test_email_requires_recipient(self):
        self.create({'name': 'e2e-email-noto', 'trigger_event': 'scan.completed',
                     'channel_type': 'email', 'channel_config': {}}, expect=400)

    def test_unknown_channel_rejected(self):
        self.create({'name': 'e2e-bad-channel', 'trigger_event': 'scan.completed',
                     'channel_type': 'pigeon'}, expect=400)

    def test_email_rule_lifecycle(self):
        r = self.create({'name': 'e2e-email-rule', 'trigger_event': 'scan.completed',
                         'channel_type': 'email',
                         'channel_config': {'to': 'e2e@test.local', 'subject_prefix': '[E2E]'}})
        if r.status_code == 400 and 'smtp' in r.text.lower():
            self.skipTest('SMTP not configured on server')
        rule = r.json()
        # update must go through PUT and persist
        upd = api('PUT', f"/api/admin/notification-rules/{rule['id']}", expect=200,
                  json_body={'name': 'e2e-email-rule-renamed'}).json()
        self.assertEqual(upd['name'], 'e2e-email-rule-renamed')
        # test dispatch
        api('POST', f"/api/admin/notification-rules/{rule['id']}/test", expect=200)
        if SMTP_SINK_LOG and os.path.exists(SMTP_SINK_LOG):
            deadline = time.time() + 10
            content = ''
            while time.time() < deadline:
                with open(SMTP_SINK_LOG) as f:
                    content = f.read()
                if 'e2e@test.local' in content:
                    break
                time.sleep(0.5)
            self.assertIn('e2e@test.local', content, 'SMTP sink must receive the test email')
            self.assertIn('[E2E] test', content)

    def test_log_rule_create(self):
        self.create({'name': 'e2e-log-rule', 'trigger_event': 'security_db.updated',
                     'channel_type': 'log'})


class TestScanRequests(Base):
    @classmethod
    def setUpClass(cls):
        hosts = api('GET', '/api/hosts', expect=200).json() or []
        if not hosts:
            raise unittest.SkipTest('no hosts registered')
        cls.host_id = hosts[0]['id']

    def test_lifecycle(self):
        r = api('POST', '/api/scan-requests', expect=202,
                json_body={'host_id': self.host_id, 'scan_type': 'manual',
                           'packages_only': True, 'reason': 'e2e robustness check'})
        req = r.json()
        self.assertEqual(req['status'], 'pending')
        listed = api('GET', '/api/scan-requests', expect=200,
                     params={'host_id': self.host_id, 'status': 'pending', 'limit': '50'}).json()
        self.assertTrue(any(i['id'] == req['id'] for i in listed.get('items', [])))
        api('POST', f"/api/scan-requests/{req['id']}/cancel", expect=200)
        listed = api('GET', '/api/scan-requests', expect=200,
                     params={'host_id': self.host_id, 'status': 'cancelled', 'limit': '50'}).json()
        self.assertTrue(any(i['id'] == req['id'] for i in listed.get('items', [])))

    def test_invalid_scan_type_rejected(self):
        api('POST', '/api/scan-requests', expect=400,
            json_body={'host_id': self.host_id, 'scan_type': 'force'})

    def test_requeue_stale_endpoint(self):
        api('POST', '/api/scan-requests/requeue-stale', expect=200, json_body={})


class TestSchedules(Base):
    def test_lifecycle_with_put_update(self):
        r = api('POST', '/api/admin/schedules', expect=201,
                json_body={'name': 'e2e-sched', 'cron_expr': '30 3 * * *'})
        sched = r.json()
        try:
            upd = api('PUT', f"/api/admin/schedules/{sched['id']}", expect=200,
                      json_body={'name': 'e2e-sched-renamed', 'cron_expr': '0 4 * * *',
                                 'enabled': False}).json()
            self.assertEqual(upd['name'], 'e2e-sched-renamed')
            self.assertFalse(upd['enabled'])
            got = api('GET', f"/api/admin/schedules/{sched['id']}", expect=200).json()
            self.assertEqual(got['cron_expr'], '0 4 * * *')
        finally:
            api('DELETE', f"/api/admin/schedules/{sched['id']}", expect=200)


class TestAssetGroups(Base):
    @classmethod
    def setUpClass(cls):
        hosts = api('GET', '/api/hosts', expect=200).json() or []
        cls.host_id = hosts[0]['id'] if hosts else ''

    def test_membership_lifecycle(self):
        r = api('POST', '/api/asset-groups', expect=201,
                json_body={'name': f'e2e-group-{uuid.uuid4().hex[:6]}', 'rule_type': 'static'})
        group = r.json()
        try:
            if self.host_id:
                api('POST', f"/api/asset-groups/{group['id']}/hosts", expect=200,
                    json_body={'host_id': self.host_id})
                detail = api('GET', f"/api/asset-groups/{group['id']}", expect=200).json()
                self.assertIn(self.host_id, detail.get('host_ids') or [])
                api('DELETE', f"/api/asset-groups/{group['id']}/hosts/{self.host_id}", expect=200)
                detail = api('GET', f"/api/asset-groups/{group['id']}", expect=200).json()
                self.assertNotIn(self.host_id, detail.get('host_ids') or [])
        finally:
            api('DELETE', f"/api/asset-groups/{group['id']}", expect=200)


class TestIntelligenceAndReports(Base):
    def test_endpoints_respond_with_shape(self):
        cases = [
            ('/api/intelligence/top-risk', 'items'),
            ('/api/intelligence/recommendations', 'items'),
            ('/api/intelligence/posture', 'current_total'),
            ('/api/reports/executive-summary', 'total_hosts'),
            ('/api/reports/sla-compliance', 'by_severity'),
            ('/api/reports/risk-breakdown', 'items'),
        ]
        for path, key in cases:
            with self.subTest(path=path):
                body = api('GET', path, expect=200).json()
                self.assertIn(key, body)


class TestCveDb(Base):
    def test_search(self):
        body = api('GET', '/api/cve-db/search', expect=200,
                   params={'q': 'CVE-2021', 'limit': '5'}).json()
        self.assertIn('items', body)

    def test_stats(self):
        body = api('GET', '/api/cve-db/stats', expect=200).json()
        self.assertIn('sources', body)

    @unittest.skipUnless(HEAVY, 'set BONGSU_E2E_HEAVY=1 to run bundle export')
    def test_bundle_export(self):
        r = api('GET', '/api/admin/security-db/export', expect=200,
                params={'include_trivy': 'false'}, timeout=600, stream=True)
        head = next(r.iter_content(chunk_size=2))
        self.assertEqual(head, b'\x1f\x8b', 'bundle must be gzip')
        size = len(head)
        for chunk in r.iter_content(chunk_size=1 << 20):
            size += len(chunk)
        self.assertGreater(size, 1 << 20, 'bundle should be at least 1MB')


class TestSearchSurface(Base):
    """Detailed search filters + reverse lookups added for commercial-grade search."""

    def test_package_filters_combine(self):
        body = api('GET', '/api/packages', expect=200,
                   params={'asset_type': 'host', 'limit': '5'}).json()
        self.assertIn('items', body)
        for p in body['items']:
            self.assertFalse(p.get('container'), 'asset_type=host must exclude container rows')
        # exact-name + version reverse lookup: pick a real package then re-find it
        seed = api('GET', '/api/packages', expect=200, params={'limit': '1'}).json()
        if seed['items']:
            name = seed['items'][0]['name']
            ver = seed['items'][0]['version']
            body = api('GET', '/api/packages', expect=200,
                       params={'name': name, 'version': ver, 'limit': '10'}).json()
            self.assertGreaterEqual(body['total'], 1)
            for p in body['items']:
                self.assertEqual(p['name'].lower(), name.lower())
                self.assertEqual(p['version'], ver)

    def test_package_has_vulns_filter(self):
        body = api('GET', '/api/packages', expect=200,
                   params={'has_vulns': 'true', 'limit': '5'}).json()
        self.assertIn('total', body)

    def test_vuln_id_pattern_filter(self):
        body = api('GET', '/api/vulnerabilities', expect=200,
                   params={'vuln_id': 'CVE-', 'limit': '5'}).json()
        items = body.get('items', body if isinstance(body, list) else [])
        for v in items:
            self.assertIn('CVE-', v['vulnerability_id'].upper())

    def test_vuln_has_fix_filter(self):
        with_fix = api('GET', '/api/vulnerabilities', expect=200,
                       params={'has_fix': 'yes', 'limit': '5'}).json()
        items = with_fix.get('items', with_fix if isinstance(with_fix, list) else [])
        for v in items:
            self.assertTrue(v.get('fixed_version'),
                            'has_fix=yes must only return findings with a fix')

    def test_host_metadata_filters(self):
        hosts = api('GET', '/api/hosts', expect=200).json()
        if hosts:
            env = next((h.get('environment') for h in hosts if h.get('environment')), None)
            if env:
                filtered = api('GET', '/api/hosts', expect=200,
                               params={'environment': env}).json()
                self.assertGreaterEqual(len(filtered), 1)
                for h in filtered:
                    self.assertEqual(h.get('environment', '').lower(), env.lower())
        # q filter never errors even with no match
        api('GET', '/api/hosts', expect=200, params={'q': 'zz-no-such-host-zz'})

    def test_affected_assets_reverse_lookup(self):
        body = api('GET', '/api/vulnerabilities', expect=200, params={'limit': '1'}).json()
        items = body.get('items', body if isinstance(body, list) else [])
        if not items:
            self.skipTest('no vulnerabilities in dataset')
        cve = items[0]['vulnerability_id']
        res = api('GET', '/api/vulnerabilities/affected-assets', expect=200,
                  params={'vulnerability_id': cve, 'limit': '10'}).json()
        self.assertEqual(res['vulnerability_id'], cve)
        self.assertIn('assets', res)
        self.assertGreaterEqual(res['total'], 1, 'a listed vuln must have at least one affected asset')
        a = res['assets'][0]
        for field in ('host_id', 'hostname', 'asset_type', 'pkg_name', 'installed_version', 'severity'):
            self.assertIn(field, a)

    def test_affected_assets_requires_id(self):
        api('GET', '/api/vulnerabilities/affected-assets', expect=400)


class TestRBACViewerKey(Base):
    """RBAC fail-closed: a viewer key with no granted subjects must not leak unscoped data.

    The server treats an unknown-to-server viewer key as a viewer with zero subjects,
    so all scoped list endpoints return 200 with empty results rather than leaking
    all-tenant data.  Admin-only endpoints must return 401 or 403.

    Skipped entirely if BONGSU_E2E_VIEWER_KEY is not set.
    """

    @classmethod
    def setUpClass(cls):
        if not VIEWER_KEY:
            raise unittest.SkipTest('BONGSU_E2E_VIEWER_KEY not set')
        # Confirm admin key has at least one host so the dataset is non-empty.
        hosts = api('GET', '/api/hosts', expect=200).json() or []
        if not hosts:
            raise unittest.SkipTest('no hosts in dataset – RBAC leak check would be vacuous')

    def _assert_no_leak(self, path, params=None):
        """GET path with viewer key: must be 403 or return scoped/empty list."""
        r = api('GET', path, key=VIEWER_KEY, params=params)
        if r.status_code == 403:
            return  # explicit deny is fine
        self.assertEqual(r.status_code, 200,
                         f'{path}: unexpected status {r.status_code}')
        body = r.json()
        # Must not expose any hosts/vulns/packages that belong to other tenants.
        if isinstance(body, list):
            self.assertEqual(body, [], f'{path}: viewer got non-empty list – possible data leak')
        elif isinstance(body, dict):
            items = body.get('items', [])
            total = body.get('total', body.get('total_vulnerabilities', body.get('total_hosts', None)))
            if items:
                self.fail(f'{path}: viewer got {len(items)} items – possible data leak')
            if total not in (None, 0):
                self.fail(f'{path}: viewer got total={total} – possible data leak')

    def test_hosts_no_leak(self):
        self._assert_no_leak('/api/hosts')

    def test_packages_no_leak(self):
        self._assert_no_leak('/api/packages')

    def test_vulnerabilities_no_leak(self):
        self._assert_no_leak('/api/vulnerabilities')

    def test_stats_no_leak(self):
        """Stats with viewer key must return zeroed counts, not full fleet data."""
        r = api('GET', '/api/stats', key=VIEWER_KEY)
        if r.status_code == 403:
            return
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ('total_vulnerabilities', 'total_hosts'):
            if key in body:
                self.assertEqual(body[key], 0,
                                 f'/api/stats: viewer got {key}={body[key]} – data leak')

    def test_admin_retention_prune_denied(self):
        """Admin-only POST /api/admin/retention/prune must reject viewer key."""
        r = api('POST', '/api/admin/retention/prune', key=VIEWER_KEY,
                json_body={'dry_run': True})
        self.assertIn(r.status_code, (401, 403),
                      f'viewer key must not reach admin prune endpoint, got {r.status_code}')

    def test_admin_audit_logs_denied(self):
        """Admin-only GET /api/admin/audit-logs must reject viewer key."""
        r = api('GET', '/api/admin/audit-logs', key=VIEWER_KEY)
        self.assertIn(r.status_code, (401, 403),
                      f'viewer key must not read audit logs, got {r.status_code}')

    def test_admin_metrics_denied(self):
        """Admin-only GET /api/admin/metrics must reject viewer key."""
        r = api('GET', '/api/admin/metrics', key=VIEWER_KEY)
        self.assertIn(r.status_code, (401, 403),
                      f'viewer key must not read Prometheus metrics, got {r.status_code}')


class TestAuthNegatives(Base):
    """Authentication rejection cases across key types and endpoints."""

    def test_wrong_key_hosts_401(self):
        api('GET', '/api/hosts', expect=401, key='definitely-wrong-key-xyzzy')

    def test_missing_key_hosts_401(self):
        """Completely absent X-API-Key header must return 401."""
        r = S.get(BASE + '/api/hosts', headers={'X-API-Key': ''}, timeout=10)
        self.assertEqual(r.status_code, 401,
                         f'missing key on /api/hosts: expected 401, got {r.status_code}')

    def test_wrong_key_vulnerabilities_401(self):
        api('GET', '/api/vulnerabilities', expect=401, key='bad-key-zyx')

    def test_missing_key_vulnerabilities_401(self):
        r = S.get(BASE + '/api/vulnerabilities', headers={'X-API-Key': ''}, timeout=10)
        self.assertEqual(r.status_code, 401)

    def test_admin_key_on_agent_report_endpoint(self):
        """POST /api/report uses authenticateAgent.
        When BONGSU_AGENT_API_KEY is unset the server falls back to apiKey, so the admin
        key is also accepted as an agent key.  The actual 403 comes from a missing
        per-host agent token, not from auth – encode that reality.
        """
        r = api('POST', '/api/report', json_body={}, key=API_KEY)
        # 400 (bad body after auth) or 403 (missing host token after auth) both mean auth passed.
        self.assertIn(r.status_code, (400, 403),
                      f'admin key on /api/report: unexpected status {r.status_code}: {r.text[:200]}')

    def test_wrong_key_report_401(self):
        api('POST', '/api/report', expect=401, key='completely-wrong-key-123')


class TestInputValidationHardening(Base):
    """Garbage / boundary inputs must never produce HTTP 500."""

    def test_min_epss_garbage_no_500(self):
        r = api('GET', '/api/vulnerabilities', params={'min_epss': 'abc'})
        self.assertNotEqual(r.status_code, 500,
                            f'min_epss=abc caused 500: {r.text[:200]}')
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn('items', body)

    def test_limit_negative_no_500(self):
        r = api('GET', '/api/vulnerabilities', params={'limit': '-5'})
        self.assertNotEqual(r.status_code, 500,
                            f'limit=-5 caused 500: {r.text[:200]}')
        self.assertEqual(r.status_code, 200)
        body = r.json()
        # Server should clamp to a sane default; items list must not be empty if data exists.
        self.assertIn('items', body)

    def test_limit_huge_no_500(self):
        r = api('GET', '/api/vulnerabilities', params={'limit': '999999'})
        self.assertNotEqual(r.status_code, 500,
                            f'limit=999999 caused 500: {r.text[:200]}')
        self.assertEqual(r.status_code, 200)

    def test_oversized_q_no_500_vulnerabilities(self):
        big_q = 'A' * 10240
        r = api('GET', '/api/vulnerabilities', params={'q': big_q})
        self.assertNotEqual(r.status_code, 500,
                            f'10KB q on /api/vulnerabilities caused 500: {r.text[:200]}')

    def test_oversized_q_no_500_hosts(self):
        big_q = 'A' * 10240
        r = api('GET', '/api/hosts', params={'q': big_q})
        self.assertNotEqual(r.status_code, 500,
                            f'10KB q on /api/hosts caused 500: {r.text[:200]}')

    def test_triage_invalid_json_400(self):
        """Invalid JSON body on triage endpoint must return 400, not 500."""
        import requests as _req
        r = _req.post(BASE + '/api/vulnerabilities/triage',
                      headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
                      data='not-valid-json', timeout=10)
        self.assertEqual(r.status_code, 400,
                         f'invalid JSON on triage: expected 400, got {r.status_code}: {r.text[:200]}')

    def test_affected_assets_missing_id_400(self):
        """GET /api/vulnerabilities/affected-assets without vulnerability_id → 400."""
        api('GET', '/api/vulnerabilities/affected-assets', expect=400)

    def test_packages_limit_garbage_no_500(self):
        r = api('GET', '/api/packages', params={'limit': 'abc'})
        self.assertNotEqual(r.status_code, 500,
                            f'limit=abc on /api/packages caused 500: {r.text[:200]}')


class TestExportIntegrity(Base):
    """Export endpoint returns correct content-type, structure, and row counts."""

    def test_csv_200_and_content_type(self):
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'csv'})
        ct = r.headers.get('Content-Type', '')
        self.assertIn('csv', ct.lower(),
                      f'CSV export wrong Content-Type: {ct}')

    def test_csv_header_row_present(self):
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'csv', 'limit': '5'})
        lines = r.text.splitlines()
        self.assertGreater(len(lines), 0, 'CSV export is empty')
        header = lines[0]
        # These columns must exist in any sensible export header.
        for col in ('vulnerability_id', 'severity', 'pkg_name'):
            self.assertIn(col, header,
                          f'CSV header missing expected column {col!r}')

    def test_csv_row_count_matches_limit(self):
        """Data rows (excluding header) must equal the requested limit when data exists."""
        limit = 10
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'csv', 'limit': str(limit)})
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        header_rows = 1
        data_rows = len(lines) - header_rows
        # Allow fewer rows only if total < limit.
        body_check = api('GET', '/api/vulnerabilities', expect=200,
                         params={'limit': '1'}).json()
        total = body_check.get('total', 0)
        expected = min(limit, total)
        self.assertEqual(data_rows, expected,
                         f'CSV: expected {expected} data rows for limit={limit}, got {data_rows}')

    def test_json_export_200_and_structure(self):
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'json'})
        body = r.json()
        for key in ('items', 'total', 'exported', 'metadata'):
            self.assertIn(key, body, f'JSON export missing key {key!r}')

    def test_json_export_filters_echoed_in_metadata(self):
        """Metadata in JSON export must echo the request filters."""
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'json', 'limit': '5'})
        body = r.json()
        meta = body.get('metadata', {})
        self.assertIn('filters', meta, 'JSON export metadata must contain filters key')
        self.assertIn('format', meta, 'JSON export metadata must contain format key')
        self.assertIn('generated_at', meta, 'JSON export metadata must contain generated_at')

    def test_json_export_item_count_matches_exported(self):
        limit = 5
        r = api('GET', '/api/vulnerabilities/export', expect=200,
                params={'format': 'json', 'limit': str(limit)})
        body = r.json()
        items = body.get('items', [])
        exported = body.get('exported', -1)
        self.assertEqual(len(items), exported,
                         f'JSON export: items length {len(items)} != exported field {exported}')


class TestHealthMetricsSurface(Base):
    """Health and metrics endpoints expose the expected keys and auth posture."""

    def test_health_security_db_freshness_keys(self):
        body = api('GET', '/api/health', expect=200).json()
        self.assertIn('security_db_freshness', body,
                      '/api/health must include security_db_freshness')
        freshness = body['security_db_freshness']
        for key in ('status', 'stale', 'source_count'):
            self.assertIn(key, freshness,
                          f'/api/health security_db_freshness missing key {key!r}')

    def test_admin_metrics_200_with_admin_key(self):
        body = api('GET', '/api/admin/metrics', expect=200).text
        self.assertIn('bongsu_', body,
                      '/api/admin/metrics must return Prometheus text with bongsu_ metrics')

    def test_admin_metrics_known_metric_present(self):
        body = api('GET', '/api/admin/metrics', expect=200).text
        self.assertIn('bongsu_build_info', body,
                      'bongsu_build_info metric must be present in /api/admin/metrics')

    def test_admin_metrics_no_key_denied(self):
        """Prometheus metrics must not be exposed without authentication."""
        import requests as _req
        r = _req.get(BASE + '/api/admin/metrics',
                     headers={'X-API-Key': ''}, timeout=10)
        self.assertIn(r.status_code, (401, 403),
                      f'/api/admin/metrics without key: expected 401/403, got {r.status_code}')

    def test_admin_metrics_wrong_key_denied(self):
        api('GET', '/api/admin/metrics', expect=401, key='not-the-admin-key-xyzzy')


class TestPaginationInvariants(Base):
    """Offset-based pagination must be stable and produce disjoint pages."""

    @classmethod
    def setUpClass(cls):
        pkg_total = api('GET', '/api/packages', expect=200,
                        params={'limit': '1'}).json().get('total', 0)
        vuln_total = api('GET', '/api/vulnerabilities', expect=200,
                         params={'limit': '1'}).json().get('total', 0)
        if pkg_total < 10:
            raise unittest.SkipTest(f'need ≥10 packages for pagination tests, got {pkg_total}')
        if vuln_total < 10:
            raise unittest.SkipTest(f'need ≥10 vulnerabilities for pagination tests, got {vuln_total}')

    def test_packages_pages_disjoint(self):
        page0 = api('GET', '/api/packages', expect=200,
                    params={'limit': '5', 'offset': '0'}).json()
        page1 = api('GET', '/api/packages', expect=200,
                    params={'limit': '5', 'offset': '5'}).json()
        ids0 = {i['id'] for i in page0['items']}
        ids1 = {i['id'] for i in page1['items']}
        self.assertEqual(len(ids0), 5, 'page 0 must return exactly 5 items')
        self.assertEqual(len(ids1), 5, 'page 1 must return exactly 5 items')
        self.assertTrue(ids0.isdisjoint(ids1),
                        f'packages page 0 and page 1 share ids: {ids0 & ids1}')

    def test_packages_total_stable_across_pages(self):
        r0 = api('GET', '/api/packages', expect=200,
                 params={'limit': '5', 'offset': '0'}).json()
        r1 = api('GET', '/api/packages', expect=200,
                 params={'limit': '5', 'offset': '5'}).json()
        self.assertEqual(r0['total'], r1['total'],
                         f'total changed between pages: {r0["total"]} vs {r1["total"]}')

    def test_vulnerabilities_pages_disjoint(self):
        page0 = api('GET', '/api/vulnerabilities', expect=200,
                    params={'limit': '5', 'offset': '0'}).json()
        page1 = api('GET', '/api/vulnerabilities', expect=200,
                    params={'limit': '5', 'offset': '5'}).json()
        # Use composite key (vulnerability_id, host_id, pkg_name) as the stable identifier.
        def vuln_key(v):
            return (v['vulnerability_id'], v['host_id'], v['pkg_name'])
        keys0 = {vuln_key(v) for v in page0['items']}
        keys1 = {vuln_key(v) for v in page1['items']}
        self.assertEqual(len(keys0), 5, 'vulnerabilities page 0 must return exactly 5 items')
        self.assertEqual(len(keys1), 5, 'vulnerabilities page 1 must return exactly 5 items')
        self.assertTrue(keys0.isdisjoint(keys1),
                        f'vuln page 0 and page 1 share entries: {keys0 & keys1}')

    def test_vulnerabilities_total_stable_across_pages(self):
        r0 = api('GET', '/api/vulnerabilities', expect=200,
                 params={'limit': '5', 'offset': '0'}).json()
        r1 = api('GET', '/api/vulnerabilities', expect=200,
                 params={'limit': '5', 'offset': '5'}).json()
        self.assertEqual(r0['total'], r1['total'],
                         f'total changed between vuln pages: {r0["total"]} vs {r1["total"]}')


def main():
    if not API_KEY:
        print('BONGSU_E2E_API_KEY is required', file=sys.stderr)
        return 2
    try:
        api('GET', '/api/health', expect=200, timeout=10)
    except Exception as exc:
        print(f'server not reachable at {BASE}: {exc}', file=sys.stderr)
        return 2
    runner = unittest.main(module=__name__, exit=False, verbosity=2, argv=sys.argv)
    return 0 if runner.result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
