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
