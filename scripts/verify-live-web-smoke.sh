#!/bin/bash
set -euo pipefail

# verify-live-web-smoke.sh - Exercise a running Bongsu web UI with Playwright.
# The script does not start a dev server; it targets the deployed web URL.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WEB_URL="${BONGSU_WEB_BASE:-http://127.0.0.1:5678}"
API_KEY="${BONGSU_API_KEY:-}"
ADMIN_USERNAME="${BONGSU_ADMIN_USERNAME:-}"
ADMIN_PASSWORD="${BONGSU_ADMIN_PASSWORD:-}"
CVE_QUERY="${BONGSU_VERIFY_WEB_CVE_QUERY:-CVE}"
TMP_DIR="$(mktemp -d "$ROOT/web/.live-smoke.XXXXXX")"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool curl
require_tool npm

if [ -z "$API_KEY" ] && { [ -z "$ADMIN_USERNAME" ] || [ -z "$ADMIN_PASSWORD" ]; }; then
    echo "ERROR: set BONGSU_API_KEY or BONGSU_ADMIN_USERNAME/BONGSU_ADMIN_PASSWORD for live web verification" >&2
    exit 1
fi

echo "=== Bongsu Live Web Smoke Verification ==="
echo "Web: ${WEB_URL}"

curl -fsS --max-time 20 "$WEB_URL/" >/dev/null

cat > "$TMP_DIR/live-web-smoke.spec.ts" << 'EOF'
import { expect, test } from '@playwright/test';

const webURL = process.env.BONGSU_WEB_BASE || 'http://127.0.0.1:5678';
const apiKey = process.env.BONGSU_API_KEY || '';
const adminUsername = process.env.BONGSU_ADMIN_USERNAME || '';
const adminPassword = process.env.BONGSU_ADMIN_PASSWORD || '';
const cveQuery = process.env.BONGSU_VERIFY_WEB_CVE_QUERY || 'CVE';

async function authenticate(page) {
  await page.goto(webURL, { waitUntil: 'domcontentloaded' });
  const loginCard = page.locator('.login-card');
  if (!(await loginCard.isVisible({ timeout: 3000 }).catch(() => false))) return;

  if (apiKey) {
    await page.getByRole('button', { name: 'Use API Key' }).click();
    await page.getByPlaceholder('API Key').fill(apiKey);
    await page.getByRole('button', { name: 'Connect with API Key' }).click();
  } else {
    await page.getByPlaceholder('Username').fill(adminUsername);
    await page.getByPlaceholder('Password').fill(adminPassword);
    await page.getByRole('button', { name: 'Sign In' }).click();
  }
  await expect(page.getByRole('link', { name: /Dashboard/ })).toBeVisible({ timeout: 15000 });
}

test('live dashboard and operator routes render without API 5xx responses', async ({ page }) => {
  const failedResponses: string[] = [];
  page.on('response', response => {
    const url = response.url();
    if (!url.includes('/api/')) return;
    if (response.status() >= 500) failedResponses.push(`${response.status()} ${url}`);
  });
  page.on('pageerror', err => {
    throw err;
  });

  async function openRoute(linkName: string | RegExp, headingName: string | RegExp, visibleText: string | RegExp) {
    await page.getByRole('link', { name: linkName }).click();
    await expect(page.getByRole('heading', { name: headingName, exact: typeof headingName === 'string' })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(visibleText).first()).toBeVisible({ timeout: 15000 });
    await page.waitForTimeout(500);
  }

  await authenticate(page);
  await expect(page.getByRole('link', { name: /CVE Search/ })).toBeVisible();
  await expect(page.getByText(/CVE DB/i).first()).toBeVisible({ timeout: 15000 });
  await expect(page.getByText(/Total Hosts|Active Findings|SBOM/i).first()).toBeVisible({ timeout: 15000 });

  await page.getByRole('link', { name: /CVE Search/ }).click();
  await expect(page.getByRole('heading', { name: 'CVE Search' })).toBeVisible();
  const cveSearch = page.waitForResponse(response => response.url().includes('/api/cve-db/search') && response.status() < 500);
  await page.getByPlaceholder('CVE, package, ecosystem, keyword...').fill(cveQuery);
  await page.getByRole('button', { name: 'Search' }).click();
  await cveSearch;
  await expect(page.getByText(/Results|CVE-|No CVEs found/i).first()).toBeVisible({ timeout: 15000 });

  const hostsResponse = page.waitForResponse(response => response.url().includes('/api/hosts') && response.status() < 500);
  await page.getByRole('link', { name: 'Hosts' }).click();
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible();
  await hostsResponse;
  await expect(page.getByText(/Force Scan All|No hosts found|Hostname/i).first()).toBeVisible({ timeout: 15000 });

  const vulnResponse = page.waitForResponse(response => response.url().includes('/api/vulnerabilities') && response.status() < 500);
  await page.getByRole('link', { name: 'Vulnerabilities' }).click();
  await expect(page.getByRole('heading', { name: 'Vulnerabilities' })).toBeVisible();
  await vulnResponse;
  await expect(page.getByText(/Export CSV|No vulnerabilities found|Severity/i).first()).toBeVisible({ timeout: 15000 });

  const rbacResponse = page.waitForResponse(response => response.url().includes('/api/admin/rbac/subjects') && response.status() < 500);
  await page.getByRole('link', { name: 'RBAC' }).click();
  await expect(page.getByRole('heading', { name: 'RBAC' })).toBeVisible();
  await rbacResponse;
  await expect(page.getByText(/Access Subjects|Save Subject|RBAC management requires/i).first()).toBeVisible({ timeout: 15000 });

  await openRoute('Packages', 'Packages', /Package|No packages found|Scanned/i);
  await openRoute('Containers', 'Containers', /Container|No containers found|Image/i);
  await openRoute('Scan History', 'Scan History', /Scan Requests|No scans found|Created/i);
  await openRoute('Audit Log', 'Audit Log', /Audit|No audit logs|Action/i);
  await openRoute('Schedules', 'Schedules', /Create Schedule|No schedules|Cron/i);
  await openRoute('Asset Groups', 'Asset Groups', /Create Asset Group|No asset groups|Rule/i);
  await openRoute('Trends', 'Vulnerability Trends', /Daily Vulnerability Counts|No trend data|Current Total/i);
  await openRoute('Reports', 'Reports', /Severity Counts|Risk Breakdown|Active Vulnerabilities/i);
  await openRoute('Notifications', 'Notifications', /Create Notification Rule|No notification rules|Trigger Event/i);

  expect(failedResponses, failedResponses.join('\n')).toEqual([]);
});
EOF

cat > "$TMP_DIR/playwright.config.ts" << 'EOF'
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 120_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: process.env.BONGSU_WEB_BASE || 'http://127.0.0.1:5678',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
EOF

(
    cd "$TMP_DIR"
    NODE_PATH="$ROOT/web/node_modules" npm --prefix "$ROOT/web" exec playwright test -- --config "$TMP_DIR/playwright.config.ts"
)

echo "Live web smoke verification passed"
