import { test, expect } from '@playwright/test';

const ROUTES_TO_TEST = [
  { path: '/', expectedText: 'Deterministic Tree-sitter' },
  { path: '/dashboard', expectedText: 'Security Dashboard' },
  { path: '/findings', expectedText: 'Security Findings Workbench' },
  { path: '/scan/new', expectedText: 'Configure Security Analysis Run' },
  { path: '/scan/SCN-2026-0941', expectedText: 'LIVE ORCHESTRATOR COCKPIT' },
  { path: '/reports', expectedText: 'Audit Reports' },
  { path: '/settings', expectedText: 'Preferences' },
  { path: '/traffic', expectedText: 'Traffic' },
];

test.describe('E2E Production Route Performance and Error Integrity', () => {
  for (const route of ROUTES_TO_TEST) {
    test(`renders ${route.path} under 3s with zero console errors`, async ({ page }) => {
      const consoleErrors: string[] = [];
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });
      page.on('pageerror', (err) => {
        consoleErrors.push(err.message);
      });

      const startTime = Date.now();
      await page.goto(route.path, { waitUntil: 'domcontentloaded' });
      await expect(page.locator('body')).toContainText(route.expectedText, { timeout: 4000 });
      const durationMs = Date.now() - startTime;

      console.log(`Route ${route.path} loaded in ${durationMs}ms`);

      expect(durationMs).toBeLessThan(3000);
      expect(consoleErrors).toHaveLength(0);
    });
  }

  test('navigates between dashboard routes without route transition overlay', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('body')).toContainText('Security Dashboard');

    // Click link to Findings
    await page.click('a[href="/findings"]');
    await expect(page.locator('body')).toContainText('Security Findings Workbench');

    // Assert that the marketing route overlay is not present or visible in (app) routes
    const routeOverlay = page.locator('div[style*="clip-path"][aria-hidden="true"]');
    const count = await routeOverlay.count();
    if (count > 0) {
      await expect(routeOverlay.first()).not.toBeVisible();
    }

    // Click link to New Scan
    await page.click('a[href="/scan/new"]');
    await expect(page.locator('body')).toContainText('Configure Security Analysis Run');
  });
});
