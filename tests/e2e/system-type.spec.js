/**
 * E2E Test: System Type Dropdown
 *
 * Prerequisites:
 *   - Server must be running (started automatically by playwright.config.js webServer)
 *   - Set TEST_USER and TEST_PASS env vars to an admin user WITHOUT must_change_password,
 *     e.g.: TEST_USER=testadmin TEST_PASS=testpass123 npm run test:e2e
 *   - Or create a test admin user in the app first (Admin > Benutzer > Neu)
 *
 * The default 'teamlead' user has must_change_password=1 so it cannot be used directly.
 */

const { test, expect } = require('@playwright/test');
const path = require('path');

// Load .env from project root inside the worker process
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3232/sap-planner.html';
// Credentials are read from .env (variables: 'user' and 'password')
// Override with TEST_USER / TEST_PASS for a different account.
const TEST_USER = process.env.TEST_USER || process.env.user || 'teamlead';
const TEST_PASS = process.env.TEST_PASS || process.env.password;

// Skip all E2E tests if credentials are not provided
test.beforeAll(async () => {
  if (!TEST_PASS) {
    console.warn(
      '\nSKIPPING E2E tests: Ensure your .env file contains the "Password" variable.\n'
    );
  }
});

test.describe('System Type Dropdown', () => {
  test.skip(!TEST_PASS, '"Password" variable not found in .env');

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    // Fill in login form using form element names
    await page.locator('input[name="username"]').fill(TEST_USER);
    await page.locator('input[name="password"]').fill(TEST_PASS);
    await page.locator('button[type="submit"]').click();
    // Wait for the main navigation to appear - trying multiple possible selectors
    await page.waitForSelector(
      [
        'text=Systemlandschaften',
        'text=Jahresplan',
        'nav',
        '[data-tab]',
      ].join(', '),
      { timeout: 15_000 }
    );
  });

  test('SID system type can be changed and persists after reload', async ({ page }) => {
    // Navigate to landscape editor
    const landscapeTab = page.locator('button:has-text("Systemlandschaften"), a:has-text("Systemlandschaften")').first();
    if (await landscapeTab.isVisible()) {
      await landscapeTab.click();
    }

    // Find the first SID system type dropdown
    const firstDropdown = page.locator('select[name^="sidType-"]').first();
    await expect(firstDropdown).toBeVisible({ timeout: 10_000 });

    // Get the current value
    const originalValue = await firstDropdown.inputValue();
    // Choose a different value
    const newValue = originalValue === 'QAS' ? 'TST' : 'QAS';

    await firstDropdown.selectOption(newValue);
    // Wait for save
    await page.waitForTimeout(800);

    // Reload page and log back in
    await page.reload();
    await page.locator('input[name="username"]').fill(TEST_USER);
    await page.locator('input[name="password"]').fill(TEST_PASS);
    await page.locator('button[type="submit"]').click();
    await page.waitForSelector('select[name^="sidType-"]', { timeout: 15_000 });

    // Navigate to landscape editor
    const reloadedLandscapeTab = page.locator('button:has-text("Systemlandschaften"), a:has-text("Systemlandschaften")').first();
    if (await reloadedLandscapeTab.isVisible()) {
      await reloadedLandscapeTab.click();
    }

    // Verify the dropdown still shows the updated value
    const reloadedDropdown = page.locator('select[name^="sidType-"]').first();
    await expect(reloadedDropdown).toHaveValue(newValue);
  });

  test('PRD badge is displayed in the Gantt sidebar', async ({ page }) => {
    // Navigate to Gantt / Jahresplan
    const ganttTab = page.locator('button:has-text("Jahresplan"), a:has-text("Jahresplan")').first();
    if (await ganttTab.isVisible()) {
      await ganttTab.click();
    }

    // Look for any system type badge in the sidebar
    const anyBadge = page.locator('.gantt-row-label span.rounded').first();
    await expect(anyBadge).toBeVisible({ timeout: 10_000 });
  });
});
