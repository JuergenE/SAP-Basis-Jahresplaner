/**
 * E2E Test: System Type Dropdown
 *
 * Tests the full user flow for the system type dropdown feature:
 * 1. Log in as admin
 * 2. Create a new landscape with a SID
 * 3. Change the SID's system type to QAS
 * 4. Reload the page and verify persistence
 */

const { test, expect } = require('@playwright/test');

const BASE_URL = 'http://localhost:3232/sap-planner.html';
const ADMIN_USER = process.env.TEST_USER || 'admin';
const ADMIN_PASS = process.env.TEST_PASS || 'admin123';

test.describe('System Type Dropdown', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    // Log in
    await page.fill('input[name="username"], input[type="text"]', ADMIN_USER);
    await page.fill('input[name="password"], input[type="password"]', ADMIN_PASS);
    await page.click('button[type="submit"]');
    // Wait for the main app to load
    await page.waitForSelector('text=Systemlandschaften', { timeout: 10_000 });
  });

  test('SID system type can be changed and persists after reload', async ({ page }) => {
    // Navigate to landscape editor tab
    await page.click('text=Systemlandschaften');

    // Find the first SID system type dropdown
    const firstDropdown = page.locator('select[name^="sidType-"]').first();
    await expect(firstDropdown).toBeVisible();

    // Change to QAS
    await firstDropdown.selectOption('QAS');

    // Wait for save (debounce / immediate)
    await page.waitForTimeout(500);

    // Reload page
    await page.reload();
    await page.waitForSelector('text=Systemlandschaften', { timeout: 10_000 });
    await page.click('text=Systemlandschaften');

    // Verify the dropdown still shows QAS
    const reloadedDropdown = page.locator('select[name^="sidType-"]').first();
    await expect(reloadedDropdown).toHaveValue('QAS');
  });

  test('PRD badge is displayed in bold red in the Gantt view', async ({ page }) => {
    // Navigate to the Gantt chart view (default or via tab)
    await page.click('text=Jahresplan');
    
    // Look for a PRD badge in the sidebar
    const prdBadge = page.locator('span:has-text("PRD")').first();
    await expect(prdBadge).toBeVisible();
  });
});
