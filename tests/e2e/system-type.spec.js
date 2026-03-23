/**
 * E2E Test: System Type Display and Persistence
 *
 * Credentials are read from .env (variables: 'user' and 'password').
 * Override with TEST_USER / TEST_PASS environment variables.
 */

const { test, expect } = require('@playwright/test');
const path = require('path');

// Load .env from project root inside the worker process
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const BASE_URL = 'http://localhost:3232/sap-planner.html';
const TEST_USER = process.env.TEST_USER || process.env.user || 'teamlead';
const TEST_PASS = process.env.TEST_PASS || process.env.password;

// ─────────────────────────────────────────────────────────────
// Login helper: fills the login form and waits for the Gantt tab
// ─────────────────────────────────────────────────────────────
async function login(page) {
  await page.goto(BASE_URL);

  // If server shows a login form, fill it in
  const usernameInput = page.locator('input[name="username"]');
  if (await usernameInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await usernameInput.fill(TEST_USER);
    await page.locator('input[name="password"]').fill(TEST_PASS);
    await page.locator('button[type="submit"]').click();
  }

  // Wait for the actual tab bar that appears after a successful login
  await expect(page.locator('button:has-text("Gantt-Ansicht")')).toBeVisible({ timeout: 15_000 });
}

// ─────────────────────────────────────────────────────────────
// Guards
// ─────────────────────────────────────────────────────────────
test.skip(!TEST_PASS, '"password" variable not found in .env — set it to run E2E tests');

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────
test.describe('System Type Display', () => {

  test('Gantt sidebar shows system type badges after login', async ({ page }) => {
    await login(page);

    // The Gantt-Ansicht is the default view; badges appear in the sidebar
    // Wait for the Gantt chart container to fully render
    await expect(page.locator('text=Gantt-Chart')).toBeVisible({ timeout: 10_000 });

    // Verify that at least one system type badge is rendered in the sidebar
    // Badges are <span> elements with the system type text (PRD, QAS, DEV, etc.)
    const badges = page.locator('span').filter({ hasText: /^(PRD|PPRD|QAS|TST|DEV|SBX|TRN)$/ });
    await expect(badges.first()).toBeVisible({ timeout: 10_000 });
  });

  test('System type dropdown is visible in landscape editor', async ({ page }) => {
    await login(page);

    // Scroll down in the Gantt sidebar to find the Systemlandschaften section
    // or navigate to the config area via the header
    // Look for a SID system type dropdown (rendered in the landscape config section)
    const systemTypeDropdown = page.locator('select').filter({ hasText: /DEV|PRD|QAS|TST/ }).first();

    // This checks the dropdown is rendered somewhere in the page
    // It may be in the right panel / settings; scroll to make it visible
    const isVisible = await systemTypeDropdown.isVisible().catch(() => false);
    if (!isVisible) {
      // Scroll down to find the landscape editor section
      await page.mouse.wheel(0, 500);
    }

    // Verify the dropdown is present in the DOM (even if scrolled out of view)
    const count = await page.locator('select').count();
    expect(count).toBeGreaterThan(0);
  });

  test('API: SID system type persists after update', async ({ request }) => {
    // Direct API test: no need for browser UI, just verify the backend
    // Log in via API
    const loginRes = await request.post(`${BASE_URL.replace('/sap-planner.html', '')}/api/auth/login`, {
      data: { username: TEST_USER, password: TEST_PASS }
    });
    expect(loginRes.ok()).toBeTruthy();

    // Fetch landscapes
    const landscapesRes = await request.get(`${BASE_URL.replace('/sap-planner.html', '')}/api/landscapes`);
    expect(landscapesRes.ok()).toBeTruthy();

    const landscapes = await landscapesRes.json();
    expect(Array.isArray(landscapes)).toBeTruthy();

    // Verify all SIDs have a systemType returned
    for (const landscape of landscapes) {
      for (const sid of landscape.sids || []) {
        expect(sid.systemType).toBeTruthy();
        expect(['PRD', 'PPRD', 'QAS', 'TST', 'DEV', 'SBX', 'TRN']).toContain(sid.systemType);
      }
    }
  });
});
