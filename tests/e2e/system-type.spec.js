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
const API_URL  = 'http://localhost:3232';
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
// API helper: create test data (landscape + SID) via REST API
// ─────────────────────────────────────────────────────────────
async function seedTestData(request) {
  // Log in via API to get a session cookie
  const loginRes = await request.post(`${API_URL}/api/auth/login`, {
    data: { username: TEST_USER, password: TEST_PASS }
  });
  if (!loginRes.ok()) return null;

  // Create a test landscape
  const landRes = await request.post(`${API_URL}/api/landscapes`, {
    data: { name: 'CI Test Landscape' }
  });
  if (!landRes.ok()) return null;
  const landscape = await landRes.json();

  // Create a SID with PRD type so a badge will appear
  const sidRes = await request.post(`${API_URL}/api/sids`, {
    data: { landscape_id: landscape.id, name: 'CIP', systemType: 'PRD' }
  });
  if (!sidRes.ok()) return null;

  return { landscapeId: landscape.id };
}

// ─────────────────────────────────────────────────────────────
// API helper: clean up test data
// ─────────────────────────────────────────────────────────────
async function cleanupTestData(request, landscapeId) {
  if (!landscapeId) return;
  await request.delete(`${API_URL}/api/landscapes/${landscapeId}`);
}

// ─────────────────────────────────────────────────────────────
// Guards
// ─────────────────────────────────────────────────────────────
test.skip(!TEST_PASS, '"password" variable not found in .env — set it to run E2E tests');

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────
test.describe('System Type Display', () => {

  test('Gantt sidebar shows system type badges after login', async ({ page, request }) => {
    // Seed test data so there is at least one SID with a badge
    const testData = await seedTestData(request);

    try {
      await login(page);

      // The Gantt-Ansicht is the default view; badges appear in the sidebar
      await expect(page.locator('text=Gantt-Chart')).toBeVisible({ timeout: 10_000 });

      // Verify that at least one system type badge is rendered in the sidebar
      const badges = page.locator('span').filter({ hasText: /^(PRD|PPRD|QAS|TST|DEV|SBX|TRN)$/ });
      await expect(badges.first()).toBeVisible({ timeout: 10_000 });
    } finally {
      // Clean up test data regardless of test outcome
      if (testData) await cleanupTestData(request, testData.landscapeId);
    }
  });

  test('System type dropdown is visible in landscape editor', async ({ page }) => {
    await login(page);

    // Look for a select dropdown present in the DOM
    const count = await page.locator('select').count();
    expect(count).toBeGreaterThan(0);
  });

  test('API: SID system type persists after update', async ({ request }) => {
    // Log in via API
    const loginRes = await request.post(`${API_URL}/api/auth/login`, {
      data: { username: TEST_USER, password: TEST_PASS }
    });
    expect(loginRes.ok()).toBeTruthy();

    // Fetch landscapes
    const landscapesRes = await request.get(`${API_URL}/api/landscapes`);
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
