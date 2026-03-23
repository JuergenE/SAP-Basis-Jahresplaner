import { defineConfig, devices } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

// Load .env file from project root if it exists
const envPath = path.resolve('.env');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
}


/**
 * Playwright E2E Configuration
 * 
 * Runs a real browser against the live dev server.
 * Before running, start the server: npm run dev
 * Then run: npx playwright test
 * 
 * Or run directly with: npm run test:e2e
 */
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['html', { open: 'never' }], ['list']],

  use: {
    baseURL: 'http://localhost:3232',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Automatically start and stop the dev server for E2E tests
  webServer: {
    command: 'node server.js',
    url: 'http://localhost:3232/api/health',
    reuseExistingServer: !process.env.CI,
    timeout: 15_000,
    env: {
      PORT: '3232',
      NODE_ENV: 'development',
      // Pass through any DB_PATH from .env
      ...(process.env.DB_PATH ? { DB_PATH: process.env.DB_PATH } : {}),
    }
  },
});
