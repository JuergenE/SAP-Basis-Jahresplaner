/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  testPathIgnorePatterns: ['/node_modules/', '/tests/e2e/'],
  setupFilesAfterFramework: [],
  // For Playwright E2E tests, see playwright.config.js
  verbose: true,
};
