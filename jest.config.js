/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  testPathIgnorePatterns: ['/node_modules/', '/tests/e2e/'],
  // Transform uuid (and other ESM-only packages) with Babel
  transformIgnorePatterns: [
    '/node_modules/(?!(uuid)/)',
  ],
  verbose: true,
};
