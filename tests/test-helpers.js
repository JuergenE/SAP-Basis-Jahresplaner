/**
 * test-helpers.js
 * 
 * Shared helper for backend tests: sets up an in-memory SQLite test database
 * and provides an authenticated supertest agent for admin actions.
 */

const request = require('supertest');
const bcrypt = require('bcryptjs');

/**
 * Creates and returns an authenticated supertest agent for the given app.
 * The agent uses a cookie jar so HttpOnly session cookies are preserved.
 *
 * @param {import('express').Express} app - The Express app instance
 * @param {import('better-sqlite3').Database} db - The database instance
 * @returns {Promise<{ agent: import('supertest').SuperAgentTest, userId: number }>}
 */
async function createAuthAgent(app, db) {
  // Create a test admin user
  const hash = await bcrypt.hash('test1234', 10);
  const result = db.prepare(
    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')"
  ).run('testadmin', hash);
  const userId = result.lastInsertRowid;

  // Log in and obtain a session cookie
  const agent = request.agent(app);
  const res = await agent
    .post('/api/auth/login')
    .send({ username: 'testadmin', password: 'test1234' });

  if (res.status !== 200) {
    throw new Error('Test setup login failed: ' + JSON.stringify(res.body));
  }

  return { agent, userId };
}

module.exports = { createAuthAgent };
