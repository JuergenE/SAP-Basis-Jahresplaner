/**
 * api.test.js
 *
 * Backend API Integration Tests
 * 
 * Tests Exercise the full Express request/response cycle using an in-memory
 * SQLite database so no real data is touched.
 * 
 * Run: NODE_ENV=test npx jest
 */

const request = require('supertest');
const { app, db } = require('../server');
const { createAuthAgent } = require('./test-helpers');

// ============================================================
// Helpers
// ============================================================

let agent;
let landscapeId;
let sidId;

beforeAll(async () => {
  ({ agent } = await createAuthAgent(app, db));
});

afterAll(() => {
  // Clean up the in-memory DB after all tests
  try { db.close(); } catch (_) {}
});

// ============================================================
// 1. AUTH TESTS
// ============================================================

describe('Authentication', () => {
  test('POST /api/auth/login with wrong credentials returns 401', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'nobody', password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('error');
  });

  test('POST /api/auth/login with correct credentials returns 200 + user info', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'testadmin', password: 'test1234' });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ username: 'testadmin', role: 'admin' });
  });

  test('GET /api/landscapes without session returns 401', async () => {
    const res = await request(app).get('/api/landscapes');
    expect(res.status).toBe(401);
  });
});

// ============================================================
// 2. LANDSCAPE TESTS
// ============================================================

describe('Landscapes', () => {
  test('POST /api/landscapes creates a new landscape', async () => {
    const res = await agent
      .post('/api/landscapes')
      .send({ name: 'Test Landschaft' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id');
    expect(res.body.name).toBe('Test Landschaft');
    landscapeId = res.body.id;
  });

  test('GET /api/landscapes returns the created landscape', async () => {
    const res = await agent.get('/api/landscapes');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const found = res.body.find(l => l.id === landscapeId);
    expect(found).toBeDefined();
    expect(found.name).toBe('Test Landschaft');
  });

  test('PUT /api/landscapes/:id updates landscape name', async () => {
    const res = await agent
      .put(`/api/landscapes/${landscapeId}`)
      .send({ name: 'Umbenannte Landschaft' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const getRes = await agent.get('/api/landscapes');
    const found = getRes.body.find(l => l.id === landscapeId);
    expect(found.name).toBe('Umbenannte Landschaft');
  });
});

// ============================================================
// 3. SID TESTS
// ============================================================

describe('SIDs', () => {
  test('POST /api/sids creates a SID with empty name and default DEV type', async () => {
    const res = await agent
      .post('/api/sids')
      .send({ landscape_id: landscapeId, name: '' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id');
    expect(res.body.systemType).toBe('DEV');
    expect(res.body.isPRD).toBe(false);
    sidId = res.body.id;
  });

  test('POST /api/sids creates a SID with PRD type', async () => {
    const res = await agent
      .post('/api/sids')
      .send({ landscape_id: landscapeId, name: 'DB3', systemType: 'PRD' });
    expect(res.status).toBe(200);
    expect(res.body.systemType).toBe('PRD');
    expect(res.body.isPRD).toBe(true);
  });

  test('POST /api/sids creates a SID with QAS type', async () => {
    const res = await agent
      .post('/api/sids')
      .send({ landscape_id: landscapeId, name: 'DBQ', systemType: 'QAS' });
    expect(res.status).toBe(200);
    expect(res.body.systemType).toBe('QAS');
    expect(res.body.isPRD).toBe(false);
  });

  test('POST /api/sids without landscape_id returns 400', async () => {
    const res = await agent
      .post('/api/sids')
      .send({ name: 'FAIL' });
    expect(res.status).toBe(400);
  });
});

// ============================================================
// 4. SYSTEM TYPE PERSISTENCE TESTS (the main regression we fixed)
// ============================================================

describe('System Type Persistence', () => {
  let prdSidId;

  test('SID with TST type is persisted and returned correctly on GET /api/landscapes', async () => {
    // Create SID with TST type
    const createRes = await agent
      .post('/api/sids')
      .send({ landscape_id: landscapeId, name: 'RXT', systemType: 'TST' });
    expect(createRes.status).toBe(200);
    prdSidId = createRes.body.id;

    // Fetch landscapes and verify the type is returned
    const getRes = await agent.get('/api/landscapes');
    const landscape = getRes.body.find(l => l.id === landscapeId);
    const sid = landscape.sids.find(s => s.id === prdSidId);
    expect(sid).toBeDefined();
    expect(sid.systemType).toBe('TST');
    expect(sid.isPRD).toBe(false);
  });

  test('PUT /api/sids/:id can update system type from DEV to PPRD', async () => {
    const updateRes = await agent
      .put(`/api/sids/${sidId}`)
      .send({ systemType: 'PPRD' });
    expect(updateRes.status).toBe(200);

    // Verify persistence via GET
    const getRes = await agent.get('/api/landscapes');
    const landscape = getRes.body.find(l => l.id === landscapeId);
    const sid = landscape.sids.find(s => s.id === sidId);
    expect(sid.systemType).toBe('PPRD');
    expect(sid.isPRD).toBe(false);
  });

  test('PUT /api/sids/:id can update system type from PPRD to PRD', async () => {
    const updateRes = await agent
      .put(`/api/sids/${sidId}`)
      .send({ systemType: 'PRD' });
    expect(updateRes.status).toBe(200);

    // Verify persistence via GET
    const getRes = await agent.get('/api/landscapes');
    const landscape = getRes.body.find(l => l.id === landscapeId);
    const sid = landscape.sids.find(s => s.id === sidId);
    expect(sid.systemType).toBe('PRD');
    expect(sid.isPRD).toBe(true);
  });

  test('PUT /api/sids/:id with empty body returns 400', async () => {
    const res = await agent
      .put(`/api/sids/${sidId}`)
      .send({});
    expect(res.status).toBe(400);
  });
});

// ============================================================
// 5. ACTIVITY TYPE TESTS
// ============================================================

describe('Activity Types', () => {
  test('GET /api/activity-types returns an array', async () => {
    const res = await agent.get('/api/activity-types');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ============================================================
// 6. SETTINGS TESTS
// ============================================================

describe('Settings', () => {
  test('GET /api/settings returns the settings object', async () => {
    const res = await agent.get('/api/settings');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('bundesland');
  });
});

// ============================================================
// 7. LANDSCAPE DELETION
// ============================================================

describe('Cleanup / Delete', () => {
  test('DELETE /api/landscapes/:id removes the landscape', async () => {
    const res = await agent.delete(`/api/landscapes/${landscapeId}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const getRes = await agent.get('/api/landscapes');
    const found = getRes.body.find(l => l.id === landscapeId);
    expect(found).toBeUndefined();
  });
});
