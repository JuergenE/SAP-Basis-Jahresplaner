/*
 * Copyright 2026 Optima Solutions GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * SAP Basis Jahresplaner - Backend Server
 * 
 * Express.js Server mit SQLite-Datenbank und Multi-User-Support
 * Port: 3232
 */

const express = require('express');
const https = require('https');

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3232;
const HOST = process.env.HOST || '0.0.0.0';

// Online Users Memory Store
// Maps user_id -> { id, username, abbreviation, lastSeen }
const activeUsers = new Map();

// Read version from package.json
let APP_VERSION = '0.1.5';
try {
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  APP_VERSION = packageJson.version || '1.0.0';
} catch (e) {
  console.warn('Could not read version from package.json, using default:', APP_VERSION);
}

// Directory Configuration
const defaultDataDir = process.env.NODE_ENV === 'production' ? '/app/data' : __dirname;

// Middleware
const LOG_FILE = path.join(defaultDataDir, 'server.log');
const MAX_LOG_SIZE = 1024 * 1024; // 1MB

app.use(cookieParser());

// Security Headers via Helmet
// HSTS disabled: app is accessed via IP/HTTP in Portainer environments
// CSP disabled: inline scripts (React/Babel) and CDN resources require permissive policy
app.use(helmet({
  hsts: false,
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // 30 login attempts per 15 min
  message: { error: 'Zu viele Anmeldeversuche. Bitte versuchen Sie es in 15 Minuten erneut.' }
});
app.use('/api/auth/login', loginLimiter);

// CORS Configuration
// Set CORS_ORIGIN env var to restrict origins (comma-separated), e.g. "http://192.168.1.100:3232,https://planner.firma.local"
const corsOrigin = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : true; // Default: allow all origins (for backward compatibility)
app.use(cors({
  origin: corsOrigin,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Serve only specific frontend files (not server.js, package.json, etc.)
const allowedStaticFiles = ['sap-planner.html', 'screenshot.png'];
app.get('/:filename', (req, res, next) => {
  if (allowedStaticFiles.includes(req.params.filename)) {
    return res.sendFile(path.join(__dirname, req.params.filename));
  }
  next();
});

// =========================================================================
// DATABASE SETUP
// =========================================================================

// Use DB_PATH env var if set, otherwise default to local or /app/data based on NODE_ENV
const dbPath = process.env.DB_PATH || path.join(defaultDataDir, 'sap-planner.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrent access
db.pragma('journal_mode = WAL');

// Initialize database schema
const initDatabase = () => {
  db.exec(`
    -- Users & Authentication
    -- Note: Migration to add 'teamlead' role is handled in initDatabase code below
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('admin', 'user', 'teamlead')) NOT NULL DEFAULT 'user',
      must_change_password BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL
    );

    -- Application Settings
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      value TEXT
    );

    -- Activity Types
    CREATE TABLE IF NOT EXISTS activity_types (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      color TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    -- Landscapes
    CREATE TABLE IF NOT EXISTS landscapes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    -- Team Members
    CREATE TABLE IF NOT EXISTS team_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      abbreviation TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    -- SIDs
    CREATE TABLE IF NOT EXISTS sids (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      landscape_id INTEGER REFERENCES landscapes(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      is_prd BOOLEAN DEFAULT FALSE,
      visible_in_gantt BOOLEAN DEFAULT TRUE,
      notes TEXT DEFAULT '',
      sort_order INTEGER DEFAULT 0
    );

    -- Activities
    CREATE TABLE IF NOT EXISTS activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sid_id INTEGER REFERENCES sids(id) ON DELETE CASCADE,
      type_id TEXT REFERENCES activity_types(id),
      start_date TEXT NOT NULL,
      duration INTEGER DEFAULT 1,
      includes_weekend BOOLEAN DEFAULT FALSE
    );

    -- Maintenance Sundays (Wartungssonntage)
    CREATE TABLE IF NOT EXISTS maintenance_sundays (
      id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 4),
      date TEXT,
      label TEXT DEFAULT ''
    );

    -- Sub-Activities (for Update/Upgrade activities)
    CREATE TABLE IF NOT EXISTS sub_activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      activity_id INTEGER REFERENCES activities(id) ON DELETE CASCADE,
      name TEXT NOT NULL DEFAULT 'Sub-Aktivität',
      start_date TEXT NOT NULL,
      duration INTEGER DEFAULT 1,
      includes_weekend BOOLEAN DEFAULT FALSE,
      sort_order INTEGER DEFAULT 0
    );

    -- Application Logs
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      level TEXT CHECK(level IN ('INFO', 'WARN', 'ERROR')) DEFAULT 'INFO',
      user_id INTEGER REFERENCES users(id),
      username TEXT,
      action TEXT NOT NULL,
      details TEXT
    );

    -- Create indexes for performance
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_sids_landscape ON sids(landscape_id);
    CREATE INDEX IF NOT EXISTS idx_activities_sid ON activities(sid_id);
    CREATE INDEX IF NOT EXISTS idx_subactivities_activity ON sub_activities(activity_id);
    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);

    -- Landscape Locks (Multi-User concurrency)
    CREATE TABLE IF NOT EXISTS landscape_locks (
      landscape_id INTEGER PRIMARY KEY REFERENCES landscapes(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id),
      username TEXT,
      expires_at DATETIME NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_landscape_locks_expires ON landscape_locks(expires_at);

    -- Matrix Columns (Qualifikationen)
    CREATE TABLE IF NOT EXISTS matrix_columns (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    -- Matrix Values (Qualifikationen)
    CREATE TABLE IF NOT EXISTS matrix_values (
      team_member_id INTEGER REFERENCES team_members(id) ON DELETE CASCADE,
      column_id TEXT REFERENCES matrix_columns(id) ON DELETE CASCADE,
      level INTEGER DEFAULT 0,
      PRIMARY KEY (team_member_id, column_id)
    );

    -- Trainings (Schulungen)
    CREATE TABLE IF NOT EXISTS trainings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      participants TEXT DEFAULT '',
      course TEXT DEFAULT '',
      topic TEXT DEFAULT '',
      cost TEXT DEFAULT '',
      location TEXT DEFAULT '',
      date1 TEXT DEFAULT '',
      date2 TEXT DEFAULT '',
      date3 TEXT DEFAULT '',
      days INTEGER DEFAULT 0,
      is_booked BOOLEAN DEFAULT 0
    );
  `);

  // Migration: Update users table to allow 'teamlead' role
  try {
    const tableDef = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (tableDef && !tableDef.sql.includes('teamlead')) {
      console.log('Migrating users table to include teamlead role...');
      // Disable foreign keys to allow dropping referenced table
      db.pragma('foreign_keys = OFF');

      db.transaction(() => {
        db.exec("ALTER TABLE users RENAME TO users_old");
        db.exec(`
          CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'user', 'teamlead')) NOT NULL DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          )
        `);
        // Copy data back
        db.exec("INSERT INTO users (id, username, password_hash, role, created_at) SELECT id, username, password_hash, role, created_at FROM users_old");
        db.exec("DROP TABLE users_old");
      })();

      // Re-enable foreign keys
      db.pragma('foreign_keys = ON');
      console.log('✓ Users table migrated');
    }
  } catch (e) {
    console.error('Migration failed:', e);
    // Ensure FKs are back on even if failed
    try { db.pragma('foreign_keys = ON'); } catch (err) { }
  }

  // Create default teamlead user if not exists (FIRST user on fresh install)
  try {
    const teamleadExists = db.prepare('SELECT id FROM users WHERE username = ?').get('teamlead');
    if (!teamleadExists) {
      const passwordHash = bcrypt.hashSync('teamlead', 10);
      db.prepare('INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)').run('teamlead', passwordHash, 'teamlead');
      console.log('✓ Default teamlead user created (change password after first login!)');
    }
  } catch (e) {
    console.error('⚠ Could not create default teamlead user:', e.message);
  }

  // Create default settings if not exists
  const yearSetting = db.prepare('SELECT id FROM settings WHERE key = ?').get('year');
  if (!yearSetting) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('year', '2026');
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('bundesland', 'BW');
    console.log('✓ Default settings created');
  }

  // Create default activity types if not exists
  const typesExist = db.prepare('SELECT COUNT(*) as count FROM activity_types').get();
  if (typesExist.count === 0) {
    const defaultTypes = [
      { id: 'installation', label: 'Installation', color: '#3b82f6' },
      { id: 'update', label: 'Update/Upgrade', color: '#8b5cf6' },
      { id: 'kernel', label: 'Kernel Update', color: '#06b6d4' },
      { id: 'db', label: 'DB Update', color: '#10b981' },
      { id: 'os', label: 'OS Patches', color: '#f59e0b' },
      { id: 'stpi', label: 'ST-PI Patches', color: '#ef4444' },
      { id: 'security', label: 'Security Patches', color: '#ec4899' },
      { id: 'other', label: 'Sonstige', color: '#6b7280' }
    ];
    const insertType = db.prepare('INSERT INTO activity_types (id, label, color, sort_order) VALUES (?, ?, ?, ?)');
    defaultTypes.forEach((type, index) => {
      insertType.run(type.id, type.label, type.color, index);
    });
    console.log('✓ Default activity types created');
  }

  // Create default maintenance sundays if not exists
  const maintenanceExists = db.prepare('SELECT COUNT(*) as count FROM maintenance_sundays').get();
  if (maintenanceExists.count === 0) {
    const insertMaint = db.prepare('INSERT INTO maintenance_sundays (id, date, label) VALUES (?, ?, ?)');
    insertMaint.run(1, '', 'Wartungssonntag I');
    insertMaint.run(2, '', 'Wartungssonntag II');
    insertMaint.run(3, '', 'Wartungssonntag III');
    insertMaint.run(4, '', 'Wartungssonntag IV');
    console.log('✓ Default maintenance sundays created');
  }

  // Migration: Add notes column to sids table if not exists
  try {
    db.exec(`ALTER TABLE sids ADD COLUMN notes TEXT DEFAULT ''`);
    console.log('✓ Added notes column to sids table');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add visible_in_gantt column to sids table if not exists
  try {
    db.exec(`ALTER TABLE sids ADD COLUMN visible_in_gantt BOOLEAN DEFAULT 1`);
    console.log('✓ Added visible_in_gantt column to sids table');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add sort_order column to landscapes table if not exists
  try {
    db.exec(`ALTER TABLE landscapes ADD COLUMN sort_order INTEGER DEFAULT 0`);
    console.log('✓ Added sort_order column to landscapes table');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add team_member_id column to activities table if not exists
  try {
    db.exec(`ALTER TABLE activities ADD COLUMN team_member_id INTEGER REFERENCES team_members(id)`);
    console.log('✓ Added team_member_id column to activities table');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add team_member_id column to sub_activities table if not exists
  try {
    db.exec(`ALTER TABLE sub_activities ADD COLUMN team_member_id INTEGER REFERENCES team_members(id)`);
    console.log('✓ Added team_member_id column to sub_activities table');
  } catch (e) {
    // Column already exists, ignore
  }

  // Migration: Add working_days, training_days, to_plan_days to team_members
  try {
    db.exec(`ALTER TABLE team_members ADD COLUMN working_days INTEGER DEFAULT 0`);
    console.log('✓ Added working_days to team_members');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE team_members ADD COLUMN training_days INTEGER DEFAULT 0`);
    console.log('✓ Added training_days to team_members');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE team_members ADD COLUMN to_plan_days INTEGER DEFAULT 0`);
    console.log('✓ Added to_plan_days to team_members');
  } catch (e) { }

  // Migration: Add created_by column to users table
  try {
    db.exec(`ALTER TABLE users ADD COLUMN created_by INTEGER REFERENCES users(id)`);
    console.log('✓ Added created_by to users');
  } catch (e) { }

  // Migration: Add start_time and end_time columns to activities table
  try {
    db.exec(`ALTER TABLE activities ADD COLUMN start_time TEXT`);
    console.log('✓ Added start_time to activities');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE activities ADD COLUMN end_time TEXT`);
    console.log('✓ Added end_time to activities');
  } catch (e) { }

  // Migration: Add start_time and end_time columns to sub_activities table
  try {
    db.exec(`ALTER TABLE sub_activities ADD COLUMN start_time TEXT`);
    console.log('✓ Added start_time to sub_activities');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE sub_activities ADD COLUMN end_time TEXT`);
    console.log('✓ Added end_time to sub_activities');
  } catch (e) { }



  // Migration: Add dark_mode column to users table if not exists
  try {
    db.exec(`ALTER TABLE users ADD COLUMN dark_mode BOOLEAN DEFAULT 0`);
    console.log('✓ Added dark_mode to users');
  } catch (e) { }

  // Migration: Add must_change_password column to users table
  try {
    db.exec(`ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0`);
    console.log('✓ Added must_change_password to users');
  } catch (e) { }

  // Migration: Add first_name and last_name columns to users table
  try {
    db.exec(`ALTER TABLE users ADD COLUMN first_name TEXT DEFAULT ''`);
    console.log('✓ Added first_name to users');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE users ADD COLUMN last_name TEXT DEFAULT ''`);
    console.log('✓ Added last_name to users');
  } catch (e) { }

  // Migration: Populate existing empty users with meaningful names to test the dropdown UI
  try {
    db.exec(`UPDATE users SET first_name = 'Jürgen', last_name = 'Eifridt' WHERE username = 'juergen' AND (first_name = '' OR first_name IS NULL)`);
    db.exec(`UPDATE users SET first_name = 'Team', last_name = 'Lead' WHERE username = 'teamlead' AND (first_name = '' OR first_name IS NULL)`);
    db.exec(`UPDATE users SET first_name = 'Kevin', last_name = 'M' WHERE username = 'Kevin' AND (first_name = '' OR first_name IS NULL)`);
    db.exec(`UPDATE users SET first_name = 'Karl', last_name = 'T' WHERE username = 'KarlT' AND (first_name = '' OR first_name IS NULL)`);
    console.log('✓ Populated existing users with sample first and last names');
  } catch (e) { console.error(e) }
  try {
    db.exec(`ALTER TABLE users ADD COLUMN abbreviation TEXT DEFAULT ''`);
    console.log('✓ Added abbreviation to users');
  } catch (e) { }

  // Migration: Create user_sid_visibility table for per-user Gantt visibility
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_sid_visibility (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sid_id INTEGER NOT NULL REFERENCES sids(id) ON DELETE CASCADE,
      visible BOOLEAN NOT NULL DEFAULT 1,
      PRIMARY KEY (user_id, sid_id)
    )
  `);

  console.log('✓ Database initialized');
};

initDatabase();
console.log(`✓ SAP Basis Jahresplaner Backend starting - Version: ${APP_VERSION}`);
logAction(null, 'SYSTEM', 'STARTUP', { version: APP_VERSION });

// =========================================================================
// LOGGING HELPER
// =========================================================================

function logAction(userId, username, action, details = null) {
  try {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] [${username || 'SYSTEM'}] ${action}: ${details ? JSON.stringify(details) : ''}\n`;

    // Check file size and rotate if needed
    if (fs.existsSync(LOG_FILE)) {
      const stats = fs.statSync(LOG_FILE);
      if (stats.size >= MAX_LOG_SIZE) {
        // Log rotation: Read file, drop oldest 20%, write back
        const content = fs.readFileSync(LOG_FILE, 'utf8');
        const lines = content.split('\n');
        const splitIndex = Math.floor(lines.length * 0.2);
        const newContent = lines.slice(splitIndex).join('\n');
        fs.writeFileSync(LOG_FILE, newContent);
      }
    }

    fs.appendFileSync(LOG_FILE, logLine);
  } catch (e) {
    console.error('Logging error:', e);
  }
}

// =========================================================================
// AUTHENTICATION MIDDLEWARE
// =========================================================================

const authenticate = (req, res, next) => {
  // Check cookie first, or fallback to header (optional, but we enforce cookie now for security)
  const token = req.cookies.auth_token;

  if (!token) {
    return res.status(401).json({ error: 'Nicht authentifiziert' });
  }

  const session = db.prepare(`
    SELECT s.*, u.id as user_id, u.username, u.role 
    FROM sessions s 
    JOIN users u ON s.user_id = u.id 
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);

  if (!session) {
    return res.status(401).json({ error: 'Session abgelaufen oder ungültig' });
  }

  req.user = {
    id: session.user_id,
    username: session.username,
    role: session.role,
    version: APP_VERSION
  };
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'teamlead') {
    return res.status(403).json({ error: 'Admin- oder Teamlead-Berechtigung erforderlich' });
  }
  next();
};

const requireTeamLead = (req, res, next) => {
  if (req.user.role !== 'teamlead') {
    return res.status(403).json({ error: 'Nur für Teamleiter erlaubt' });
  }
  next();
};

// =========================================================================
// AUTH ROUTES
// =========================================================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
    }

    const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
    if (!user) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }

    // Create session token
    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

    db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);

    // Clean up old sessions
    db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();

    // Set HttpOnly Cookie
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        dark_mode: !!user.dark_mode,
        must_change_password: !!user.must_change_password,
        version: APP_VERSION
      },
      version: APP_VERSION
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Serverfehler beim Login' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const token = req.cookies.auth_token;
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.clearCookie('auth_token');
  res.json({ success: true });
});


// Health check endpoint (for Docker/Portainer)
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', version: APP_VERSION });
});

// Online Users Tracking
app.post('/api/users/ping', authenticate, (req, res) => {
  const username = req.user.username;

  let abbreviation = username.substring(0, 2).toUpperCase();
  try {
    // Try to locate a matching team member abbreviation
    const member = db.prepare('SELECT abbreviation FROM team_members WHERE LOWER(name) = LOWER(?) OR LOWER(abbreviation) = LOWER(?)').get(username, username);
    if (member && member.abbreviation) {
      abbreviation = member.abbreviation;
    }
  } catch (err) {
    // Fallback to substring if DB fails
  }

  activeUsers.set(req.user.id, {
    id: req.user.id,
    username: username,
    abbreviation: abbreviation,
    lastSeen: Date.now()
  });

  res.json({ success: true });
});

app.get('/api/users/online', authenticate, (req, res) => {
  const now = Date.now();
  const activeList = [];

  for (const [userId, data] of activeUsers.entries()) {
    if (now - data.lastSeen > 60000) { // 60 seconds timeout
      activeUsers.delete(userId);
    } else {
      activeList.push({ id: data.id, abbreviation: data.abbreviation, username: data.username });
    }
  }

  res.json(activeList);
});

// Get current user
app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT dark_mode, must_change_password FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...req.user, dark_mode: !!(user && user.dark_mode), must_change_password: !!(user && user.must_change_password), version: APP_VERSION });
});

// Update dark mode preference
app.put('/api/auth/dark-mode', authenticate, (req, res) => {
  const { dark_mode } = req.body;
  db.prepare('UPDATE users SET dark_mode = ? WHERE id = ?').run(dark_mode ? 1 : 0, req.user.id);
  res.json({ success: true, dark_mode: !!dark_mode });
});

// Change own password
app.post('/api/auth/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Aktuelles und neues Passwort erforderlich' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Neues Passwort muss mindestens 6 Zeichen haben' });
    }

    // Verify current password
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const passwordValid = await bcrypt.compare(currentPassword, user.password_hash);

    if (!passwordValid) {
      return res.status(401).json({ error: 'Aktuelles Passwort ist falsch' });
    }

    // Update password and clear must_change_password flag
    const newHash = await bcrypt.hash(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(newHash, req.user.id);

    res.json({ success: true, message: 'Passwort erfolgreich geändert' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Serverfehler beim Passwort ändern' });
  }
});

// =========================================================================
// SETTINGS ROUTES
// =========================================================================

app.get('/api/settings', authenticate, (req, res) => {
  const settings = db.prepare('SELECT key, value FROM settings').all();
  const settingsObj = { version: APP_VERSION };
  settings.forEach(s => {
    settingsObj[s.key] = s.value;
  });
  // Log the response for debugging missing version
  logAction(req.user.id, req.user.username, 'GET_SETTINGS', { version: settingsObj.version });
  res.json(settingsObj);
});

app.put('/api/settings', authenticate, requireAdmin, (req, res) => {
  const { year, bundesland } = req.body;

  if (year !== undefined) {
    db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(year), 'year');
  }
  if (bundesland !== undefined) {
    db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(bundesland, 'bundesland');
  }

  res.json({ success: true });
});

// =========================================================================
// ACTIVITY TYPES ROUTES
// =========================================================================

app.get('/api/activity-types', authenticate, (req, res) => {
  const types = db.prepare('SELECT * FROM activity_types ORDER BY sort_order').all();
  res.json(types);
});

app.post('/api/activity-types', authenticate, requireAdmin, (req, res) => {
  const { id, label, color } = req.body;

  if (!id || !label || !color) {
    return res.status(400).json({ error: 'id, label und color erforderlich' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM activity_types').get();
  const sortOrder = (maxOrder.max || 0) + 1;

  try {
    db.prepare('INSERT INTO activity_types (id, label, color, sort_order) VALUES (?, ?, ?, ?)').run(id, label, color, sortOrder);
    res.json({ id, label, color, sort_order: sortOrder });
  } catch (error) {
    res.status(400).json({ error: 'Aktivitätstyp existiert bereits' });
  }
});

app.put('/api/activity-types/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { label, color } = req.body;

  const updates = [];
  const values = [];

  if (label !== undefined) {
    updates.push('label = ?');
    values.push(label);
  }
  if (color !== undefined) {
    updates.push('color = ?');
    values.push(color);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  db.prepare(`UPDATE activity_types SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

app.delete('/api/activity-types/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;

  // Check if type is in use
  const inUse = db.prepare('SELECT COUNT(*) as count FROM activities WHERE type_id = ?').get(id);
  if (inUse.count > 0) {
    return res.status(400).json({ error: 'Aktivitätstyp wird noch verwendet und kann nicht gelöscht werden' });
  }

  db.prepare('DELETE FROM activity_types WHERE id = ?').run(id);
  res.json({ success: true });
});

// =========================================================================
// LANDSCAPES ROUTES
// =========================================================================

const cleanupLocks = () => {
  db.prepare('DELETE FROM landscape_locks WHERE expires_at < CURRENT_TIMESTAMP').run();
};

app.get('/api/landscapes/locks', authenticate, (req, res) => {
  cleanupLocks();
  const locks = db.prepare('SELECT * FROM landscape_locks').all();
  res.json(locks);
});

app.post('/api/landscapes/:id/lock', authenticate, (req, res) => {
  const { id } = req.params;
  cleanupLocks();

  const existingLock = db.prepare('SELECT * FROM landscape_locks WHERE landscape_id = ?').get(id);

  if (existingLock) {
    if (existingLock.user_id !== req.user.id) {
      return res.status(409).json({ error: `Landschaft ist bereits gesperrt durch ${existingLock.username}` });
    }
    // Renew lock
    db.prepare("UPDATE landscape_locks SET expires_at = datetime('now', '+5 minutes') WHERE landscape_id = ?").run(id);
  } else {
    // Acquire new lock
    db.prepare("INSERT INTO landscape_locks (landscape_id, user_id, username, expires_at) VALUES (?, ?, ?, datetime('now', '+5 minutes'))")
      .run(id, req.user.id, req.user.username);
  }

  res.json({ success: true, expires_at: db.prepare('SELECT expires_at FROM landscape_locks WHERE landscape_id = ?').get(id).expires_at });
});

app.delete('/api/landscapes/:id/lock', authenticate, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM landscape_locks WHERE landscape_id = ? AND user_id = ?').run(id, req.user.id);
  res.json({ success: true });
});

app.get('/api/landscapes', authenticate, (req, res) => {
  cleanupLocks();
  const landscapes = db.prepare('SELECT * FROM landscapes ORDER BY sort_order').all();

  // Get SIDs and activities for each landscape
  const result = landscapes.map(landscape => {
    const sids = db.prepare('SELECT * FROM sids WHERE landscape_id = ? ORDER BY sort_order').all(landscape.id);

    const sidsWithActivities = sids.map(sid => {
      const activities = db.prepare('SELECT * FROM activities WHERE sid_id = ? ORDER BY start_date').all(sid.id);

      // Check per-user visibility override
      const userVis = req.user ? db.prepare('SELECT visible FROM user_sid_visibility WHERE user_id = ? AND sid_id = ?').get(req.user.id, sid.id) : null;
      const visibleInGantt = userVis !== undefined && userVis !== null ? !!userVis.visible : sid.visible_in_gantt !== 0;

      return {
        ...sid,
        isPRD: !!sid.is_prd,
        visibleInGantt,
        activities: activities.map(a => {
          // Get sub-activities for this activity
          const subActivities = db.prepare('SELECT * FROM sub_activities WHERE activity_id = ? ORDER BY sort_order').all(a.id);
          return {
            ...a,
            type: a.type_id,
            startDate: a.start_date,
            includesWeekend: !!a.includes_weekend,
            team_member_id: a.team_member_id || null,
            teamMemberId: a.team_member_id || null,
            start_time: a.start_time || null,
            end_time: a.end_time || null,
            subActivities: subActivities.map(sa => ({
              id: sa.id,
              name: sa.name,
              startDate: sa.start_date,
              duration: sa.duration,
              includesWeekend: !!sa.includes_weekend,
              sort_order: sa.sort_order,
              team_member_id: sa.team_member_id || null,
              teamMemberId: sa.team_member_id || null,
              start_time: sa.start_time || null,
              end_time: sa.end_time || null
            }))
          };
        })
      };
    });

    const lock = db.prepare('SELECT user_id, username, expires_at FROM landscape_locks WHERE landscape_id = ?').get(landscape.id);

    return {
      ...landscape,
      lock: lock || null,
      sids: sidsWithActivities
    };
  });

  res.json(result);
});

app.post('/api/landscapes', authenticate, requireAdmin, (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Name erforderlich' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM landscapes').get();
  const sortOrder = (maxOrder.max || 0) + 1;

  const result = db.prepare('INSERT INTO landscapes (name, sort_order) VALUES (?, ?)').run(name, sortOrder);
  res.json({ id: result.lastInsertRowid, name, sort_order: sortOrder, sids: [] });
});

app.put('/api/landscapes/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { name, sort_order } = req.body;

    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
    }
    if (sort_order !== undefined) {
      const newSortOrder = parseInt(sort_order) || 0;

      // Check if another landscape has this sort_order
      const conflicting = db.prepare('SELECT id FROM landscapes WHERE sort_order = ? AND id != ?').get(newSortOrder, id);

      if (conflicting) {
        // Find the first available gap in the sequence (1, 2, 3, ...)
        const usedOrders = db.prepare('SELECT sort_order FROM landscapes WHERE id != ?').all(id).map(r => r.sort_order);
        usedOrders.push(newSortOrder); // Include the new order being assigned

        let nextAvailable = 1;
        while (usedOrders.includes(nextAvailable)) {
          nextAvailable++;
        }

        // Reassign the conflicting landscape to next sequential available
        db.prepare('UPDATE landscapes SET sort_order = ? WHERE id = ?').run(nextAvailable, conflicting.id);
      }

      updates.push('sort_order = ?');
      values.push(newSortOrder);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Keine Änderungen angegeben' });
    }

    values.push(id);
    db.prepare(`UPDATE landscapes SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (error) {
    console.error('Update landscape error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/landscapes/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM landscapes WHERE id = ?').run(id);
  res.json({ success: true });
});

// =========================================================================
// SIDS ROUTES
// =========================================================================

app.post('/api/sids', authenticate, requireAdmin, (req, res) => {
  const { landscape_id, name, is_prd, visible_in_gantt } = req.body;

  if (!landscape_id) {
    return res.status(400).json({ error: 'landscape_id erforderlich' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM sids WHERE landscape_id = ?').get(landscape_id);
  const sortOrder = (maxOrder?.max || 0) + 1;

  const result = db.prepare('INSERT INTO sids (landscape_id, name, is_prd, visible_in_gantt, sort_order) VALUES (?, ?, ?, ?, ?)').run(
    landscape_id,
    name || '',
    is_prd ? 1 : 0,
    visible_in_gantt !== false ? 1 : 0, // Default to true
    sortOrder
  );

  res.json({
    id: result.lastInsertRowid,
    landscape_id,
    name: name || '',
    isPRD: !!is_prd,
    visibleInGantt: visible_in_gantt !== false,
    sort_order: sortOrder,
    activities: []
  });
});

app.put('/api/sids/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, is_prd, visible_in_gantt, notes, sort_order } = req.body;

  const updates = [];
  const values = [];

  const currentSid = db.prepare('SELECT landscape_id, sort_order FROM sids WHERE id = ?').get(id);
  if (!currentSid) {
    return res.status(404).json({ error: 'SID nicht gefunden' });
  }

  if (sort_order !== undefined) {
    const newSortOrder = parseInt(sort_order) || 0;
    if (newSortOrder !== currentSid.sort_order) {
      // Check if another SID in this landscape has this sort_order
      const conflicting = db.prepare('SELECT id FROM sids WHERE landscape_id = ? AND sort_order = ? AND id != ?').get(currentSid.landscape_id, newSortOrder, id);

      if (conflicting) {
        // Shift conflicting SID correctly
        const usedOrders = db.prepare('SELECT sort_order FROM sids WHERE landscape_id = ? AND id != ?').all(currentSid.landscape_id, id).map(r => r.sort_order);
        let nextAvailable = newSortOrder + 1;
        while (usedOrders.includes(nextAvailable)) {
          nextAvailable++;
        }
        db.prepare('UPDATE sids SET sort_order = ? WHERE id = ?').run(nextAvailable, conflicting.id);
      }
      updates.push('sort_order = ?');
      values.push(newSortOrder);
    }
  }

  if (name !== undefined) {
    updates.push('name = ?');
    values.push(name);
  }
  if (is_prd !== undefined) {
    updates.push('is_prd = ?');
    values.push(is_prd ? 1 : 0);
  }
  if (visible_in_gantt !== undefined) {
    updates.push('visible_in_gantt = ?');
    values.push(visible_in_gantt ? 1 : 0);
  }
  if (notes !== undefined) {
    updates.push('notes = ?');
    values.push(notes.substring(0, 5000)); // Limit to 5000 chars
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  db.prepare(`UPDATE sids SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

// Deep Copy SID
app.post('/api/sids/:id/copy', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params; // Source SID
  const { target_landscape_id, new_name } = req.body;

  if (!target_landscape_id || !new_name) {
    return res.status(400).json({ error: 'target_landscape_id und new_name erforderlich' });
  }

  const sourceSid = db.prepare('SELECT * FROM sids WHERE id = ?').get(id);
  if (!sourceSid) {
    return res.status(404).json({ error: 'Quell-SID nicht gefunden' });
  }

  try {
    const newSidId = db.transaction(() => {
      // 1. Create new SID record
      const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM sids WHERE landscape_id = ?').get(target_landscape_id);
      const sortOrder = (maxOrder?.max || 0) + 1;

      const sidResult = db.prepare('INSERT INTO sids (landscape_id, name, is_prd, visible_in_gantt, notes, sort_order) VALUES (?, ?, ?, ?, ?, ?)').run(
        target_landscape_id,
        new_name,
        sourceSid.is_prd,
        sourceSid.visible_in_gantt,
        sourceSid.notes,
        sortOrder
      );
      const targetSidId = sidResult.lastInsertRowid;

      // 2. Fetch and duplicate all activities for this SID
      const activities = db.prepare('SELECT * FROM activities WHERE sid_id = ?').all(id);

      const insertActivity = db.prepare(`
        INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, start_time, end_time, team_member_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const subActivities = db.prepare('SELECT * FROM sub_activities WHERE activity_id = ?');
      const insertSubActivity = db.prepare(`
        INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, start_time, end_time, team_member_id, sort_order)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const activity of activities) {
        const activityResult = insertActivity.run(
          targetSidId,
          activity.type_id,
          activity.start_date,
          activity.duration,
          activity.includes_weekend,
          activity.start_time,
          activity.end_time,
          activity.team_member_id
        );
        const newActivityId = activityResult.lastInsertRowid;

        // 3. Fetch and duplicate all sub_activities for the current activity
        const subs = subActivities.all(activity.id);
        for (const sub of subs) {
          insertSubActivity.run(
            newActivityId,
            sub.name,
            sub.start_date,
            sub.duration,
            sub.includes_weekend,
            sub.start_time,
            sub.end_time,
            sub.team_member_id,
            sub.sort_order
          );
        }
      }

      return targetSidId;
    })();

    logAction(req.user.id, req.user.username, 'SID_COPY', { source_id: id, target_id: newSidId, target_landscape_id, new_name });
    res.json({ success: true, id: newSidId });

  } catch (error) {
    console.error('Deep Copy SID Error:', error);
    res.status(500).json({ error: 'Fehler beim Kopieren der SID' });
  }
});

// Toggle SID Gantt visibility — per-user, available to ALL authenticated users
app.patch('/api/sids/:id/visibility', authenticate, (req, res) => {
  const { id } = req.params;
  const { visible_in_gantt } = req.body;
  if (visible_in_gantt === undefined) {
    return res.status(400).json({ error: 'visible_in_gantt erforderlich' });
  }
  db.prepare(
    'INSERT OR REPLACE INTO user_sid_visibility (user_id, sid_id, visible) VALUES (?, ?, ?)'
  ).run(req.user.id, id, visible_in_gantt ? 1 : 0);
  res.json({ success: true });
});

app.delete('/api/sids/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM sids WHERE id = ?').run(id);
  res.json({ success: true });
});

// =========================================================================
// ACTIVITIES ROUTES
// =========================================================================

app.post('/api/activities', authenticate, requireAdmin, (req, res) => {
  const { sid_id, type_id, start_date, duration, includes_weekend, team_member_id } = req.body;

  if (!sid_id || !type_id || !start_date) {
    return res.status(400).json({ error: 'sid_id, type_id und start_date erforderlich' });
  }

  const result = db.prepare(`
    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, team_member_id) 
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sid_id, type_id, start_date, duration || 1, includes_weekend ? 1 : 0, team_member_id || null);

  logAction(req.user.id, req.user.username, 'ACTIVITY_CREATE', { sid_id, type_id, start_date, duration });

  res.json({
    id: result.lastInsertRowid,
    sid_id,
    type: type_id,
    startDate: start_date,
    duration: duration || 1,
    includesWeekend: !!includes_weekend,
    team_member_id: team_member_id || null,
    teamMemberId: team_member_id || null
  });
});

app.put('/api/activities/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { type_id, start_date, duration, includes_weekend, team_member_id, start_time, end_time } = req.body;

  const updates = [];
  const values = [];

  if (type_id !== undefined) {
    updates.push('type_id = ?');
    values.push(type_id);
  }
  if (start_date !== undefined) {
    updates.push('start_date = ?');
    values.push(start_date);
  }
  if (duration !== undefined) {
    updates.push('duration = ?');
    values.push(duration);
  }
  if (includes_weekend !== undefined) {
    updates.push('includes_weekend = ?');
    values.push(includes_weekend ? 1 : 0);
  }
  if (team_member_id !== undefined) {
    updates.push('team_member_id = ?');
    values.push(team_member_id || null);
  }
  if (start_time !== undefined) {
    updates.push('start_time = ?');
    values.push(start_time || null);
  }
  if (end_time !== undefined) {
    updates.push('end_time = ?');
    values.push(end_time || null);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  db.prepare(`UPDATE activities SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

app.delete('/api/activities/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM activities WHERE id = ?').run(id);
  res.json({ success: true });
});

// =========================================================================
// SUB-ACTIVITIES ROUTES
// =========================================================================

// Create sub-activity
app.post('/api/sub-activities', authenticate, requireAdmin, (req, res) => {
  const { activity_id, name, start_date, duration, includes_weekend, team_member_id } = req.body;

  if (!activity_id || !start_date) {
    return res.status(400).json({ error: 'activity_id und start_date erforderlich' });
  }

  // Verify parent activity exists
  const parentActivity = db.prepare('SELECT id, type_id FROM activities WHERE id = ?').get(activity_id);
  if (!parentActivity) {
    return res.status(404).json({ error: 'Übergeordnete Aktivität nicht gefunden' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM sub_activities WHERE activity_id = ?').get(activity_id);
  const sortOrder = (maxOrder?.max || 0) + 1;

  const result = db.prepare(`
    INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, sort_order, team_member_id) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(activity_id, name || 'Sub-Aktivität', start_date, duration || 1, includes_weekend ? 1 : 0, sortOrder, team_member_id || null);

  logAction(req.user.id, req.user.username, 'SUBACTIVITY_CREATE', { activity_id, name, start_date, duration });

  res.json({
    id: result.lastInsertRowid,
    activity_id,
    name: name || 'Sub-Aktivität',
    startDate: start_date,
    duration: duration || 1,
    includesWeekend: !!includes_weekend,
    sort_order: sortOrder,
    team_member_id: team_member_id || null
  });
});

// Update sub-activity
app.put('/api/sub-activities/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, start_date, duration, includes_weekend, team_member_id, start_time, end_time } = req.body;

  const updates = [];
  const values = [];

  if (name !== undefined) {
    updates.push('name = ?');
    values.push(name);
  }
  if (start_date !== undefined) {
    updates.push('start_date = ?');
    values.push(start_date);
  }
  if (duration !== undefined) {
    updates.push('duration = ?');
    values.push(duration);
  }
  if (includes_weekend !== undefined) {
    updates.push('includes_weekend = ?');
    values.push(includes_weekend ? 1 : 0);
  }
  if (team_member_id !== undefined) {
    updates.push('team_member_id = ?');
    values.push(team_member_id || null);
  }
  if (start_time !== undefined) {
    updates.push('start_time = ?');
    values.push(start_time || null);
  }
  if (end_time !== undefined) {
    updates.push('end_time = ?');
    values.push(end_time || null);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  db.prepare(`UPDATE sub_activities SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

// Delete sub-activity
app.delete('/api/sub-activities/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM sub_activities WHERE id = ?').run(id);
  res.json({ success: true });
});

// =========================================================================
// TEAM MEMBERS ROUTES
// =========================================================================

// Get all team members
app.get('/api/team-members', authenticate, (req, res) => {
  const members = db.prepare('SELECT * FROM team_members ORDER BY sort_order').all();
  res.json(members);
});

// Create team member
app.post('/api/team-members', authenticate, requireTeamLead, (req, res) => {
  let { name, user_id, abbreviation, working_days, training_days, to_plan_days } = req.body;

  if (!abbreviation) {
    return res.status(400).json({ error: 'Abkürzung erforderlich' });
  }

  if (user_id) {
    const user = db.prepare('SELECT username, first_name, last_name FROM users WHERE id = ?').get(user_id);
    if (!user) {
      return res.status(400).json({ error: 'Benutzer nicht gefunden' });
    }
    name = (user.first_name || user.last_name) ? `${user.first_name} ${user.last_name}`.trim() : user.username;
    // Update abbreviation in user's data set
    db.prepare('UPDATE users SET abbreviation = ? WHERE id = ?').run(abbreviation, user_id);
  } else if (!name) {
    return res.status(400).json({ error: 'Name oder Benutzer erforderlich' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM team_members').get();
  const sortOrder = (maxOrder.max || 0) + 1;

  try {
    const result = db.prepare('INSERT INTO team_members (name, abbreviation, sort_order, working_days, training_days, to_plan_days) VALUES (?, ?, ?, ?, ?, ?)').run(
      name,
      abbreviation,
      sortOrder,
      working_days || 0,
      training_days || 0,
      to_plan_days || 0
    );
    logAction(req.user.id, req.user.username, 'TEAM_MEMBER_CREATE', { name, abbreviation });
    res.json({
      id: result.lastInsertRowid,
      name,
      abbreviation,
      sort_order: sortOrder,
      working_days: working_days || 0,
      training_days: training_days || 0,
      to_plan_days: to_plan_days || 0
    });
  } catch (error) {
    res.status(400).json({ error: 'Fehler beim Erstellen des Teammitglieds' });
  }
});

// Update team member
app.put('/api/team-members/:id', authenticate, requireTeamLead, (req, res) => {
  const { id } = req.params;
  const { name, abbreviation } = req.body;

  const updates = [];
  const values = [];

  if (name !== undefined) {
    updates.push('name = ?');
    values.push(name);
  }
  if (abbreviation !== undefined) {
    updates.push('abbreviation = ?');
    values.push(abbreviation);
  }
  if (req.body.working_days !== undefined) {
    updates.push('working_days = ?');
    values.push(req.body.working_days);
  }
  if (req.body.training_days !== undefined) {
    updates.push('training_days = ?');
    values.push(req.body.training_days);
  }
  if (req.body.to_plan_days !== undefined) {
    updates.push('to_plan_days = ?');
    values.push(req.body.to_plan_days);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  db.prepare(`UPDATE team_members SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  logAction(req.user.id, req.user.username, 'TEAM_MEMBER_UPDATE', { id, name, abbreviation });
  res.json({ success: true });
});

// Delete team member
app.delete('/api/team-members/:id', authenticate, requireTeamLead, (req, res) => {
  const { id } = req.params;

  // Set team_member_id to NULL for activities/sub-activities that reference this member
  db.prepare('UPDATE activities SET team_member_id = NULL WHERE team_member_id = ?').run(id);
  db.prepare('UPDATE sub_activities SET team_member_id = NULL WHERE team_member_id = ?').run(id);

  db.prepare('DELETE FROM team_members WHERE id = ?').run(id);
  logAction(req.user.id, req.user.username, 'TEAM_MEMBER_DELETE', { id });
  res.json({ success: true });
});

// =========================================================================
// USER MANAGEMENT ROUTES (Admin only)
// =========================================================================

app.get('/api/users', authenticate, requireTeamLead, (req, res) => {
  const users = db.prepare('SELECT id, username, first_name, last_name, abbreviation, role, created_at, created_by FROM users ORDER BY created_at').all();
  res.json(users);
});

app.post('/api/users', authenticate, requireAdmin, async (req, res) => {
  const { username, password, role, first_name, last_name } = req.body;

  if (!username || !password || !first_name || !last_name) {
    return res.status(400).json({ error: 'Benutzername, Passwort, Vorname und Nachname erforderlich' });
  }

  const targetRole = role || 'user';

  // Role-based creation restrictions
  if (req.user.role === 'teamlead') {
    // Teamlead can create admin, user, or teamlead
    if (!['admin', 'user', 'teamlead'].includes(targetRole)) {
      return res.status(400).json({ error: 'Ungültige Rolle' });
    }
  } else if (req.user.role === 'admin') {
    // Admin can only create user
    if (targetRole !== 'user') {
      return res.status(403).json({ error: 'Admins können nur Benutzer erstellen' });
    }
  } else {
    return res.status(403).json({ error: 'Keine Berechtigung' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash, role, created_by, must_change_password, first_name, last_name) VALUES (?, ?, ?, ?, 1, ?, ?)').run(
      username,
      passwordHash,
      targetRole,
      req.user.id,
      first_name || '',
      last_name || ''
    );
    res.json({ id: result.lastInsertRowid, username, first_name, last_name, role: targetRole, created_by: req.user.id });
  } catch (error) {
    res.status(400).json({ error: 'Benutzername existiert bereits' });
  }
});

app.put('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, password, role } = req.body;

  const updates = [];
  const values = [];

  if (username !== undefined) {
    updates.push('username = ?');
    values.push(username);
  }
  if (password !== undefined) {
    const passwordHash = await bcrypt.hash(password, 10);
    updates.push('password_hash = ?');
    values.push(passwordHash);
    // Force password change on next login after admin reset
    updates.push('must_change_password = ?');
    values.push(1);
  }
  if (role !== undefined) {
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Ungültige Rolle' });
    }
    updates.push('role = ?');
    values.push(role);
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  values.push(id);
  try {
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: 'Benutzername existiert bereits' });
  }
});

app.delete('/api/users/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const targetId = parseInt(id);

  // Prevent deleting self
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Sie können sich nicht selbst löschen' });
  }

  // Get target user info
  const targetUser = db.prepare('SELECT id, role, created_by FROM users WHERE id = ?').get(targetId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Benutzer nicht gefunden' });
  }

  // Cannot delete teamlead users
  if (targetUser.role === 'teamlead') {
    return res.status(403).json({ error: 'Teamleiter können nicht gelöscht werden' });
  }

  // Role-based deletion restrictions
  if (req.user.role === 'teamlead') {
    // Teamlead can delete admin or user
    // (teamlead deletion already blocked above)
  } else if (req.user.role === 'admin') {
    // Admin can only delete users (not admins)
    if (targetUser.role !== 'user') {
      return res.status(403).json({ error: 'Admins können nur Benutzer löschen' });
    }
  }

  // Handle foreign key constraint for created_by and logs
  // If this user created other users, set their created_by to NULL
  // Also unlink from logs (set user_id to NULL to keep log history but allow user deletion)
  // Wrap in transaction for safety
  const deleteTransaction = db.transaction((userId) => {
    db.prepare('UPDATE users SET created_by = NULL WHERE created_by = ?').run(userId);
    db.prepare('UPDATE logs SET user_id = NULL WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  });

  try {
    deleteTransaction(targetId);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Fehler beim Löschen des Benutzers: ' + error.message });
  }
});

// =========================================================================
// JSON IMPORT ROUTE
// =========================================================================

app.post('/api/import/json', authenticate, requireAdmin, (req, res) => {
  const data = req.body;

  if (!data) {
    return res.status(400).json({ error: 'JSON-Daten erforderlich' });
  }

  try {
    // Start transaction
    const transaction = db.transaction(() => {
      // Import settings
      if (data.year) {
        db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(data.year), 'year');
      }
      if (data.bundesland) {
        db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(data.bundesland, 'bundesland');
      }

      // Import activity types
      if (data.activityTypes && Array.isArray(data.activityTypes)) {
        // Clear existing types that are not in use
        const usedTypes = db.prepare('SELECT DISTINCT type_id FROM activities').all().map(r => r.type_id);
        db.prepare('DELETE FROM activity_types WHERE id NOT IN (SELECT DISTINCT type_id FROM activities)').run();

        const insertOrUpdateType = db.prepare(`
          INSERT INTO activity_types (id, label, color, sort_order) VALUES (?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET label = excluded.label, color = excluded.color, sort_order = excluded.sort_order
        `);

        data.activityTypes.forEach((type, index) => {
          insertOrUpdateType.run(type.id, type.label, type.color, index);
        });
      }

      // Import landscapes
      if (data.landscapes && Array.isArray(data.landscapes)) {
        // Clear existing data
        db.prepare('DELETE FROM activities').run();
        db.prepare('DELETE FROM sids').run();
        db.prepare('DELETE FROM landscapes').run();

        data.landscapes.forEach((landscape, landscapeIndex) => {
          const landscapeResult = db.prepare('INSERT INTO landscapes (name, sort_order) VALUES (?, ?)').run(
            landscape.name,
            landscapeIndex
          );
          const newLandscapeId = landscapeResult.lastInsertRowid;

          if (landscape.sids && Array.isArray(landscape.sids)) {
            landscape.sids.forEach((sid, sidIndex) => {
              const sidResult = db.prepare('INSERT INTO sids (landscape_id, name, is_prd, sort_order) VALUES (?, ?, ?, ?)').run(
                newLandscapeId,
                sid.name || '',
                sid.isPRD ? 1 : 0,
                sidIndex
              );
              const newSidId = sidResult.lastInsertRowid;

              if (sid.activities && Array.isArray(sid.activities)) {
                sid.activities.forEach(activity => {
                  db.prepare(`
                    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend) 
                    VALUES (?, ?, ?, ?, ?)
                  `).run(
                    newSidId,
                    activity.type,
                    activity.startDate,
                    activity.duration || 1,
                    activity.includesWeekend ? 1 : 0
                  );
                });
              }
            });
          }
        });
      }
    });

    transaction();
    res.json({ success: true, message: 'Daten erfolgreich importiert' });
  } catch (error) {
    console.error('Import error:', error);
    res.status(500).json({ error: 'Fehler beim Import: ' + error.message });
  }
});

// =========================================================================
// LOGS API
// =========================================================================

// Get logs (admin only)
// Get logs (admin only)
app.get('/api/logs', authenticate, requireAdmin, (req, res) => {
  try {
    if (fs.existsSync(LOG_FILE)) {
      const content = fs.readFileSync(LOG_FILE, 'utf8');
      res.json({ logs: content });
    } else {
      res.json({ logs: '' });
    }
  } catch (error) {
    console.error('Error reading logs:', error);
    res.status(500).json({ error: 'Fehler beim Laden der Logs' });
  }
});

// =========================================================================
// MAINTENANCE SUNDAYS API
// =========================================================================

// Get all maintenance sundays
app.get('/api/maintenance-sundays', authenticate, (req, res) => {
  try {
    const sundays = db.prepare('SELECT id, date, label FROM maintenance_sundays ORDER BY id').all();
    res.json(sundays);
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Laden der Wartungssonntage' });
  }
});

// Update maintenance sunday (admin only)
app.put('/api/maintenance-sundays/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { date, label } = req.body;

    if (id < 1 || id > 4) {
      return res.status(400).json({ error: 'Ungültige Wartungssonntag-ID (1-4)' });
    }

    db.prepare('UPDATE maintenance_sundays SET date = ?, label = ? WHERE id = ?').run(date || '', label || '', id);

    logAction(req.user.id, req.user.username, 'MAINTENANCE_SUNDAY_UPDATE', { id, date, label });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Fehler beim Aktualisieren des Wartungssonntags' });
  }
});

// =========================================================================
// BACKUP/RESTORE API (Teamlead only)
// =========================================================================

// Export all data as JSON backup
app.get('/api/backup/export', authenticate, requireAdmin, (req, res) => {
  try {
    // Get settings
    const settings = db.prepare('SELECT key, value FROM settings').all();
    const settingsObj = {};
    settings.forEach(s => settingsObj[s.key] = s.value);

    // Get activity types
    const activityTypes = db.prepare('SELECT * FROM activity_types ORDER BY sort_order').all();

    // Get team members
    const teamMembers = db.prepare('SELECT * FROM team_members ORDER BY sort_order').all();

    // Get maintenance sundays
    const maintenanceSundays = db.prepare('SELECT * FROM maintenance_sundays ORDER BY id').all();

    // Get landscapes with full hierarchy
    const landscapes = db.prepare('SELECT * FROM landscapes ORDER BY sort_order').all();
    const landscapesWithData = landscapes.map(landscape => {
      const sids = db.prepare('SELECT * FROM sids WHERE landscape_id = ? ORDER BY sort_order').all(landscape.id);
      const sidsWithActivities = sids.map(sid => {
        const activities = db.prepare('SELECT * FROM activities WHERE sid_id = ? ORDER BY start_date').all(sid.id);
        const activitiesWithSubs = activities.map(activity => {
          const subActivities = db.prepare('SELECT * FROM sub_activities WHERE activity_id = ? ORDER BY sort_order').all(activity.id);
          return {
            ...activity,
            type: activity.type_id,
            startDate: activity.start_date,
            includesWeekend: !!activity.includes_weekend,
            teamMemberId: activity.team_member_id,
            subActivities: subActivities.map(sa => ({
              ...sa,
              startDate: sa.start_date,
              includesWeekend: !!sa.includes_weekend,
              teamMemberId: sa.team_member_id
            }))
          };
        });
        return {
          ...sid,
          isPRD: !!sid.is_prd,
          visibleInGantt: !!sid.visible_in_gantt,
          activities: activitiesWithSubs
        };
      });
      return {
        ...landscape,
        sids: sidsWithActivities
      };
    });

    const backup = {
      version: APP_VERSION,
      exportDate: new Date().toISOString(),
      settings: settingsObj,
      activityTypes,
      teamMembers,
      maintenanceSundays,
      landscapes: landscapesWithData
    };

    // Set headers for file download
    const filename = `sap-planner-backup-${new Date().toISOString().split('T')[0]}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');

    logAction(req.user.id, req.user.username, 'BACKUP_EXPORT', { filename });
    res.json(backup);
  } catch (error) {
    console.error('Backup export error:', error);
    res.status(500).json({ error: 'Fehler beim Erstellen des Backups: ' + error.message });
  }
});

// Import data from JSON backup (replaces existing data)
app.post('/api/backup/import', authenticate, requireAdmin, (req, res) => {
  const backup = req.body;

  // Validate backup structure
  if (!backup || !backup.version) {
    return res.status(400).json({ error: 'Ungültiges Backup-Format: Version fehlt' });
  }

  try {
    const stats = {
      activityTypes: 0,
      teamMembers: 0,
      maintenanceSundays: 0,
      landscapes: 0,
      sids: 0,
      activities: 0,
      subActivities: 0
    };

    const transaction = db.transaction(() => {
      // 1. Import settings
      if (backup.settings) {
        if (backup.settings.year) {
          db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(backup.settings.year), 'year');
        }
        if (backup.settings.bundesland) {
          db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(backup.settings.bundesland, 'bundesland');
        }
      }

      // 2. Import activity types (upsert)
      if (backup.activityTypes && Array.isArray(backup.activityTypes)) {
        const insertOrUpdateType = db.prepare(`
          INSERT INTO activity_types (id, label, color, sort_order) VALUES (?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET label = excluded.label, color = excluded.color, sort_order = excluded.sort_order
        `);
        backup.activityTypes.forEach((type, index) => {
          insertOrUpdateType.run(type.id, type.label, type.color, type.sort_order ?? index);
          stats.activityTypes++;
        });
      }

      // 3. Import team members (clear and recreate)
      if (backup.teamMembers && Array.isArray(backup.teamMembers)) {
        // Clear assignments first
        db.prepare('UPDATE activities SET team_member_id = NULL').run();
        db.prepare('UPDATE sub_activities SET team_member_id = NULL').run();
        db.prepare('DELETE FROM team_members').run();

        const insertMember = db.prepare(`
          INSERT INTO team_members (id, name, abbreviation, sort_order, working_days, training_days, to_plan_days) 
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        backup.teamMembers.forEach(member => {
          insertMember.run(
            member.id,
            member.name,
            member.abbreviation,
            member.sort_order || 0,
            member.working_days || 0,
            member.training_days || 0,
            member.to_plan_days || 0
          );
          stats.teamMembers++;
        });
      }

      // 4. Import maintenance sundays
      if (backup.maintenanceSundays && Array.isArray(backup.maintenanceSundays)) {
        backup.maintenanceSundays.forEach(sunday => {
          if (sunday.id >= 1 && sunday.id <= 4) {
            db.prepare('UPDATE maintenance_sundays SET date = ?, label = ? WHERE id = ?')
              .run(sunday.date || '', sunday.label || '', sunday.id);
            stats.maintenanceSundays++;
          }
        });
      }

      // 5. Import landscapes with full hierarchy
      if (backup.landscapes && Array.isArray(backup.landscapes)) {
        // Clear existing data (cascade will handle activities)
        db.prepare('DELETE FROM sub_activities').run();
        db.prepare('DELETE FROM activities').run();
        db.prepare('DELETE FROM sids').run();
        db.prepare('DELETE FROM landscapes').run();

        // Create ID mapping for team members (old ID -> new ID if IDs changed)
        const teamMemberMap = new Map();
        if (backup.teamMembers) {
          backup.teamMembers.forEach(m => teamMemberMap.set(m.id, m.id));
        }

        backup.landscapes.forEach((landscape, landscapeIndex) => {
          const landscapeResult = db.prepare('INSERT INTO landscapes (name, sort_order) VALUES (?, ?)')
            .run(landscape.name, landscape.sort_order ?? landscapeIndex);
          const newLandscapeId = landscapeResult.lastInsertRowid;
          stats.landscapes++;

          if (landscape.sids && Array.isArray(landscape.sids)) {
            landscape.sids.forEach((sid, sidIndex) => {
              const sidResult = db.prepare(`
                INSERT INTO sids (landscape_id, name, is_prd, visible_in_gantt, notes, sort_order) 
                VALUES (?, ?, ?, ?, ?, ?)
              `).run(
                newLandscapeId,
                sid.name || '',
                sid.isPRD || sid.is_prd ? 1 : 0,
                (sid.visibleInGantt ?? sid.visible_in_gantt ?? true) ? 1 : 0,
                sid.notes || '',
                sid.sort_order ?? sidIndex
              );
              const newSidId = sidResult.lastInsertRowid;
              stats.sids++;

              if (sid.activities && Array.isArray(sid.activities)) {
                sid.activities.forEach(activity => {
                  const teamMemberId = activity.teamMemberId || activity.team_member_id;
                  const activityResult = db.prepare(`
                    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, team_member_id, start_time, end_time) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                  `).run(
                    newSidId,
                    activity.type || activity.type_id,
                    activity.startDate || activity.start_date,
                    activity.duration || 1,
                    activity.includesWeekend || activity.includes_weekend ? 1 : 0,
                    teamMemberMap.has(teamMemberId) ? teamMemberId : null,
                    activity.start_time || null,
                    activity.end_time || null
                  );
                  const newActivityId = activityResult.lastInsertRowid;
                  stats.activities++;

                  if (activity.subActivities && Array.isArray(activity.subActivities)) {
                    activity.subActivities.forEach((sub, subIndex) => {
                      const subTeamMemberId = sub.teamMemberId || sub.team_member_id;
                      db.prepare(`
                        INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, sort_order, team_member_id, start_time, end_time) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `).run(
                        newActivityId,
                        sub.name || 'Sub-Aktivität',
                        sub.startDate || sub.start_date,
                        sub.duration || 1,
                        sub.includesWeekend || sub.includes_weekend ? 1 : 0,
                        sub.sort_order ?? subIndex,
                        teamMemberMap.has(subTeamMemberId) ? subTeamMemberId : null,
                        sub.start_time || null,
                        sub.end_time || null
                      );
                      stats.subActivities++;
                    });
                  }
                });
              }
            });
          }
        });
      }
    });

    transaction();

    logAction(req.user.id, req.user.username, 'BACKUP_IMPORT', {
      version: backup.version,
      exportDate: backup.exportDate,
      stats
    });

    res.json({
      success: true,
      message: 'Backup erfolgreich importiert',
      stats
    });
  } catch (error) {
    console.error('Backup import error:', error);
    res.status(500).json({ error: 'Fehler beim Import: ' + error.message });
  }
});

// =========================================================================
// API: MATRIX & TRAININGS 
// =========================================================================

// Get Matrix (Columns and Values)
app.get('/api/matrix', authenticate, (req, res) => {
  try {
    const columns = db.prepare('SELECT * FROM matrix_columns ORDER BY sort_order ASC, name ASC').all();
    const values = db.prepare('SELECT * FROM matrix_values').all();
    res.json({ columns, values });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Matrix Column
app.post('/api/matrix/columns', authenticate, requireAdmin, (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name ist erforderlich' });

    const id = uuidv4();
    const sort_order = db.prepare('SELECT COALESCE(MAX(sort_order), 0) + 1 AS next FROM matrix_columns').get().next;

    db.prepare('INSERT INTO matrix_columns (id, name, sort_order) VALUES (?, ?, ?)')
      .run(id, name, sort_order);

    logAction(req.user.id, req.user.username, 'CREATE_MATRIX_COLUMN', { columnId: id, name });
    res.json({ id, name, sort_order });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Matrix Column
app.put('/api/matrix/columns/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { name, sort_order } = req.body;
    const stmt = db.prepare('UPDATE matrix_columns SET name = COALESCE(?, name), sort_order = COALESCE(?, sort_order) WHERE id = ?');
    stmt.run(name, sort_order, req.params.id);

    // Sort collision logic can be complex, keeping it simple for now
    logAction(req.user.id, req.user.username, 'UPDATE_MATRIX_COLUMN', { columnId: req.params.id, name });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Matrix Column
app.delete('/api/matrix/columns/:id', authenticate, requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM matrix_columns WHERE id = ?').run(req.params.id);
    logAction(req.user.id, req.user.username, 'DELETE_MATRIX_COLUMN', { columnId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Upsert Matrix Value (Everyone can edit)
app.put('/api/matrix/values', authenticate, (req, res) => {
  try {
    const { teamMemberId, columnId, level } = req.body;
    if (!teamMemberId || !columnId || level === undefined) {
      return res.status(400).json({ error: 'teamMemberId, columnId und level erforderlich' });
    }

    const count = db.prepare('SELECT count(*) as c FROM matrix_values WHERE team_member_id = ? AND column_id = ?').get(teamMemberId, columnId).c;

    if (count > 0) {
      db.prepare('UPDATE matrix_values SET level = ? WHERE team_member_id = ? AND column_id = ?').run(level, teamMemberId, columnId);
    } else {
      db.prepare('INSERT INTO matrix_values (team_member_id, column_id, level) VALUES (?, ?, ?)').run(teamMemberId, columnId, level);
    }

    logAction(req.user.id, req.user.username, 'UPDATE_MATRIX_VALUE', { teamMemberId, columnId, level });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Trainings
app.get('/api/trainings', authenticate, (req, res) => {
  try {
    const trainings = db.prepare('SELECT * FROM trainings ORDER BY id ASC').all();
    res.json(trainings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Training 
app.post('/api/trainings', authenticate, requireAdmin, (req, res) => {
  try {
    const result = db.prepare(`
      INSERT INTO trainings (participants, course, topic, cost, location, date1, date2, date3, days, is_booked)
      VALUES ('', 'Neuer Kurs', '', '', '', '', '', '', 0, 0)
    `).run();

    logAction(req.user.id, req.user.username, 'CREATE_TRAINING', { trainingId: result.lastInsertRowid });
    res.json({ id: result.lastInsertRowid, course: 'Neuer Kurs', participants: '', topic: '', cost: '', location: '', date1: '', date2: '', date3: '', days: 0, is_booked: 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Training
app.put('/api/trainings/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { participants, course, topic, cost, location, date1, date2, date3, days, is_booked } = req.body;

    // Dynamically build the update query to only update provided fields
    const updates = [];
    const params = [];

    const fields = { participants, course, topic, cost, location, date1, date2, date3, days, is_booked };

    for (const [key, value] of Object.entries(fields)) {
      if (value !== undefined) {
        updates.push(`${key} = ?`);
        params.push(value);
      }
    }

    if (updates.length === 0) return res.json({ success: true });

    params.push(req.params.id);

    db.prepare(`UPDATE trainings SET ${updates.join(', ')} WHERE id = ?`).run(...params);

    logAction(req.user.id, req.user.username, 'UPDATE_TRAINING', { trainingId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Training
app.delete('/api/trainings/:id', authenticate, requireAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM trainings WHERE id = ?').run(req.params.id);
    logAction(req.user.id, req.user.username, 'DELETE_TRAINING', { trainingId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =========================================================================
// SERVE FRONTEND
// =========================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'sap-planner.html'));
});

// =========================================================================
// START SERVER
// =========================================================================

const startServer = () => {
  const keyPath = path.join(__dirname, 'server.key');
  const certPath = path.join(__dirname, 'server.cert');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    // Start HTTPS Server
    try {
      const httpsOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
      };

      https.createServer(httpsOptions, app).listen(PORT, HOST, () => {
        console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SAP Basis Jahresplaner Server (HTTPS)                       ║
║                                                               ║
║   Server läuft auf: https://localhost:${PORT}                  ║
║   Datenbank: ${path.basename(dbPath)}                                   ║
║                                                               ║
║   Standard-Login: admin (Passwort nach Erstanmeldung ändern!) ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        `);
      });
    } catch (error) {
      console.error('Failed to start HTTPS server:', error);
      console.log('Falling back to HTTP...');
      startHttp();
    }
  } else {
    // Start HTTP Server (Fallback)
    startHttp();
  }
};

const startHttp = () => {
  app.listen(PORT, HOST, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SAP Basis Jahresplaner Server (HTTP)                        ║
║                                                               ║
║   Server läuft auf: http://${HOST}:${PORT}                       ║
║   Datenbank: ${path.basename(dbPath)}                                   ║
║                                                               ║
║   Standard-Login: teamlead (Passwort nach Erstanmeldung ändern!) ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    `);
  });
};

startServer();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nServer wird beendet...');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nServer wird beendet...');
  db.close();
  process.exit(0);
});
