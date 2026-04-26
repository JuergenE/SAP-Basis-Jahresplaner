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
const compression = require('compression');
const cookieParser = require('cookie-parser');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3232;
const HOST = process.env.HOST || '0.0.0.0';

// Trust proxy headers (X-Forwarded-For) when running behind a reverse proxy / Kubernetes ingress.
// Required for express-rate-limit to correctly identify clients by their real IP.
// Default '1' = trust exactly one proxy hop (typical K8s ingress setup).
// Set TRUST_PROXY env var to adjust: '2' for chained proxies, '0' to disable.
app.set('trust proxy', Number(process.env.TRUST_PROXY ?? 1));

// Online Users Memory Store
// Maps user_id -> { id, username, abbreviation, lastSeen }
const activeUsers = new Map();

// Read version from package.json
let APP_VERSION = '0.2.0';
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
// Gzip/Brotli compression for all responses.
// Disable via NO_COMPRESSION=1 when behind a proxy that handles compression (e.g. K8s ingress)
// to prevent double-compression which can corrupt responses and freeze the frontend.
if (!process.env.NO_COMPRESSION) {
  app.use(compression());
  console.log('✓ Response compression enabled');
} else {
  console.log('⚠ Response compression disabled (NO_COMPRESSION is set)');
}

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
  max: 10000, // Limit each IP to 10000 requests per windowMs (supports 50+ concurrent users)
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false }, // Disable strict proxy validation for K8s environments
  message: { error: 'Zu viele Anfragen. Bitte versuchen Sie es später erneut.' }
});
app.use('/api/', apiLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300, // 300 login attempts per 15 min (supports offices sharing one IP)
  validate: { trustProxy: false, xForwardedForHeader: false },
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
const allowedStaticFiles = ['sap-planner.html', 'screenshot.png', 'styles.css', 'app.js'];
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
const db = new Database(dbPath,
  { timeout: 30000 }); // 30s busy timeout for high-concurrency environments

// Enable WAL mode for better concurrent access
db.pragma('journal_mode = WAL');

// =========================================================================
// DATE CALCULATION HELPERS (server-side, mirrors frontend logic)
// =========================================================================

const getEasterDate = (year) => {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31) - 1;
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(year, month, day);
};

const getGermanHolidays = (year, bundesland) => {
  const holidays = new Set();
  const addHoliday = (date) => {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    holidays.add(`${y}-${m}-${d}`);
  };

  // Fixed holidays (nationwide)
  addHoliday(new Date(year, 0, 1));   // Neujahr
  addHoliday(new Date(year, 4, 1));   // Tag der Arbeit
  addHoliday(new Date(year, 9, 3));   // Tag der Deutschen Einheit
  addHoliday(new Date(year, 11, 25)); // 1. Weihnachtstag
  addHoliday(new Date(year, 11, 26)); // 2. Weihnachtstag

  // Easter-based holidays
  const easter = getEasterDate(year);
  const karfreitag = new Date(easter); karfreitag.setDate(easter.getDate() - 2);
  addHoliday(karfreitag);
  const ostermontag = new Date(easter); ostermontag.setDate(easter.getDate() + 1);
  addHoliday(ostermontag);
  const christiHimmelfahrt = new Date(easter); christiHimmelfahrt.setDate(easter.getDate() + 39);
  addHoliday(christiHimmelfahrt);
  const pfingstmontag = new Date(easter); pfingstmontag.setDate(easter.getDate() + 50);
  addHoliday(pfingstmontag);

  // State-specific holidays
  if (['BW', 'BY', 'ST'].includes(bundesland)) addHoliday(new Date(year, 0, 6));
  if (['BW', 'BY', 'HE', 'NW', 'RP', 'SL'].includes(bundesland)) {
    const fronleichnam = new Date(easter); fronleichnam.setDate(easter.getDate() + 60);
    addHoliday(fronleichnam);
  }
  if (['BY', 'SL'].includes(bundesland)) addHoliday(new Date(year, 7, 15));
  if (['BB', 'MV', 'SN', 'ST', 'TH'].includes(bundesland)) addHoliday(new Date(year, 9, 31));
  if (['BW', 'BY', 'NW', 'RP', 'SL'].includes(bundesland)) addHoliday(new Date(year, 10, 1));
  if (bundesland === 'SN') {
    const nov23 = new Date(year, 10, 23);
    const dayOfWeek = nov23.getDay();
    const daysToWednesday = (dayOfWeek + 4) % 7;
    const bussUndBettag = new Date(nov23); bussUndBettag.setDate(nov23.getDate() - daysToWednesday);
    addHoliday(bussUndBettag);
  }

  return holidays;
};

/** Cache for holiday sets to avoid recomputation when crossing year boundaries */
const _holidayCache = new Map();
const getHolidaysForYear = (year, bundesland) => {
  const key = `${year}_${bundesland}`;
  if (_holidayCache.has(key)) return _holidayCache.get(key);
  const holidays = getGermanHolidays(year, bundesland);
  _holidayCache.set(key, holidays);
  // Keep cache small: only retain last 5 entries
  if (_holidayCache.size > 5) {
    const firstKey = _holidayCache.keys().next().value;
    _holidayCache.delete(firstKey);
  }
  return holidays;
};

/** Check if a given date string is a holiday for its own year */
const isHoliday = (dateStr, bundesland) => {
  const year = parseInt(dateStr.substring(0, 4));
  const holidays = getHolidaysForYear(year, bundesland);
  return holidays.has(dateStr);
};

const formatDateISO = (date) => {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
};

/**
 * Calculate end date based on working days (Arbeitstage).
 * Duration 0 = sub-day (time-based), start and end are the same day.
 * includesWeekend = true means weekends ARE working days (only holidays excluded).
 * 
 * Multi-year aware: derives the correct holiday calendar from each day's own year,
 * so activities crossing year boundaries (e.g. Dec 30 → Jan 3) work correctly.
 * The `year` and `bundesland` params are kept for API compatibility; `bundesland`
 * is used for holiday lookups. `year` is now ignored — the start date's own year is used.
 */
const calculateEndDate = (startDateStr, durationDays, year, bundesland, includesWeekend = false) => {
  if (!startDateStr) return null;
  if (durationDays === 0) return startDateStr;

  let current = new Date(startDateStr);
  let workingDaysCount = 0;

  while (workingDaysCount < durationDays) {
    const dateStr = formatDateISO(current);
    const dayOfWeek = current.getDay();

    let isWorkingDay;
    if (includesWeekend) {
      isWorkingDay = !isHoliday(dateStr, bundesland);
    } else {
      isWorkingDay = dayOfWeek !== 0 && dayOfWeek !== 6 && !isHoliday(dateStr, bundesland);
    }

    if (isWorkingDay) {
      workingDaysCount++;
      if (workingDaysCount >= durationDays) break;
    }

    current.setDate(current.getDate() + 1);
  }

  return formatDateISO(current);
};

/** Read current year and bundesland from settings table */
const getSettingsForEndDate = () => {
  try {
    const yearRow = db.prepare("SELECT value FROM settings WHERE key = 'year'").get();
    const blRow = db.prepare("SELECT value FROM settings WHERE key = 'bundesland'").get();
    return {
      year: parseInt(yearRow?.value || new Date().getFullYear()),
      bundesland: blRow?.value || 'BW'
    };
  } catch {
    return { year: new Date().getFullYear(), bundesland: 'BW' };
  }
};

// Initialize database schema
const initDatabase = () => {
  db.exec(`
    -- Users & Authentication
    -- Note: Migration to add 'teamlead' role is handled in initDatabase code below
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('admin', 'user', 'teamlead', 'viewer', 'projekt')) NOT NULL DEFAULT 'user',
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

    -- Bereitschaft
    CREATE TABLE IF NOT EXISTS bereitschaft (
      week_start TEXT PRIMARY KEY,
      user_id INTEGER,
      abbreviation TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    -- Urlaub (Vacation Planning)
    CREATE TABLE IF NOT EXISTS urlaub (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_urlaub_user ON urlaub(user_id);
    CREATE INDEX IF NOT EXISTS idx_urlaub_dates ON urlaub(start_date, end_date);

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
      includes_weekend BOOLEAN DEFAULT FALSE,
      team_member_id INTEGER REFERENCES team_members(id),
      start_time TEXT,
      end_time TEXT,
      status TEXT DEFAULT 'PLANNED'
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
      sort_order INTEGER DEFAULT 0,
      team_member_id INTEGER REFERENCES team_members(id),
      start_time TEXT,
      end_time TEXT,
      status TEXT DEFAULT 'PLANNED'
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

    -- SID Locks (Multi-User concurrency) Replacing old landscape_locks
    CREATE TABLE IF NOT EXISTS sid_locks (
      sid_id INTEGER PRIMARY KEY REFERENCES sids(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id),
      username TEXT,
      abbreviation TEXT,
      expires_at DATETIME NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sid_locks_expires ON sid_locks(expires_at);

    -- Activity Series (recurring activity groups)
    CREATE TABLE IF NOT EXISTS activity_series (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sid_id INTEGER REFERENCES sids(id) ON DELETE CASCADE,
      type_id TEXT REFERENCES activity_types(id),
      rule_type TEXT CHECK(rule_type IN ('every_x_weeks', 'x_per_year', 'manual')) DEFAULT 'manual',
      rule_value INTEGER DEFAULT 0,
      rule_start_date TEXT,
      rule_end_date TEXT,
      default_start_time TEXT DEFAULT '',
      default_end_time TEXT DEFAULT '',
      team_member_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_activity_series_sid ON activity_series(sid_id);

    -- Series Occurrences (individual dates within a series)
    CREATE TABLE IF NOT EXISTS series_occurrences (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      series_id INTEGER REFERENCES activity_series(id) ON DELETE CASCADE,
      date TEXT NOT NULL,
      start_time TEXT DEFAULT '',
      end_time TEXT DEFAULT '',
      includes_weekend BOOLEAN DEFAULT FALSE,
      team_member_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL,
      sort_order INTEGER DEFAULT 0,
      status TEXT DEFAULT 'PLANNED'
    );
    CREATE INDEX IF NOT EXISTS idx_series_occurrences_series ON series_occurrences(series_id);

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
      booked_date INTEGER DEFAULT 0
    );
  `);

  // Migration: Drop old landscape_locks table
  try {
    db.exec(`DROP TABLE IF EXISTS landscape_locks`);
    console.log('✓ Dropped deprecated landscape_locks table');
  } catch (e) { }

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
            role TEXT CHECK(role IN ('admin', 'user', 'teamlead', 'viewer')) NOT NULL DEFAULT 'user',
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
  try {
    db.exec(`ALTER TABLE team_members ADD COLUMN weekly_hours REAL DEFAULT 40`);
    console.log('✓ Added weekly_hours to team_members');
  } catch (e) { }

  // Migration: Add created_by column to users table
  try {
    db.exec(`ALTER TABLE users ADD COLUMN created_by INTEGER REFERENCES users(id)`);
    console.log('✓ Added created_by to users');
  } catch (e) { }

  // Migration: Add system_type column to sids table and migrate is_prd
  try {
    const tableDef = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='sids'").get();
    if (tableDef && !tableDef.sql.includes('system_type')) {
      db.exec(`ALTER TABLE sids ADD COLUMN system_type TEXT DEFAULT 'DEV'`);
      db.exec(`UPDATE sids SET system_type = 'PRD' WHERE is_prd = 1`);
      console.log('✓ Added system_type column to sids and migrated is_prd data');
    }
  } catch (e) {
    console.error('Migration system_type failed:', e.message);
  }

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

  // Migration: Add status column to activities and sub_activities tables
  try {
    db.exec(`ALTER TABLE activities ADD COLUMN status TEXT DEFAULT 'PLANNED'`);
    console.log('✓ Added status to activities');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE sub_activities ADD COLUMN status TEXT DEFAULT 'PLANNED'`);
    console.log('✓ Added status to sub_activities');
  } catch (e) { }
  try {
    db.exec(`ALTER TABLE series_occurrences ADD COLUMN status TEXT DEFAULT 'PLANNED'`);
    console.log('✓ Added status to series_occurrences');
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

  // Fix existing users with empty or too-short abbreviations
  try {
    const usersToFix = db.prepare("SELECT id, username, first_name, last_name, abbreviation FROM users WHERE (abbreviation IS NULL OR abbreviation = '' OR LENGTH(abbreviation) < 3) AND first_name IS NOT NULL AND first_name != '' AND last_name IS NOT NULL AND last_name != ''").all();
    for (const u of usersToFix) {
      const fn = u.first_name.trim().toUpperCase();
      const ln = u.last_name.trim().toUpperCase();
      if (fn && ln) {
        const newAbbr = fn[0] + ln[0] + ln[ln.length - 1];
        db.prepare('UPDATE users SET abbreviation = ? WHERE id = ?').run(newAbbr, u.id);
        // Also sync to team_members
        const memberName = `${u.first_name} ${u.last_name}`.trim();
        db.prepare('UPDATE team_members SET abbreviation = ? WHERE LOWER(name) = LOWER(?)').run(newAbbr, memberName);
        console.log(`✓ Fixed abbreviation for ${u.username}: '${u.abbreviation || ''}' → '${newAbbr}'`);
      }
    }
  } catch (e) { console.error('Abbreviation fix error:', e); }

  try {
    db.exec(`ALTER TABLE trainings ADD COLUMN booked_date INTEGER DEFAULT 0`);
    console.log('✓ Added booked_date to trainings');
  } catch (e) { }

  // Migration: Add abbreviation column to sid_locks
  try {
    db.exec(`ALTER TABLE sid_locks ADD COLUMN abbreviation TEXT DEFAULT ''`);
    console.log('✓ Added abbreviation to sid_locks');
  } catch (e) { }

  // Migration: Add rule_end_date column to activity_series
  try {
    db.exec(`ALTER TABLE activity_series ADD COLUMN rule_end_date TEXT`);
    console.log('✓ Added rule_end_date to activity_series');
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

  // Migration: Update users table to allow 'viewer' role
  try {
    const tableDef2 = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (tableDef2 && !tableDef2.sql.includes('viewer')) {
      console.log('Migrating users table to include viewer role...');
      db.pragma('foreign_keys = OFF');
      db.pragma('legacy_alter_table = ON'); // Prevent SQLite from updating FK refs in other tables
      db.transaction(() => {
        // Get current column list
        const cols = db.pragma('table_info(users)').map(c => c.name);
        const colList = cols.join(', ');
        db.exec("ALTER TABLE users RENAME TO users_old2");
        db.exec(`
          CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'user', 'teamlead', 'viewer', 'projekt')) NOT NULL DEFAULT 'user',
            must_change_password BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            dark_mode BOOLEAN DEFAULT 0,
            first_name TEXT DEFAULT '',
            last_name TEXT DEFAULT '',
            abbreviation TEXT
          )
        `);
        db.exec(`INSERT INTO users (${colList}) SELECT ${colList} FROM users_old2`);
        db.exec("DROP TABLE users_old2");
      })();
      db.pragma('legacy_alter_table = OFF');
      db.pragma('foreign_keys = ON');
      console.log('✓ Users table migrated to include viewer role');
    }
  } catch (e) {
    console.error('Viewer role migration failed:', e);
    try { db.pragma('legacy_alter_table = OFF'); } catch (err) { }
    try { db.pragma('foreign_keys = ON'); } catch (err) { }
  }

  // Migration: Update users table to allow 'projekt' role
  try {
    const tableDef3 = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (tableDef3 && !tableDef3.sql.includes('projekt')) {
      console.log('Migrating users table to include projekt role...');
      db.pragma('foreign_keys = OFF');
      db.pragma('legacy_alter_table = ON');
      db.transaction(() => {
        const cols = db.pragma('table_info(users)').map(c => c.name);
        const colList = cols.join(', ');
        db.exec("ALTER TABLE users RENAME TO users_old3");
        db.exec(`
          CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'user', 'teamlead', 'viewer', 'projekt')) NOT NULL DEFAULT 'user',
            must_change_password BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            dark_mode BOOLEAN DEFAULT 0,
            first_name TEXT DEFAULT '',
            last_name TEXT DEFAULT '',
            abbreviation TEXT
          )
        `);
        db.exec(`INSERT INTO users (${colList}) SELECT ${colList} FROM users_old3`);
        db.exec("DROP TABLE users_old3");
      })();
      db.pragma('legacy_alter_table = OFF');
      db.pragma('foreign_keys = ON');
      console.log('✓ Users table migrated to include projekt role');
    }
  } catch (e) {
    console.error('Projekt role migration failed:', e);
    try { db.pragma('legacy_alter_table = OFF'); } catch (err) { }
    try { db.pragma('foreign_keys = ON'); } catch (err) { }
  }

  // Repair: Fix ALL tables with broken FK references from the RENAME migration
  try {
    const brokenTables = db.prepare(
      "SELECT name, sql FROM sqlite_master WHERE type='table' AND sql LIKE '%users_old2%'"
    ).all();
    if (brokenTables.length > 0) {
      console.log(`Repairing ${brokenTables.length} table(s) with broken FK references...`);
      db.pragma('foreign_keys = OFF');
      db.transaction(() => {
        brokenTables.forEach(({ name, sql }) => {
          const cols = db.pragma(`table_info(${name})`).map(c => c.name);
          const colList = cols.join(', ');
          const tempName = `${name}_repair_temp`;
          db.exec(`ALTER TABLE ${name} RENAME TO ${tempName}`);
          // Fix the schema: replace users_old2 with users
          const fixedSql = sql.replace(/users_old2/g, 'users');
          db.exec(fixedSql);
          db.exec(`INSERT INTO ${name} (${colList}) SELECT ${colList} FROM ${tempName}`);
          db.exec(`DROP TABLE ${tempName}`);
          console.log(`  ✓ Repaired: ${name}`);
        });
      })();
      db.pragma('foreign_keys = ON');
      console.log('✓ All broken FK references repaired');
    }
  } catch (e) {
    console.error('FK repair failed:', e);
    try { db.pragma('foreign_keys = ON'); } catch (err) { }
  }

  // Migration: Add end_date column to activities and sub_activities
  try {
    db.exec(`ALTER TABLE activities ADD COLUMN end_date TEXT`);
    console.log('✓ Added end_date column to activities');
  } catch (e) { /* Column already exists */ }
  try {
    db.exec(`ALTER TABLE sub_activities ADD COLUMN end_date TEXT`);
    console.log('✓ Added end_date column to sub_activities');
  } catch (e) { /* Column already exists */ }

  // Backfill: Compute end_date for all activities/sub_activities that don't have one
  try {
    const { year, bundesland } = getSettingsForEndDate();
    const activitiesToFix = db.prepare(
      "SELECT id, start_date, duration, includes_weekend FROM activities WHERE end_date IS NULL AND start_date IS NOT NULL"
    ).all();
    if (activitiesToFix.length > 0) {
      const updateStmt = db.prepare('UPDATE activities SET end_date = ? WHERE id = ?');
      for (const act of activitiesToFix) {
        const endDate = calculateEndDate(act.start_date, act.duration || 1, year, bundesland, !!act.includes_weekend);
        updateStmt.run(endDate, act.id);
      }
      console.log(`✓ Backfilled end_date for ${activitiesToFix.length} activities`);
    }

    const subsToFix = db.prepare(
      "SELECT id, start_date, duration, includes_weekend FROM sub_activities WHERE end_date IS NULL AND start_date IS NOT NULL"
    ).all();
    if (subsToFix.length > 0) {
      const updateSubStmt = db.prepare('UPDATE sub_activities SET end_date = ? WHERE id = ?');
      for (const sub of subsToFix) {
        const endDate = calculateEndDate(sub.start_date, sub.duration || 1, year, bundesland, !!sub.includes_weekend);
        updateSubStmt.run(endDate, sub.id);
      }
      console.log(`✓ Backfilled end_date for ${subsToFix.length} sub_activities`);
    }
  } catch (e) {
    console.error('end_date backfill error:', e.message);
  }

  console.log('✓ Database initialized');
};

initDatabase();
console.log(`✓ SAP Basis Jahresplaner Backend starting - Version: ${APP_VERSION}`);
logAction(null, 'SYSTEM', 'STARTUP', { version: APP_VERSION });

// ── CI Test User Bootstrap ──────────────────────────────────────────────
// When TEST_USER and TEST_PASS environment variables are set (e.g. in CI),
// ensure the test user exists with must_change_password=0 so E2E tests
// can log in without being blocked by the password-change modal.
if (process.env.TEST_USER && process.env.TEST_PASS) {
  try {
    const testUser = process.env.TEST_USER;
    const testPass = process.env.TEST_PASS;
    const existing = db.prepare('SELECT id, must_change_password FROM users WHERE username = ?').get(testUser);
    if (existing && existing.must_change_password) {
      // Clear the must_change_password flag so E2E tests can proceed
      db.prepare('UPDATE users SET must_change_password = 0 WHERE id = ?').run(existing.id);
      console.log(`✓ CI: Cleared must_change_password for test user "${testUser}"`);
    } else if (!existing) {
      // Create a dedicated CI test user
      const hash = bcrypt.hashSync(testPass, 10);
      db.prepare('INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 0)')
        .run(testUser, hash, 'admin');
      console.log(`✓ CI: Created test user "${testUser}" (admin, no password change required)`);
    }
  } catch (e) {
    console.error('⚠ CI test user setup failed:', e.message);
  }
}

const autoUpdateActivityStatuses = () => {
  try {
    const COMPLETED_THRESHOLD_HOURS = 24;
    const ARCHIVED_THRESHOLD_DAYS = 7;

    const completedThresholdDate = new Date();
    completedThresholdDate.setHours(completedThresholdDate.getHours() - COMPLETED_THRESHOLD_HOURS);
    const completedStr = completedThresholdDate.toISOString().split('T')[0];

    const archivedThresholdDate = new Date();
    archivedThresholdDate.setDate(archivedThresholdDate.getDate() - ARCHIVED_THRESHOLD_DAYS);
    const archivedStr = archivedThresholdDate.toISOString().split('T')[0];

    // Use stored end_date for accurate working-day-aware comparisons

    // 1. Move PLANNED to COMPLETED (end_date has passed)
    const stmtCompleted = db.prepare(`
      UPDATE activities 
      SET status = 'COMPLETED' 
      WHERE status = 'PLANNED' 
      AND end_date IS NOT NULL AND end_date <= ?
    `);
    const resCompleted = stmtCompleted.run(completedStr);

    const stmtSubCompleted = db.prepare(`
      UPDATE sub_activities 
      SET status = 'COMPLETED' 
      WHERE status = 'PLANNED' 
      AND end_date IS NOT NULL AND end_date <= ?
    `);
    stmtSubCompleted.run(completedStr);

    const stmtOccCompleted = db.prepare(`
      UPDATE series_occurrences 
      SET status = 'COMPLETED' 
      WHERE status = 'PLANNED' 
      AND date(date) <= ?
    `);
    stmtOccCompleted.run(completedStr);

    // 2. Move COMPLETED to ARCHIVED (7 days after end date)
    const stmtArchived = db.prepare(`
      UPDATE activities 
      SET status = 'ARCHIVED' 
      WHERE status = 'COMPLETED' 
      AND end_date IS NOT NULL AND end_date <= ?
    `);
    const resArchived = stmtArchived.run(archivedStr);

    const stmtSubArchived = db.prepare(`
      UPDATE sub_activities 
      SET status = 'ARCHIVED' 
      WHERE status = 'COMPLETED' 
      AND end_date IS NOT NULL AND end_date <= ?
    `);
    stmtSubArchived.run(archivedStr);

    const stmtOccArchived = db.prepare(`
      UPDATE series_occurrences 
      SET status = 'ARCHIVED' 
      WHERE status = 'COMPLETED' 
      AND date(date) <= ?
    `);
    stmtOccArchived.run(archivedStr);

    if (resCompleted.changes > 0 || resArchived.changes > 0) {
      console.log(`✓ Auto-Archiver: Marked ${resCompleted.changes} activities COMPLETED and ${resArchived.changes} ARCHIVED.`);
    }
  } catch (err) {
    console.error('Error auto-updating activity statuses:', err.message);
  }
};

// Periodic session cleanup (moved out of login route to reduce write contention)
const cleanupExpiredSessions = () => {
  try {
    const result = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
    if (result.changes > 0) {
      console.log(`✓ Session cleanup: removed ${result.changes} expired session(s).`);
    }
  } catch (err) {
    console.error('Session cleanup error:', err.message);
  }
};

// Run maintenance on boot
autoUpdateActivityStatuses();
cleanupExpiredSessions();
// Run every hour (but skip during tests to avoid open handles)
if (process.env.NODE_ENV !== 'test') {
  setInterval(() => {
    autoUpdateActivityStatuses();
    cleanupExpiredSessions();
  }, 60 * 60 * 1000);
}

// =========================================================================
// LOGGING HELPER
// =========================================================================

function logAction(userId, username, action, details = null) {
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] [${username || 'SYSTEM'}] ${action}: ${details ? JSON.stringify(details) : ''}\n`;

  // Async logging to avoid blocking the event loop during high concurrency
  (async () => {
    try {
      // Check file size and rotate if needed
      try {
        const stats = await fs.promises.stat(LOG_FILE);
        if (stats.size >= MAX_LOG_SIZE) {
          const content = await fs.promises.readFile(LOG_FILE, 'utf8');
          const lines = content.split('\n');
          const splitIndex = Math.floor(lines.length * 0.2);
          const newContent = lines.slice(splitIndex).join('\n');
          await fs.promises.writeFile(LOG_FILE, newContent);
        }
      } catch (statErr) {
        // File doesn't exist yet — that's fine, appendFile will create it
      }

      await fs.promises.appendFile(LOG_FILE, logLine);
    } catch (e) {
      console.error('Logging error:', e);
    }
  })();
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
    SELECT s.*, u.id as user_id, u.username, u.role, u.abbreviation 
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
    abbreviation: session.abbreviation || session.username,
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

// Block write operations for read-only roles (viewer, projekt)
const requireWriteAccess = (req, res, next) => {
  if (req.user.role === 'viewer' || req.user.role === 'projekt') {
    return res.status(403).json({ error: 'Keine Schreibberechtigung für diese Rolle' });
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

    // Session cleanup is handled by the hourly maintenance task (cleanupExpiredSessions)

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
        first_name: user.first_name,
        last_name: user.last_name,
        abbreviation: user.abbreviation,
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
  const { activeSidId } = req.body || {};

  // Use user's abbreviation from users table (3-char Kürzel)
  let abbreviation = username.substring(0, 2).toUpperCase();
  try {
    const userRecord = db.prepare('SELECT abbreviation FROM users WHERE id = ?').get(req.user.id);
    if (userRecord && userRecord.abbreviation) {
      abbreviation = userRecord.abbreviation;
    }
  } catch (err) {
    // Fallback to substring if DB fails
  }

  activeUsers.set(req.user.id, {
    id: req.user.id,
    username: username,
    abbreviation: abbreviation,
    activeSidId: activeSidId || null,
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
      activeList.push({
        id: data.id,
        abbreviation: data.abbreviation,
        username: data.username,
        activeSidId: data.activeSidId
      });
    }
  }

  res.json(activeList);
});

// Get current user
app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT dark_mode, must_change_password, first_name, last_name, abbreviation FROM users WHERE id = ?').get(req.user.id);
  res.json({
    ...req.user,
    first_name: user?.first_name,
    last_name: user?.last_name,
    abbreviation: user?.abbreviation,
    dark_mode: !!(user && user.dark_mode),
    must_change_password: !!(user && user.must_change_password),
    version: APP_VERSION
  });
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

// Debug endpoint removed (security: was unauthenticated)

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
// SIDS / LOCKING ROUTES
// =========================================================================

const cleanupLocks = () => {
  db.prepare('DELETE FROM sid_locks WHERE expires_at < CURRENT_TIMESTAMP').run();
};

app.get('/api/sids/locks', authenticate, (req, res) => {
  cleanupLocks();
  const locks = db.prepare('SELECT * FROM sid_locks').all();
  res.json(locks);
});

app.post('/api/sids/:id/lock', authenticate, (req, res) => {
  const { id } = req.params;
  cleanupLocks();

  // Look up user's 3-char abbreviation from users table
  let abbreviation = req.user.username.substring(0, 2).toUpperCase();
  try {
    const userRecord = db.prepare('SELECT abbreviation FROM users WHERE id = ?').get(req.user.id);
    if (userRecord && userRecord.abbreviation) abbreviation = userRecord.abbreviation;
  } catch (e) { }

  const existingLock = db.prepare('SELECT * FROM sid_locks WHERE sid_id = ?').get(id);

  if (existingLock) {
    if (existingLock.user_id !== req.user.id) {
      return res.status(409).json({ error: `SID ist bereits gesperrt durch ${existingLock.username}` });
    }
    // Renew lock on same SID
    db.prepare("UPDATE sid_locks SET expires_at = datetime('now', '+5 minutes'), abbreviation = ? WHERE sid_id = ?").run(abbreviation, id);
  } else {
    // Release ALL other locks held by this user first (single-lock-per-user enforcement)
    db.prepare('DELETE FROM sid_locks WHERE user_id = ?').run(req.user.id);
    // Acquire new lock
    db.prepare("INSERT INTO sid_locks (sid_id, user_id, username, abbreviation, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+5 minutes'))")
      .run(id, req.user.id, req.user.username, abbreviation);
  }

  res.json({ success: true, expires_at: db.prepare('SELECT expires_at FROM sid_locks WHERE sid_id = ?').get(id).expires_at });
});

app.delete('/api/sids/:id/lock', authenticate, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM sid_locks WHERE sid_id = ? AND user_id = ?').run(id, req.user.id);
  res.json({ success: true });
});

// =========================================================================
// LANDSCAPES ROUTES
// =========================================================================

app.get('/api/landscapes', authenticate, (req, res) => {
  cleanupLocks();
  let landscapes = db.prepare('SELECT * FROM landscapes ORDER BY sort_order').all();

  // Projekt role: only show landscapes with '(Projekt)' in the name
  if (req.user.role === 'projekt') {
    landscapes = landscapes.filter(l => l.name && l.name.includes('(Projekt)'));
  }

  // Pre-fetch all SID locks mapped by sid_id
  const allSidLocks = db.prepare('SELECT sid_id, user_id, username, abbreviation, expires_at FROM sid_locks').all();
  const sidLocksMap = {};
  allSidLocks.forEach(lock => {
    sidLocksMap[lock.sid_id] = {
      user_id: lock.user_id,
      username: lock.username,
      abbreviation: lock.abbreviation || lock.username.substring(0, 2).toUpperCase(),
      expires_at: lock.expires_at
    };
  });

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
        systemType: sid.system_type || (sid.is_prd ? 'PRD' : 'DEV'),
        visibleInGantt,
        lock: sidLocksMap[sid.id] || null,
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
              end_time: sa.end_time || null,
              status: sa.status
            }))
          };
        }),
        series: (() => {
          const seriesList = db.prepare('SELECT * FROM activity_series WHERE sid_id = ?').all(sid.id);
          return seriesList.map(s => {
            const occurrences = db.prepare('SELECT * FROM series_occurrences WHERE series_id = ? ORDER BY date, sort_order').all(s.id);
            return {
              ...s,
              typeId: s.type_id,
              ruleType: s.rule_type,
              ruleValue: s.rule_value,
              ruleStartDate: s.rule_start_date,
              ruleEndDate: s.rule_end_date,
              defaultStartTime: s.default_start_time,
              defaultEndTime: s.default_end_time,
              teamMemberId: s.team_member_id,
              occurrences: occurrences.map(o => ({
                ...o,
                includesWeekend: !!o.includes_weekend,
                teamMemberId: o.team_member_id
              }))
            };
          });
        })()
      };
    });

    return {
      ...landscape,
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
  const { landscape_id, name, systemType, visible_in_gantt } = req.body;
  if (!landscape_id) return res.status(400).json({ error: 'landscape_id erforderlich' });

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM sids WHERE landscape_id = ?').get(landscape_id);
  const sortOrder = (maxOrder?.max || 0) + 1;
  const safeName = name || '';

  const result = db.prepare('INSERT INTO sids (landscape_id, name, system_type, is_prd, visible_in_gantt, sort_order) VALUES (?, ?, ?, ?, ?, ?)').run(
    landscape_id,
    safeName,
    systemType || 'DEV',
    (systemType === 'PRD') ? 1 : 0,
    visible_in_gantt !== undefined ? (visible_in_gantt ? 1 : 0) : 1, // Default to true
    sortOrder
  );

  res.json({
    id: result.lastInsertRowid,
    landscapeId: landscape_id,
    name: safeName,
    systemType: systemType || 'DEV',
    isPRD: systemType === 'PRD',
    visibleInGantt: visible_in_gantt !== false,
    sortOrder,
    activities: []
  });
});

app.put('/api/sids/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, systemType, visible_in_gantt, notes, sort_order } = req.body;

  const updates = [];
  const values = [];
  let sortOrderHandled = false;

  const currentSid = db.prepare('SELECT landscape_id, sort_order FROM sids WHERE id = ?').get(id);
  if (!currentSid) {
    return res.status(404).json({ error: 'SID nicht gefunden' });
  }

  if (sort_order !== undefined) {
    let newSortOrder = Math.max(1, Math.min(9, parseInt(sort_order) || 1));
    const allSids = db.prepare('SELECT id, sort_order FROM sids WHERE landscape_id = ? ORDER BY sort_order, id').all(currentSid.landscape_id);

    // Clamp to max number of SIDs
    if (newSortOrder > allSids.length) newSortOrder = allSids.length;

    // Build the new ordering: remove this SID, then insert at the desired position
    const otherSids = allSids.filter(s => s.id !== parseInt(id));
    otherSids.splice(newSortOrder - 1, 0, { id: parseInt(id) });

    // Re-number all SIDs sequentially starting from 1
    const updateStmt = db.prepare('UPDATE sids SET sort_order = ? WHERE id = ?');
    otherSids.forEach((s, idx) => {
      updateStmt.run(idx + 1, s.id);
    });

    sortOrderHandled = true;
  }

  if (name !== undefined) {
    updates.push('name = ?');
    values.push(name);
  }
  if (systemType !== undefined) {
    updates.push('system_type = ?');
    values.push(systemType);
    updates.push('is_prd = ?'); // Keep is_prd in sync for backward compatibility
    values.push(systemType === 'PRD' ? 1 : 0);
  }
  if (visible_in_gantt !== undefined) {
    updates.push('visible_in_gantt = ?');
    values.push(visible_in_gantt ? 1 : 0);
  }
  if (notes !== undefined) {
    updates.push('notes = ?');
    values.push(notes.substring(0, 5000)); // Limit to 5000 chars
  }

  if (updates.length === 0 && !sortOrderHandled) {
    return res.status(400).json({ error: 'Keine Änderungen angegeben' });
  }

  if (updates.length > 0) {
    values.push(id);
    db.prepare(`UPDATE sids SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  }
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

      const sidResult = db.prepare('INSERT INTO sids (landscape_id, name, system_type, is_prd, visible_in_gantt, notes, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        target_landscape_id,
        new_name,
        sourceSid.system_type || 'DEV', // Copy system_type
        sourceSid.is_prd,
        sourceSid.visible_in_gantt,
        sourceSid.notes,
        sortOrder
      );
      const targetSidId = sidResult.lastInsertRowid;

      // 2. Fetch and duplicate all activities for this SID
      const activities = db.prepare('SELECT * FROM activities WHERE sid_id = ?').all(id);

      const insertActivity = db.prepare(`
        INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, start_time, end_time, team_member_id, end_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const subActivities = db.prepare('SELECT * FROM sub_activities WHERE activity_id = ?');
      const insertSubActivity = db.prepare(`
        INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, start_time, end_time, team_member_id, sort_order, end_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
          activity.team_member_id,
          activity.end_date
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
            sub.sort_order,
            sub.end_date
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

  const { year, bundesland } = getSettingsForEndDate();
  const end_date = calculateEndDate(start_date, duration || 1, year, bundesland, !!includes_weekend);

  const result = db.prepare(`
    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, team_member_id, end_date) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(sid_id, type_id, start_date, duration || 1, includes_weekend ? 1 : 0, team_member_id || null, end_date);

  logAction(req.user.id, req.user.username, 'ACTIVITY_CREATE', { sid_id, type_id, start_date, duration });

  res.json({
    id: result.lastInsertRowid,
    sid_id,
    type: type_id,
    startDate: start_date,
    endDate: end_date,
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

  // Recompute end_date if start_date, duration, or includes_weekend changed
  if (start_date !== undefined || duration !== undefined || includes_weekend !== undefined) {
    const current = db.prepare('SELECT start_date, duration, includes_weekend FROM activities WHERE id = ?').get(id);
    if (current) {
      const effectiveStart = start_date !== undefined ? start_date : current.start_date;
      const effectiveDuration = duration !== undefined ? duration : current.duration;
      const effectiveWeekend = includes_weekend !== undefined ? !!includes_weekend : !!current.includes_weekend;
      const { year, bundesland } = getSettingsForEndDate();
      const newEndDate = calculateEndDate(effectiveStart, effectiveDuration || 1, year, bundesland, effectiveWeekend);
      updates.push('end_date = ?');
      values.push(newEndDate);
    }
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

// Archive activity
app.put('/api/activities/:id/archive', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  try {
    const activity = db.prepare('SELECT status FROM activities WHERE id = ?').get(id);
    if (!activity) return res.status(404).json({ error: 'Aktivität nicht gefunden' });

    db.prepare("UPDATE activities SET status = 'ARCHIVED' WHERE id = ?").run(id);
    logAction(req.user.id, req.user.username, 'ARCHIVE_ACTIVITY', { id });
    res.json({ success: true, message: 'Aktivität erfolgreich archiviert' });
  } catch (error) {
    console.error('Fehler beim Archivieren:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Archivieren' });
  }
});

// Unarchive activity (teamlead only)
app.put('/api/activities/:id/unarchive', authenticate, requireTeamLead, (req, res) => {
  const { id } = req.params;
  try {
    const activity = db.prepare('SELECT status FROM activities WHERE id = ?').get(id);
    if (!activity) return res.status(404).json({ error: 'Aktivität nicht gefunden' });
    if (activity.status !== 'ARCHIVED') return res.status(400).json({ error: 'Aktivität ist nicht archiviert' });

    db.prepare("UPDATE activities SET status = 'COMPLETED' WHERE id = ?").run(id);
    logAction(req.user.id, req.user.username, 'UNARCHIVE_ACTIVITY', { id });
    res.json({ success: true, message: 'Aktivität erfolgreich wiederhergestellt' });
  } catch (error) {
    console.error('Fehler beim Wiederherstellen:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Wiederherstellen' });
  }
});

// =========================================================================
// ACTIVITY SERIES ROUTES
// =========================================================================

// Helper: generate occurrence dates based on rule
function generateOccurrenceDates(ruleType, ruleValue, startDate, year, endDate) {
  const dates = [];
  const start = new Date(startDate);
  // 14-month window: Dec of previous year through Jan of next year
  const windowStart = new Date(year - 1, 11, 1); // Dec 1 of prev year
  let windowEnd = new Date(year + 1, 1, 31);   // Jan 31 of next year

  // If an end date is specified, use it as the upper bound (inclusive)
  if (endDate) {
    // Parse as UTC date and add 1 day so the end date itself is included in the range
    const endBound = new Date(endDate);
    endBound.setDate(endBound.getDate() + 1); // make it exclusive upper bound (i.e., <= endDate becomes < endDate+1)
    if (endBound < windowEnd) windowEnd = endBound;
  }

  if (ruleType === 'every_x_weeks' && ruleValue > 0) {
    let current = new Date(start);
    while (current <= windowEnd) {
      if (current >= windowStart) {
        dates.push(current.toISOString().split('T')[0]);
      }
      current.setDate(current.getDate() + ruleValue * 7);
    }
  } else if (ruleType === 'x_per_year' && ruleValue > 0) {
    // Distribute X dates evenly across the year
    const intervalDays = Math.floor(365 / ruleValue);
    let current = new Date(start);
    for (let i = 0; i < ruleValue; i++) {
      if (current >= windowStart && current <= windowEnd) {
        dates.push(current.toISOString().split('T')[0]);
      }
      current.setDate(current.getDate() + intervalDays);
    }
  }
  return dates;
}

// Create a new series
app.post('/api/series', authenticate, requireAdmin, (req, res) => {
  try {
    const { sid_id, type_id, rule_type, rule_value, rule_start_date, rule_end_date, default_start_time, default_end_time, team_member_id, year } = req.body;

    if (!sid_id || !type_id) {
      return res.status(400).json({ error: 'sid_id und type_id erforderlich' });
    }

    const result = db.prepare(
      'INSERT INTO activity_series (sid_id, type_id, rule_type, rule_value, rule_start_date, rule_end_date, default_start_time, default_end_time, team_member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(sid_id, type_id, rule_type || 'manual', rule_value || 0, rule_start_date || '', rule_end_date || '', default_start_time || '', default_end_time || '', team_member_id || null);

    const seriesId = result.lastInsertRowid;

    // Auto-generate occurrences if rule is not manual
    if (rule_type && rule_type !== 'manual' && rule_start_date) {
      const planYear = year || new Date().getFullYear();
      const dates = generateOccurrenceDates(rule_type, rule_value, rule_start_date, planYear, rule_end_date);
      const insertOcc = db.prepare('INSERT INTO series_occurrences (series_id, date, start_time, end_time, team_member_id, sort_order) VALUES (?, ?, ?, ?, ?, ?)');
      dates.forEach((date, idx) => {
        insertOcc.run(seriesId, date, default_start_time || '', default_end_time || '', team_member_id || null, idx + 1);
      });
    }

    // Return the full series with occurrences
    const series = db.prepare('SELECT * FROM activity_series WHERE id = ?').get(seriesId);
    const occurrences = db.prepare('SELECT * FROM series_occurrences WHERE series_id = ? ORDER BY date, sort_order').all(seriesId);

    logAction(req.user.id, req.user.username, 'SERIES_CREATE', { seriesId, type_id, sid_id, occurrences: occurrences.length });

    res.json({
      ...series,
      typeId: series.type_id, ruleType: series.rule_type, ruleValue: series.rule_value,
      ruleStartDate: series.rule_start_date, ruleEndDate: series.rule_end_date, defaultStartTime: series.default_start_time,
      defaultEndTime: series.default_end_time, teamMemberId: series.team_member_id,
      occurrences: occurrences.map(o => ({ ...o, includesWeekend: !!o.includes_weekend, teamMemberId: o.team_member_id }))
    });
  } catch (error) {
    console.error('Create series error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get series for a SID
app.get('/api/sids/:id/series', authenticate, (req, res) => {
  const seriesList = db.prepare('SELECT * FROM activity_series WHERE sid_id = ?').all(req.params.id);
  const result = seriesList.map(s => {
    const occurrences = db.prepare('SELECT * FROM series_occurrences WHERE series_id = ? ORDER BY date, sort_order').all(s.id);
    return {
      ...s, typeId: s.type_id, ruleType: s.rule_type, ruleValue: s.rule_value,
      ruleStartDate: s.rule_start_date, ruleEndDate: s.rule_end_date, defaultStartTime: s.default_start_time,
      defaultEndTime: s.default_end_time, teamMemberId: s.team_member_id,
      occurrences: occurrences.map(o => ({ ...o, includesWeekend: !!o.includes_weekend, teamMemberId: o.team_member_id }))
    };
  });
  res.json(result);
});

// Update series metadata
app.put('/api/series/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { type_id, rule_type, rule_value, rule_start_date, rule_end_date, default_start_time, default_end_time, team_member_id } = req.body;
    const updates = [];
    const values = [];

    if (type_id !== undefined) { updates.push('type_id = ?'); values.push(type_id); }
    if (rule_type !== undefined) { updates.push('rule_type = ?'); values.push(rule_type); }
    if (rule_value !== undefined) { updates.push('rule_value = ?'); values.push(rule_value); }
    if (rule_start_date !== undefined) { updates.push('rule_start_date = ?'); values.push(rule_start_date); }
    if (rule_end_date !== undefined) { updates.push('rule_end_date = ?'); values.push(rule_end_date); }
    if (default_start_time !== undefined) { updates.push('default_start_time = ?'); values.push(default_start_time); }
    if (default_end_time !== undefined) { updates.push('default_end_time = ?'); values.push(default_end_time); }
    if (team_member_id !== undefined) { updates.push('team_member_id = ?'); values.push(team_member_id || null); }

    if (updates.length === 0) return res.status(400).json({ error: 'Keine Änderungen' });

    values.push(id);
    db.prepare(`UPDATE activity_series SET ${updates.join(', ')} WHERE id = ?`).run(...values);

    logAction(req.user.id, req.user.username, 'SERIES_UPDATE', { seriesId: id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete series + all occurrences
app.delete('/api/series/:id', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM activity_series WHERE id = ?').run(id); // CASCADE deletes occurrences
  logAction(req.user.id, req.user.username, 'SERIES_DELETE', { seriesId: id });
  res.json({ success: true });
});

// Add one occurrence
app.post('/api/series/:id/occurrences', authenticate, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { date, start_time, end_time, includes_weekend, team_member_id } = req.body;

    if (!date) return res.status(400).json({ error: 'Datum erforderlich' });

    const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM series_occurrences WHERE series_id = ?').get(id);
    const sortOrder = (maxOrder?.max || 0) + 1;

    const result = db.prepare(
      'INSERT INTO series_occurrences (series_id, date, start_time, end_time, includes_weekend, team_member_id, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(id, date, start_time || '', end_time || '', includes_weekend ? 1 : 0, team_member_id || null, sortOrder);

    res.json({ id: result.lastInsertRowid, series_id: parseInt(id), date, start_time: start_time || '', end_time: end_time || '', includes_weekend: !!includes_weekend, teamMemberId: team_member_id || null, sort_order: sortOrder });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update one occurrence
app.put('/api/series/:id/occurrences/:occId', authenticate, requireAdmin, (req, res) => {
  try {
    const { occId } = req.params;
    const { date, start_time, end_time, includes_weekend, team_member_id } = req.body;
    const updates = [];
    const values = [];

    if (date !== undefined) { updates.push('date = ?'); values.push(date); }
    if (start_time !== undefined) { updates.push('start_time = ?'); values.push(start_time); }
    if (end_time !== undefined) { updates.push('end_time = ?'); values.push(end_time); }
    if (includes_weekend !== undefined) { updates.push('includes_weekend = ?'); values.push(includes_weekend ? 1 : 0); }
    if (team_member_id !== undefined) { updates.push('team_member_id = ?'); values.push(team_member_id || null); }

    if (updates.length === 0) return res.status(400).json({ error: 'Keine Änderungen' });

    values.push(occId);
    db.prepare(`UPDATE series_occurrences SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Archive occurrence
app.put('/api/series/:id/occurrences/:occId/archive', authenticate, requireAdmin, (req, res) => {
  const { id, occId } = req.params;
  try {
    const occ = db.prepare('SELECT status FROM series_occurrences WHERE id = ? AND series_id = ?').get(occId, id);
    if (!occ) return res.status(404).json({ error: 'Begebenheit nicht gefunden' });

    db.prepare("UPDATE series_occurrences SET status = 'ARCHIVED' WHERE id = ?").run(occId);
    logAction(req.user.id, req.user.username, 'ARCHIVE_OCCURRENCE', { occId, seriesId: id });
    res.json({ success: true, message: 'Termin erfolgreich archiviert' });
  } catch (error) {
    console.error('Fehler beim Archivieren:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Archivieren' });
  }
});

// Unarchive occurrence (teamlead only)
app.put('/api/series/:id/occurrences/:occId/unarchive', authenticate, requireTeamLead, (req, res) => {
  const { id, occId } = req.params;
  try {
    const occ = db.prepare('SELECT status FROM series_occurrences WHERE id = ? AND series_id = ?').get(occId, id);
    if (!occ) return res.status(404).json({ error: 'Begebenheit nicht gefunden' });
    if (occ.status !== 'ARCHIVED') return res.status(400).json({ error: 'Begebenheit ist nicht archiviert' });

    db.prepare("UPDATE series_occurrences SET status = 'COMPLETED' WHERE id = ?").run(occId);
    logAction(req.user.id, req.user.username, 'UNARCHIVE_OCCURRENCE', { occId, seriesId: id });
    res.json({ success: true, message: 'Termin erfolgreich wiederhergestellt' });
  } catch (error) {
    console.error('Fehler beim Wiederherstellen:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Wiederherstellen' });
  }
});

// Delete one occurrence
app.delete('/api/series/:id/occurrences/:occId', authenticate, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM series_occurrences WHERE id = ?').run(req.params.occId);
  res.json({ success: true });
});

// Re-generate occurrences from rule
app.post('/api/series/:id/generate', authenticate, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { year, end_date } = req.body;
    const series = db.prepare('SELECT * FROM activity_series WHERE id = ?').get(id);
    if (!series) return res.status(404).json({ error: 'Serie nicht gefunden' });

    if (series.rule_type === 'manual') {
      return res.status(400).json({ error: 'Manuelle Serien können nicht automatisch generiert werden' });
    }

    // Delete existing occurrences
    db.prepare('DELETE FROM series_occurrences WHERE series_id = ?').run(id);

    // Generate new ones — prefer end_date from request body, fallback to DB value
    const planYear = year || new Date().getFullYear();
    const effectiveEndDate = end_date !== undefined ? end_date : series.rule_end_date;
    const dates = generateOccurrenceDates(series.rule_type, series.rule_value, series.rule_start_date, planYear, effectiveEndDate);
    const insertOcc = db.prepare('INSERT INTO series_occurrences (series_id, date, start_time, end_time, team_member_id, sort_order) VALUES (?, ?, ?, ?, ?, ?)');
    dates.forEach((date, idx) => {
      insertOcc.run(id, date, series.default_start_time || '', series.default_end_time || '', series.team_member_id || null, idx + 1);
    });

    const occurrences = db.prepare('SELECT * FROM series_occurrences WHERE series_id = ? ORDER BY date, sort_order').all(id);
    logAction(req.user.id, req.user.username, 'SERIES_REGENERATE', { seriesId: id, count: occurrences.length });

    res.json({ success: true, occurrences: occurrences.map(o => ({ ...o, includesWeekend: !!o.includes_weekend, teamMemberId: o.team_member_id })) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Convert existing activity → series
app.post('/api/series/convert', authenticate, requireAdmin, (req, res) => {
  try {
    const { activity_id, sid_id } = req.body;
    if (!activity_id || !sid_id) return res.status(400).json({ error: 'activity_id und sid_id erforderlich' });

    const activity = db.prepare('SELECT * FROM activities WHERE id = ?').get(activity_id);
    if (!activity) return res.status(404).json({ error: 'Aktivität nicht gefunden' });

    // Create series from the activity
    const result = db.prepare(
      'INSERT INTO activity_series (sid_id, type_id, rule_type, rule_value, rule_start_date, rule_end_date, default_start_time, default_end_time, team_member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(sid_id, activity.type_id, 'manual', 0, activity.start_date, '', activity.start_time || '', activity.end_time || '', activity.team_member_id || null);

    const seriesId = result.lastInsertRowid;

    // Create first occurrence from the activity
    db.prepare(
      'INSERT INTO series_occurrences (series_id, date, start_time, end_time, includes_weekend, team_member_id, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(seriesId, activity.start_date, activity.start_time || '', activity.end_time || '', activity.includes_weekend ? 1 : 0, activity.team_member_id || null, 1);

    // Delete the original activity
    db.prepare('DELETE FROM activities WHERE id = ?').run(activity_id);

    // Return the new series
    const series = db.prepare('SELECT * FROM activity_series WHERE id = ?').get(seriesId);
    const occurrences = db.prepare('SELECT * FROM series_occurrences WHERE series_id = ? ORDER BY date').all(seriesId);

    logAction(req.user.id, req.user.username, 'SERIES_CONVERT', { activityId: activity_id, seriesId });

    res.json({
      ...series,
      typeId: series.type_id, ruleType: series.rule_type, ruleValue: series.rule_value,
      ruleStartDate: series.rule_start_date, ruleEndDate: series.rule_end_date, defaultStartTime: series.default_start_time,
      defaultEndTime: series.default_end_time, teamMemberId: series.team_member_id,
      occurrences: occurrences.map(o => ({ ...o, includesWeekend: !!o.includes_weekend, teamMemberId: o.team_member_id }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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

  const { year, bundesland } = getSettingsForEndDate();
  const end_date = calculateEndDate(start_date, duration || 1, year, bundesland, !!includes_weekend);

  const result = db.prepare(`
    INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, sort_order, team_member_id, end_date) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(activity_id, name || 'Sub-Aktivität', start_date, duration || 1, includes_weekend ? 1 : 0, sortOrder, team_member_id || null, end_date);

  logAction(req.user.id, req.user.username, 'SUBACTIVITY_CREATE', { activity_id, name, start_date, duration });

  res.json({
    id: result.lastInsertRowid,
    activity_id,
    name: name || 'Sub-Aktivität',
    startDate: start_date,
    endDate: end_date,
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

  // Recompute end_date if start_date, duration, or includes_weekend changed
  if (start_date !== undefined || duration !== undefined || includes_weekend !== undefined) {
    const current = db.prepare('SELECT start_date, duration, includes_weekend FROM sub_activities WHERE id = ?').get(id);
    if (current) {
      const effectiveStart = start_date !== undefined ? start_date : current.start_date;
      const effectiveDuration = duration !== undefined ? duration : current.duration;
      const effectiveWeekend = includes_weekend !== undefined ? !!includes_weekend : !!current.includes_weekend;
      const { year, bundesland } = getSettingsForEndDate();
      const newEndDate = calculateEndDate(effectiveStart, effectiveDuration || 1, year, bundesland, effectiveWeekend);
      updates.push('end_date = ?');
      values.push(newEndDate);
    }
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

// Archive sub-activity
app.put('/api/sub-activities/:id/archive', authenticate, requireAdmin, (req, res) => {
  const { id } = req.params;
  try {
    const subActivity = db.prepare('SELECT status FROM sub_activities WHERE id = ?').get(id);
    if (!subActivity) return res.status(404).json({ error: 'Sub-Aktivität nicht gefunden' });

    db.prepare("UPDATE sub_activities SET status = 'ARCHIVED' WHERE id = ?").run(id);
    logAction(req.user.id, req.user.username, 'ARCHIVE_SUBACTIVITY', { id });
    res.json({ success: true, message: 'Sub-Aktivität erfolgreich archiviert' });
  } catch (error) {
    console.error('Fehler beim Archivieren:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Archivieren' });
  }
});

// Unarchive sub-activity (teamlead only)
app.put('/api/sub-activities/:id/unarchive', authenticate, requireTeamLead, (req, res) => {
  const { id } = req.params;
  try {
    const subActivity = db.prepare('SELECT status FROM sub_activities WHERE id = ?').get(id);
    if (!subActivity) return res.status(404).json({ error: 'Sub-Aktivität nicht gefunden' });
    if (subActivity.status !== 'ARCHIVED') return res.status(400).json({ error: 'Sub-Aktivität ist nicht archiviert' });

    db.prepare("UPDATE sub_activities SET status = 'COMPLETED' WHERE id = ?").run(id);
    logAction(req.user.id, req.user.username, 'UNARCHIVE_SUBACTIVITY', { id });
    res.json({ success: true, message: 'Sub-Aktivität erfolgreich wiederhergestellt' });
  } catch (error) {
    console.error('Fehler beim Wiederherstellen:', error);
    res.status(500).json({ error: 'Datenbankfehler beim Wiederherstellen' });
  }
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

  if (user_id) {
    const user = db.prepare('SELECT username, first_name, last_name, abbreviation FROM users WHERE id = ?').get(user_id);
    if (!user) {
      return res.status(400).json({ error: 'Benutzer nicht gefunden' });
    }
    name = (user.first_name || user.last_name) ? `${user.first_name} ${user.last_name}`.trim() : user.username;
    // Use abbreviation from user record (auto-generated at user creation)
    abbreviation = user.abbreviation || abbreviation || name.substring(0, 2).toUpperCase();
    // Sync abbreviation back to user record if missing
    if (!user.abbreviation && abbreviation) {
      db.prepare('UPDATE users SET abbreviation = ? WHERE id = ?').run(abbreviation, user_id);
    }
  } else if (!name) {
    return res.status(400).json({ error: 'Name oder Benutzer erforderlich' });
  }

  if (!abbreviation) {
    return res.status(400).json({ error: 'Kürzel konnte nicht ermittelt werden' });
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM team_members').get();
  const sortOrder = (maxOrder.max || 0) + 1;

  try {
    const result = db.prepare('INSERT INTO team_members (name, abbreviation, sort_order, working_days, training_days, to_plan_days, weekly_hours) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      name,
      abbreviation,
      sortOrder,
      working_days || 0,
      training_days || 0,
      to_plan_days || 0,
      req.body.weekly_hours !== undefined ? req.body.weekly_hours : 40
    );
    logAction(req.user.id, req.user.username, 'TEAM_MEMBER_CREATE', { name, abbreviation });
    res.json({
      id: result.lastInsertRowid,
      name,
      abbreviation,
      sort_order: sortOrder,
      working_days: working_days || 0,
      training_days: training_days || 0,
      to_plan_days: to_plan_days || 0,
      weekly_hours: req.body.weekly_hours !== undefined ? req.body.weekly_hours : 40
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
  if (req.body.weekly_hours !== undefined) {
    updates.push('weekly_hours = ?');
    values.push(parseFloat(req.body.weekly_hours) || 40);
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

app.get('/api/users', authenticate, requireAdmin, (req, res) => {
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
    // Teamlead can create admin, user, teamlead, or viewer
    if (!['admin', 'user', 'teamlead', 'viewer', 'projekt'].includes(targetRole)) {
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

  // Auto-generate 3-letter abbreviation: first letter of Vorname + first + last letter of Nachname
  const genAbbreviation = (fn, ln) => {
    const f = (fn || '').trim().toUpperCase();
    const l = (ln || '').trim().toUpperCase();
    if (!f || !l) return '';
    return (f[0] + l[0] + l[l.length - 1]).toUpperCase();
  };
  const abbreviation = genAbbreviation(first_name, last_name);

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash, role, created_by, must_change_password, first_name, last_name, abbreviation) VALUES (?, ?, ?, ?, 1, ?, ?, ?)').run(
      username,
      passwordHash,
      targetRole,
      req.user.id,
      first_name || '',
      last_name || '',
      abbreviation
    );
    res.json({ id: result.lastInsertRowid, username, first_name, last_name, abbreviation, role: targetRole, created_by: req.user.id });
  } catch (error) {
    if (error.message && error.message.includes('UNIQUE constraint')) {
      res.status(400).json({ error: 'Benutzername existiert bereits' });
    } else {
      res.status(400).json({ error: error.message || 'Fehler beim Erstellen des Benutzers' });
    }
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

  // Security check: Admins cannot modify teamleads & original teamlead cannot be modified by other teamleads
  if (password !== undefined || role !== undefined) {
    const targetUser = db.prepare('SELECT username, role FROM users WHERE id = ?').get(id);
    if (targetUser) {
      if (targetUser.role === 'teamlead' && req.user.role !== 'teamlead') {
        return res.status(403).json({ error: 'Admins können keine Teamleiter bearbeiten' });
      }
      if (targetUser.username === 'teamlead' && req.user.username !== 'teamlead') {
        return res.status(403).json({ error: 'Der System-Teamleiter kann nicht von anderen Teamleitern bearbeitet werden' });
      }
    }
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
    // Only teamlead can change roles
    if (req.user.role !== 'teamlead') {
      return res.status(403).json({ error: 'Nur Teamleiter können Rollen ändern' });
    }
    if (!['admin', 'user', 'teamlead', 'viewer', 'projekt'].includes(role)) {
      return res.status(400).json({ error: 'Ungültige Rolle' });
    }
    updates.push('role = ?');
    values.push(role);
  }

  const { first_name, last_name } = req.body;
  if ((first_name !== undefined || last_name !== undefined) && req.user.role !== 'teamlead') {
    return res.status(403).json({ error: 'Nur Teamleiter können Benutzerdaten ändern' });
  }
  if (first_name !== undefined) {
    updates.push('first_name = ?');
    values.push(first_name);
  }
  if (last_name !== undefined) {
    updates.push('last_name = ?');
    values.push(last_name);
  }

  // Auto-recompute abbreviation when name changes
  if (first_name !== undefined || last_name !== undefined) {
    const currentUser = db.prepare('SELECT first_name, last_name, username FROM users WHERE id = ?').get(id);
    const fn = (first_name !== undefined ? first_name : (currentUser?.first_name || '')).trim().toUpperCase();
    const ln = (last_name !== undefined ? last_name : (currentUser?.last_name || '')).trim().toUpperCase();
    if (fn && ln) {
      const newAbbr = fn[0] + ln[0] + ln[ln.length - 1];
      updates.push('abbreviation = ?');
      values.push(newAbbr);
      // Sync abbreviation to team_members if a matching member exists
      const memberName = `${first_name !== undefined ? first_name : currentUser?.first_name || ''} ${last_name !== undefined ? last_name : currentUser?.last_name || ''}`.trim();
      if (memberName) {
        db.prepare('UPDATE team_members SET abbreviation = ? WHERE LOWER(name) = LOWER(?)').run(newAbbr, memberName);
      }
    }
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
  const targetUser = db.prepare('SELECT id, username, role, created_by FROM users WHERE id = ?').get(targetId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Benutzer nicht gefunden' });
  }

  // The original system 'teamlead' user cannot be deleted by anyone
  if (targetUser.username === 'teamlead') {
    return res.status(403).json({ error: 'Der System-Teamleiter kann nicht gelöscht werden' });
  }

  // Role-based deletion restrictions
  if (req.user.role === 'teamlead') {
    // Teamlead can delete admin, user, viewer, or other teamlead users
    // (self-deletion and system teamlead deletion are blocked above)
  } else if (req.user.role === 'admin') {
    // Admin can only delete users and viewers (not admins or teamleads)
    if (targetUser.role !== 'user' && targetUser.role !== 'viewer') {
      return res.status(403).json({ error: 'Admins können nur Benutzer und Viewer löschen' });
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
              db.prepare(`
                INSERT INTO sids (landscape_id, name, system_type, is_prd, visible_in_gantt, sort_order) 
                VALUES (?, ?, ?, ?, ?, ?)
              `).run(
                newLandscapeId,
                sid.name || '',
                sid.systemType || (sid.isPRD ? 'PRD' : 'DEV'), // Use systemType if available, otherwise derive from isPRD
                sid.isPRD ? 1 : 0,
                sid.visibleInGantt !== false ? 1 : 0, // Default to true
                sidIndex
              );
              const newSidId = sidResult.lastInsertRowid;

              if (sid.activities && Array.isArray(sid.activities)) {
                const { year: settingsYear, bundesland: settingsBL } = getSettingsForEndDate();
                sid.activities.forEach(activity => {
                  const actStartDate = activity.startDate;
                  const actDuration = activity.duration || 1;
                  const actWeekend = !!activity.includesWeekend;
                  const actEndDate = calculateEndDate(actStartDate, actDuration, settingsYear, settingsBL, actWeekend);
                  db.prepare(`
                    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, end_date) 
                    VALUES (?, ?, ?, ?, ?, ?)
                  `).run(
                    newSidId,
                    activity.type,
                    actStartDate,
                    actDuration,
                    actWeekend ? 1 : 0,
                    actEndDate
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
          name: sid.name,
          isPRD: sid.system_type === 'PRD',
          systemType: sid.system_type || 'DEV',
          visibleInGantt: !!sid.visible_in_gantt,
          activities: activitiesWithSubs
        };
      });
      return {
        ...landscape,
        sids: sidsWithActivities
      };
    });

    // Get matrix columns (Skills)
    const matrixColumns = db.prepare('SELECT * FROM matrix_columns ORDER BY sort_order').all();

    // Get matrix values (Qualifikationen)
    const matrixValues = db.prepare('SELECT * FROM matrix_values').all();

    // Get trainings (Schulungen)
    const trainings = db.prepare('SELECT * FROM trainings ORDER BY id').all();

    // Get bereitschaft (on-call schedule) — store abbreviation only, not user_id
    const bereitschaftData = db.prepare('SELECT week_start, abbreviation FROM bereitschaft ORDER BY week_start').all();

    // Get user SID visibility preferences
    const userSidVisibility = db.prepare('SELECT * FROM user_sid_visibility').all();

    const backup = {
      version: APP_VERSION,
      exportDate: new Date().toISOString(),
      settings: settingsObj,
      activityTypes,
      teamMembers,
      maintenanceSundays,
      landscapes: landscapesWithData,
      matrixColumns,
      matrixValues,
      trainings,
      bereitschaft: bereitschaftData,
      userSidVisibility
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
      subActivities: 0,
      matrixColumns: 0,
      matrixValues: 0,
      trainings: 0,
      bereitschaft: 0,
      userSidVisibility: 0
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
                INSERT INTO sids (landscape_id, name, system_type, is_prd, visible_in_gantt, notes, sort_order) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
              `).run(
                newLandscapeId,
                sid.name || '',
                sid.systemType || (sid.isPRD ? 'PRD' : 'DEV'), // Use systemType if available, otherwise derive from isPRD
                sid.isPRD || sid.systemType === 'PRD' ? 1 : 0, // Keep is_prd in sync
                (sid.visibleInGantt ?? sid.visible_in_gantt ?? true) ? 1 : 0,
                sid.notes || '',
                sid.sort_order ?? sidIndex
              );
              const newSidId = sidResult.lastInsertRowid;
              stats.sids++;

              if (sid.activities && Array.isArray(sid.activities)) {
                const { year: settingsYear, bundesland: settingsBL } = getSettingsForEndDate();
                sid.activities.forEach(activity => {
                  const teamMemberId = activity.teamMemberId || activity.team_member_id;
                  const actStartDate = activity.startDate || activity.start_date;
                  const actDuration = activity.duration || 1;
                  const actWeekend = !!(activity.includesWeekend || activity.includes_weekend);
                  const actEndDate = activity.endDate || activity.end_date || calculateEndDate(actStartDate, actDuration, settingsYear, settingsBL, actWeekend);
                  const activityResult = db.prepare(`
                    INSERT INTO activities (sid_id, type_id, start_date, duration, includes_weekend, team_member_id, start_time, end_time, end_date) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                  `).run(
                    newSidId,
                    activity.type || activity.type_id,
                    actStartDate,
                    actDuration,
                    actWeekend ? 1 : 0,
                    teamMemberMap.has(teamMemberId) ? teamMemberId : null,
                    activity.start_time || null,
                    activity.end_time || null,
                    actEndDate
                  );
                  const newActivityId = activityResult.lastInsertRowid;
                  stats.activities++;

                  if (activity.subActivities && Array.isArray(activity.subActivities)) {
                    activity.subActivities.forEach((sub, subIndex) => {
                      const subTeamMemberId = sub.teamMemberId || sub.team_member_id;
                      const subStartDate = sub.startDate || sub.start_date;
                      const subDuration = sub.duration || 1;
                      const subWeekend = !!(sub.includesWeekend || sub.includes_weekend);
                      const subEndDate = sub.endDate || sub.end_date || calculateEndDate(subStartDate, subDuration, settingsYear, settingsBL, subWeekend);
                      db.prepare(`
                        INSERT INTO sub_activities (activity_id, name, start_date, duration, includes_weekend, sort_order, team_member_id, start_time, end_time, end_date) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `).run(
                        newActivityId,
                        sub.name || 'Sub-Aktivität',
                        subStartDate,
                        subDuration,
                        subWeekend ? 1 : 0,
                        sub.sort_order ?? subIndex,
                        teamMemberMap.has(subTeamMemberId) ? subTeamMemberId : null,
                        sub.start_time || null,
                        sub.end_time || null,
                        subEndDate
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

      // 6. Import matrix columns (skills)
      if (backup.matrixColumns && Array.isArray(backup.matrixColumns)) {
        db.prepare('DELETE FROM matrix_values').run();
        db.prepare('DELETE FROM matrix_columns').run();

        const insertCol = db.prepare('INSERT INTO matrix_columns (id, name, sort_order) VALUES (?, ?, ?)');
        backup.matrixColumns.forEach((col, index) => {
          insertCol.run(col.id, col.name, col.sort_order ?? index);
          stats.matrixColumns++;
        });
      }

      // 7. Import matrix values (qualifications)
      if (backup.matrixValues && Array.isArray(backup.matrixValues)) {
        // matrix_values may already be deleted in step 6, but be safe
        if (!backup.matrixColumns) {
          db.prepare('DELETE FROM matrix_values').run();
        }

        const insertVal = db.prepare('INSERT OR REPLACE INTO matrix_values (team_member_id, column_id, level) VALUES (?, ?, ?)');
        backup.matrixValues.forEach(val => {
          insertVal.run(val.team_member_id, val.column_id, val.level || 0);
          stats.matrixValues++;
        });
      }

      // 8. Import trainings
      if (backup.trainings && Array.isArray(backup.trainings)) {
        db.prepare('DELETE FROM trainings').run();

        const insertTraining = db.prepare(`
          INSERT INTO trainings (participants, course, topic, cost, location, date1, date2, date3, days, booked_date)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        backup.trainings.forEach(tr => {
          insertTraining.run(
            tr.participants || '',
            tr.course || '',
            tr.topic || '',
            tr.cost || '',
            tr.location || '',
            tr.date1 || '',
            tr.date2 || '',
            tr.date3 || '',
            tr.days || 0,
            tr.booked_date || 0
          );
          stats.trainings++;
        });
      }

      // 9. Import bereitschaft (on-call schedule) — without user_id
      if (backup.bereitschaft && Array.isArray(backup.bereitschaft)) {
        db.prepare('DELETE FROM bereitschaft').run();

        const insertBereitschaft = db.prepare('INSERT INTO bereitschaft (week_start, abbreviation) VALUES (?, ?)');
        backup.bereitschaft.forEach(entry => {
          insertBereitschaft.run(entry.week_start, entry.abbreviation || '');
          stats.bereitschaft++;
        });
      }

      // 10. Import user SID visibility
      if (backup.userSidVisibility && Array.isArray(backup.userSidVisibility)) {
        db.prepare('DELETE FROM user_sid_visibility').run();

        const insertVis = db.prepare('INSERT INTO user_sid_visibility (user_id, sid_id, visible) VALUES (?, ?, ?)');
        backup.userSidVisibility.forEach(vis => {
          try {
            insertVis.run(vis.user_id, vis.sid_id, vis.visible ?? 1);
            stats.userSidVisibility++;
          } catch (e) {
            // Skip entries with non-existing user/sid references
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
      INSERT INTO trainings (participants, course, topic, cost, location, date1, date2, date3, days, booked_date)
      VALUES ('', 'Neuer Kurs', '', '', '', '', '', '', 0, 0)
    `).run();

    logAction(req.user.id, req.user.username, 'CREATE_TRAINING', { trainingId: result.lastInsertRowid });
    res.json({ id: result.lastInsertRowid, course: 'Neuer Kurs', participants: '', topic: '', cost: '', location: '', date1: '', date2: '', date3: '', days: 0, booked_date: 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Training
app.put('/api/trainings/:id', authenticate, requireAdmin, (req, res) => {
  try {
    const { participants, course, topic, cost, location, date1, date2, date3, days, booked_date } = req.body;

    if (booked_date !== undefined && req.user.role !== 'teamlead') {
      return res.status(403).json({ error: 'Nur Teamleiter können Schulungen bestätigen' });
    }

    // Dynamically build the update query to only update provided fields
    const updates = [];
    const params = [];

    const fields = { participants, course, topic, cost, location, date1, date2, date3, days, booked_date };

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
app.delete('/api/trainings/:id', authenticate, requireTeamLead, (req, res) => {
  try {
    db.prepare('DELETE FROM trainings WHERE id = ?').run(req.params.id);
    logAction(req.user.id, req.user.username, 'DELETE_TRAINING', { trainingId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =========================================================================
// API: BEREITSCHAFT
// =========================================================================

// Get Bereitschaft
app.get('/api/bereitschaft', authenticate, (req, res) => {
  try {
    const data = db.prepare('SELECT week_start, user_id, abbreviation FROM bereitschaft ORDER BY week_start ASC').all();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Claim Bereitschaft Week
app.post('/api/bereitschaft', authenticate, requireWriteAccess, (req, res) => {
  try {
    const { week_start } = req.body;
    if (!week_start) return res.status(400).json({ error: 'week_start is required' });

    // Ensure it's not already claimed
    const existing = db.prepare('SELECT * FROM bereitschaft WHERE week_start = ?').get(week_start);
    if (existing) {
      return res.status(400).json({ error: 'Diese Woche ist bereits belegt.' });
    }

    db.prepare('INSERT INTO bereitschaft (week_start, user_id, abbreviation) VALUES (?, ?, ?)').run(
      week_start,
      req.user.id,
      req.user.abbreviation || req.user.username
    );

    logAction(req.user.id, req.user.username, 'CLAIM_BEREITSCHAFT', { week_start });
    res.json({ success: true, week_start, user_id: req.user.id, abbreviation: req.user.abbreviation || req.user.username });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Bereitschaft Claim
app.delete('/api/bereitschaft/:week_start', authenticate, requireWriteAccess, (req, res) => {
  try {
    const { week_start } = req.params;

    const existing = db.prepare('SELECT user_id FROM bereitschaft WHERE week_start = ?').get(week_start);
    if (!existing) {
      return res.status(404).json({ error: 'Nicht gefunden' });
    }

    // Only teamlead can delete anyone's, normal users can only delete their own
    if (req.user.role !== 'teamlead' && existing.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Sie dürfen nur Ihre eigenen Bereitschaften löschen.' });
    }

    db.prepare('DELETE FROM bereitschaft WHERE week_start = ?').run(week_start);
    logAction(req.user.id, req.user.username, 'DELETE_BEREITSCHAFT', { week_start });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =========================================================================
// API: URLAUB (VACATION PLANNING)
// =========================================================================

// Get all vacation entries
app.get('/api/urlaub', authenticate, (req, res) => {
  try {
    // Viewers should not access this endpoint
    if (req.user.role === 'viewer') {
      return res.status(403).json({ error: 'Kein Zugriff für Viewer' });
    }
    const data = db.prepare(`
      SELECT u.id, u.user_id, u.start_date, u.end_date,
             usr.abbreviation, usr.username
      FROM urlaub u
      JOIN users usr ON u.user_id = usr.id
      ORDER BY u.start_date ASC
    `).all();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create vacation entry
app.post('/api/urlaub', authenticate, requireWriteAccess, (req, res) => {
  try {
    if (req.user.role === 'viewer') {
      return res.status(403).json({ error: 'Kein Zugriff für Viewer' });
    }

    const { start_date, end_date, user_id } = req.body;
    if (!start_date || !end_date) {
      return res.status(400).json({ error: 'start_date und end_date sind erforderlich' });
    }
    if (end_date < start_date) {
      return res.status(400).json({ error: 'end_date darf nicht vor start_date liegen' });
    }

    // Determine target user
    let targetUserId = req.user.id;
    if (user_id && user_id !== req.user.id) {
      // Only teamlead may create vacation for other users
      if (req.user.role !== 'teamlead') {
        return res.status(403).json({ error: 'Nur Teamleads dürfen Urlaub für andere Benutzer eintragen.' });
      }
      targetUserId = user_id;
    }

    // Check for overlapping vacations for same user
    const overlap = db.prepare(`
      SELECT id FROM urlaub
      WHERE user_id = ? AND start_date <= ? AND end_date >= ?
    `).get(targetUserId, end_date, start_date);
    if (overlap) {
      return res.status(400).json({ error: 'Es gibt bereits einen überlappenden Urlaubseintrag für diesen Benutzer.' });
    }

    const result = db.prepare('INSERT INTO urlaub (user_id, start_date, end_date) VALUES (?, ?, ?)').run(
      targetUserId, start_date, end_date
    );

    // Fetch the created entry with user details
    const entry = db.prepare(`
      SELECT u.id, u.user_id, u.start_date, u.end_date,
             usr.abbreviation, usr.username
      FROM urlaub u
      JOIN users usr ON u.user_id = usr.id
      WHERE u.id = ?
    `).get(result.lastInsertRowid);

    logAction(req.user.id, req.user.username, 'CREATE_URLAUB', {
      targetUserId, start_date, end_date
    });
    res.json(entry);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete vacation entry
app.delete('/api/urlaub/:id', authenticate, requireWriteAccess, (req, res) => {
  try {
    if (req.user.role === 'viewer') {
      return res.status(403).json({ error: 'Kein Zugriff für Viewer' });
    }

    const entry = db.prepare('SELECT * FROM urlaub WHERE id = ?').get(req.params.id);
    if (!entry) {
      return res.status(404).json({ error: 'Urlaubseintrag nicht gefunden' });
    }

    // Only teamlead can delete anyone's, others can only delete their own
    if (req.user.role !== 'teamlead' && entry.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Sie dürfen nur Ihre eigenen Urlaubseinträge löschen.' });
    }

    db.prepare('DELETE FROM urlaub WHERE id = ?').run(req.params.id);
    logAction(req.user.id, req.user.username, 'DELETE_URLAUB', {
      urlaubId: req.params.id,
      targetUserId: entry.user_id,
      start_date: entry.start_date,
      end_date: entry.end_date
    });
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
║   Standard-Login: teamlead (Passwort später ändern!)          ║
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
║   Standard-Login: teamlead (Passwort später ändern!)          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    `);
  });
};


if (process.env.NODE_ENV === 'test') {
  // In test mode: database is already initialized above.
  // Tests import { app, db } and use supertest directly.
  module.exports = { app, db };
} else {
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
}
