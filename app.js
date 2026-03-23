"use strict";

const {
  useState,
  useEffect,
  useMemo,
  useCallback
} = React;
const SYSTEM_TYPES = ['PRD', 'PPRD', 'QAS', 'TST', 'DEV', 'SBX', 'TRN'];
const isPRDSystem = sid => sid?.systemType === 'PRD' || sid?.isPRD;
const getSystemTypeColor = type => {
  switch (type) {
    case 'PRD':
      return 'bg-red-600 text-white font-bold shadow-sm';
    case 'PPRD':
      return 'bg-orange-500 text-white shadow-sm';
    case 'QAS':
      return 'bg-purple-600 text-white shadow-sm';
    case 'TST':
      return 'bg-yellow-500 text-white shadow-sm';
    case 'TRN':
      return 'bg-emerald-600 text-white shadow-sm';
    case 'SBX':
      return 'bg-stone-500 text-white shadow-sm';
    case 'DEV':
    default:
      return 'bg-blue-600 text-white shadow-sm';
  }
};

// =========================================================================
// API CLIENT
// =========================================================================

class ApiClient {
  constructor() {
    // Token is managed via HttpOnly cookie

    // Configuration: API Base URL
    // Leave empty ('') if frontend and backend run on the same server (default).
    // If running strictly as client (file:// or different server), set the full URL.

    // BEFORE (local development):
    // this.baseUrl = 'http://localhost:3232';

    // AFTER (production):
    // this.baseUrl = 'http://YOUR_SERVER_IP:3232';
    // Example:
    // this.baseUrl = 'http://192.168.1.100:3232';
    // Or with hostname:
    // this.baseUrl = 'http://sap-planner.yourcompany.local:3232';

    this.baseUrl = '';
  }
  setToken(token) {
    // No-op: Token is set by server via HttpOnly cookie
  }
  async request(endpoint, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    // Authorization header is no longer needed (cookie is sent automatically)

    const url = `${this.baseUrl}${endpoint}`;
    console.log(`[API] Fetching: ${url}`, options);
    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include'
      });
      let data;
      const text = await response.text();
      try {
        data = text ? JSON.parse(text) : {};
      } catch (e) {
        // Handle plain text responses (like 429 Too Many Requests)
        data = {
          error: text.length > 150 ? text.substring(0, 150) + '...' : text
        };
      }
      console.log(`[API] Response from ${endpoint}:`, data);
      if (response.status === 401) {
        if (!endpoint.includes('/login')) {
          throw new Error('SESSION_EXPIRED');
        }
        throw new Error(data.error || 'Ungültige Anmeldedaten');
      }
      if (!response.ok) {
        throw new Error(data.error || `API Fehler (${response.status})`);
      }
      return data;
    } catch (error) {
      console.error(`[API] Error on ${endpoint}:`, error);
      throw error;
    }
  }

  // Auth
  async login(username, password) {
    // Token is set as HttpOnly cookie by server
    const data = await this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    });
    return {
      ...data.user,
      version: data.user.version || data.version
    };
  }
  async logout() {
    try {
      await this.request('/api/auth/logout', {
        method: 'POST'
      });
    } catch {}
    // Server clears cookie
  }
  async getMe() {
    return this.request('/api/auth/me');
  }
  async changePassword(currentPassword, newPassword) {
    return this.request('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword,
        newPassword
      })
    });
  }

  // Settings
  async getSettings() {
    return this.request('/api/settings');
  }
  async updateSettings(settings) {
    return this.request('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings)
    });
  }

  // Activity Types
  async getActivityTypes() {
    return this.request('/api/activity-types');
  }
  async createActivityType(type) {
    return this.request('/api/activity-types', {
      method: 'POST',
      body: JSON.stringify(type)
    });
  }
  async updateActivityType(id, data) {
    return this.request(`/api/activity-types/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteActivityType(id) {
    return this.request(`/api/activity-types/${id}`, {
      method: 'DELETE'
    });
  }

  // Landscapes
  async getLandscapes() {
    return this.request('/api/landscapes');
  }
  async createLandscape(name) {
    return this.request('/api/landscapes', {
      method: 'POST',
      body: JSON.stringify({
        name
      })
    });
  }
  async updateLandscape(id, data) {
    return this.request(`/api/landscapes/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteLandscape(id) {
    return this.request(`/api/landscapes/${id}`, {
      method: 'DELETE'
    });
  }

  // SID Locking
  async acquireLock(id) {
    return this.request(`/api/sids/${id}/lock`, {
      method: 'POST'
    });
  }
  async releaseLock(id) {
    return this.request(`/api/sids/${id}/lock`, {
      method: 'DELETE'
    });
  }
  async getLocks() {
    return this.request('/api/sids/locks');
  }

  // SIDs
  async createSid(landscape_id, name, systemType, visible_in_gantt) {
    return this.request('/api/sids', {
      method: 'POST',
      body: JSON.stringify({
        landscape_id,
        name,
        systemType,
        visible_in_gantt
      })
    });
  }
  async updateSid(id, data) {
    return this.request(`/api/sids/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteSid(id) {
    return this.request(`/api/sids/${id}`, {
      method: 'DELETE'
    });
  }
  async copySid(id, target_landscape_id, new_name) {
    return this.request(`/api/sids/${id}/copy`, {
      method: 'POST',
      body: JSON.stringify({
        target_landscape_id,
        new_name
      })
    });
  }

  // Activities
  async createActivity(data) {
    return this.request('/api/activities', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateActivity(id, data) {
    return this.request(`/api/activities/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteActivity(id) {
    return this.request(`/api/activities/${id}`, {
      method: 'DELETE'
    });
  }
  async archiveActivity(id) {
    return this.request(`/api/activities/${id}/archive`, {
      method: 'PUT'
    });
  }

  // Sub-Activities
  async createSubActivity(data) {
    return this.request('/api/sub-activities', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateSubActivity(id, data) {
    return this.request(`/api/sub-activities/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteSubActivity(id) {
    return this.request(`/api/sub-activities/${id}`, {
      method: 'DELETE'
    });
  }
  async archiveSubActivity(id) {
    return this.request(`/api/sub-activities/${id}/archive`, {
      method: 'PUT'
    });
  }

  // Activity Series
  async createSeries(data) {
    return this.request('/api/series', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateSeries(id, data) {
    return this.request(`/api/series/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteSeries(id) {
    return this.request(`/api/series/${id}`, {
      method: 'DELETE'
    });
  }
  async createOccurrence(seriesId, data) {
    return this.request(`/api/series/${seriesId}/occurrences`, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateOccurrence(seriesId, occId, data) {
    return this.request(`/api/series/${seriesId}/occurrences/${occId}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteOccurrence(seriesId, occId) {
    return this.request(`/api/series/${seriesId}/occurrences/${occId}`, {
      method: 'DELETE'
    });
  }
  async archiveOccurrence(seriesId, occId) {
    return this.request(`/api/series/${seriesId}/occurrences/${occId}/archive`, {
      method: 'PUT'
    });
  }
  async regenerateSeries(id, year) {
    return this.request(`/api/series/${id}/generate`, {
      method: 'POST',
      body: JSON.stringify({
        year
      })
    });
  }
  async convertToSeries(activity_id, sid_id) {
    return this.request('/api/series/convert', {
      method: 'POST',
      body: JSON.stringify({
        activity_id,
        sid_id
      })
    });
  }

  // Team Members
  async getTeamMembers() {
    return this.request('/api/team-members');
  }
  async createTeamMember(data) {
    return this.request('/api/team-members', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateTeamMember(id, data) {
    return this.request(`/api/team-members/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteTeamMember(id) {
    return this.request(`/api/team-members/${id}`, {
      method: 'DELETE'
    });
  }

  // Users
  async getUsers() {
    return this.request('/api/users');
  }
  async createUser(data) {
    return this.request('/api/users', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  async updateUser(id, data) {
    return this.request(`/api/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteUser(id) {
    return this.request(`/api/users/${id}`, {
      method: 'DELETE'
    });
  }
  async ping() {
    return this.request('/api/users/ping', {
      method: 'POST'
    });
  }
  async getOnlineUsers() {
    return this.request('/api/users/online');
  }

  // Import
  async importJson(data) {
    return this.request('/api/import/json', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  // Logs
  async getLogs(limit = 100) {
    return this.request(`/api/logs?limit=${limit}`);
  }

  // Maintenance Sundays
  async getMaintenanceSundays() {
    return this.request('/api/maintenance-sundays');
  }
  async updateMaintenanceSunday(id, date, label) {
    return this.request(`/api/maintenance-sundays/${id}`, {
      method: 'PUT',
      body: JSON.stringify({
        date,
        label
      })
    });
  }

  // Backup/Restore (Teamlead only)
  async exportBackup() {
    const response = await fetch(`${this.baseUrl}/api/backup/export`, {
      credentials: 'include'
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({
        error: 'Backup-Export fehlgeschlagen'
      }));
      throw new Error(error.error || 'Backup-Export fehlgeschlagen');
    }
    return response.json();
  }
  async importBackup(data) {
    return this.request('/api/backup/import', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  // Dark Mode preference (per-user)
  async setDarkMode(enabled) {
    return this.request('/api/auth/dark-mode', {
      method: 'PUT',
      body: JSON.stringify({
        dark_mode: enabled
      })
    });
  }

  // Toggle SID Gantt visibility (available to all users)
  async toggleSidVisibility(sidId, visible) {
    return this.request(`/api/sids/${sidId}/visibility`, {
      method: 'PATCH',
      body: JSON.stringify({
        visible_in_gantt: visible
      })
    });
  }

  // Matrix & Trainings
  async getMatrix() {
    return this.request('/api/matrix');
  }
  async createMatrixColumn(name) {
    return this.request('/api/matrix/columns', {
      method: 'POST',
      body: JSON.stringify({
        name
      })
    });
  }
  async updateMatrixColumn(id, name, sort_order) {
    return this.request(`/api/matrix/columns/${id}`, {
      method: 'PUT',
      body: JSON.stringify({
        name,
        sort_order
      })
    });
  }
  async deleteMatrixColumn(id) {
    return this.request(`/api/matrix/columns/${id}`, {
      method: 'DELETE'
    });
  }
  async updateMatrixValue(teamMemberId, columnId, level) {
    return this.request('/api/matrix/values', {
      method: 'PUT',
      body: JSON.stringify({
        teamMemberId,
        columnId,
        level
      })
    });
  }
  async getTrainings() {
    return this.request('/api/trainings');
  }
  async createTraining() {
    return this.request('/api/trainings', {
      method: 'POST'
    });
  }
  async updateTraining(id, data) {
    return this.request(`/api/trainings/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  async deleteTraining(id) {
    return this.request(`/api/trainings/${id}`, {
      method: 'DELETE'
    });
  }

  // Bereitschaft
  async getBereitschaft() {
    return this.request('/api/bereitschaft');
  }
  async claimBereitschaft(week_start) {
    return this.request('/api/bereitschaft', {
      method: 'POST',
      body: JSON.stringify({
        week_start
      })
    });
  }
  async deleteBereitschaft(week_start) {
    return this.request(`/api/bereitschaft/${week_start}`, {
      method: 'DELETE'
    });
  }
}
const api = new ApiClient();
const APP_VERSION_FALLBACK = '0.2.1';
const bundeslaender = [{
  id: 'BW',
  name: 'Baden-Württemberg'
}, {
  id: 'BY',
  name: 'Bayern'
}, {
  id: 'BE',
  name: 'Berlin'
}, {
  id: 'BB',
  name: 'Brandenburg'
}, {
  id: 'HB',
  name: 'Bremen'
}, {
  id: 'HH',
  name: 'Hamburg'
}, {
  id: 'HE',
  name: 'Hessen'
}, {
  id: 'MV',
  name: 'Mecklenburg-Vorpommern'
}, {
  id: 'NI',
  name: 'Niedersachsen'
}, {
  id: 'NW',
  name: 'Nordrhein-Westfalen'
}, {
  id: 'RP',
  name: 'Rheinland-Pfalz'
}, {
  id: 'SL',
  name: 'Saarland'
}, {
  id: 'SN',
  name: 'Sachsen'
}, {
  id: 'ST',
  name: 'Sachsen-Anhalt'
}, {
  id: 'SH',
  name: 'Schleswig-Holstein'
}, {
  id: 'TH',
  name: 'Thüringen'
}];
const defaultActivityTypes = [{
  id: 'installation',
  label: 'Installation',
  color: '#3b82f6'
}, {
  id: 'update',
  label: 'Update/Upgrade',
  color: '#8b5cf6'
}, {
  id: 'kernel',
  label: 'Kernel Update',
  color: '#06b6d4'
}, {
  id: 'db',
  label: 'DB Update',
  color: '#10b981'
}, {
  id: 'os',
  label: 'OS Patches',
  color: '#f59e0b'
}, {
  id: 'stpi',
  label: 'ST-PI Patches',
  color: '#ef4444'
}, {
  id: 'security',
  label: 'Security Patches',
  color: '#ec4899'
}, {
  id: 'other',
  label: 'Sonstige',
  color: '#6b7280'
}];

// Predefined colors for new activity types
const availableColors = ['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#6b7280', '#14b8a6', '#f97316', '#84cc16', '#a855f7', '#0ea5e9', '#d946ef', '#22c55e'];

// Weekday letters: Monday to Sunday (ISO week starts Monday)
const weekDayLetters = ['M', 'D', 'M', 'D', 'F', 'S', 'S'];
const defaultData = {
  year: 2026,
  bundesland: 'BW',
  landscapes: [{
    id: 1,
    name: 'ERP Landschaft',
    sids: [{
      id: 1,
      name: 'RTT',
      systemType: 'DEV',
      activities: []
    }, {
      id: 2,
      name: 'RTI',
      systemType: 'DEV',
      activities: []
    }, {
      id: 3,
      name: 'DB3',
      systemType: 'PRD',
      activities: []
    }]
  }, {
    id: 2,
    name: 'SAP Solution Manager Landschaft',
    sids: [{
      id: 4,
      name: 'SOT',
      systemType: 'DEV',
      activities: []
    }, {
      id: 5,
      name: 'SOQ',
      systemType: 'DEV',
      activities: []
    }, {
      id: 6,
      name: 'SOL',
      systemType: 'PRD',
      activities: []
    }]
  }]
};

// =========================================================================
// UTILITY FUNCTIONS
// =========================================================================

// Calculate Easter using Gauss algorithm
const getEasterDate = year => {
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
  const day = (h + l - 7 * m + 114) % 31 + 1;
  return new Date(year, month, day);
};

// Get all German holidays for a year and federal state
const getGermanHolidays = (year, bundesland) => {
  const holidays = new Map();
  // Use local date formatting to avoid timezone issues with toISOString()
  const addHoliday = (date, name) => {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    holidays.set(`${y}-${m}-${d}`, name);
  };

  // Fixed holidays (nationwide)
  addHoliday(new Date(year, 0, 1), 'Neujahr');
  addHoliday(new Date(year, 4, 1), 'Tag der Arbeit');
  addHoliday(new Date(year, 9, 3), 'Tag der Deutschen Einheit');
  addHoliday(new Date(year, 11, 25), '1. Weihnachtstag');
  addHoliday(new Date(year, 11, 26), '2. Weihnachtstag');

  // Easter-based holidays
  const easter = getEasterDate(year);
  const karfreitag = new Date(easter);
  karfreitag.setDate(easter.getDate() - 2);
  addHoliday(karfreitag, 'Karfreitag');
  const ostermontag = new Date(easter);
  ostermontag.setDate(easter.getDate() + 1);
  addHoliday(ostermontag, 'Ostermontag');
  const christiHimmelfahrt = new Date(easter);
  christiHimmelfahrt.setDate(easter.getDate() + 39);
  addHoliday(christiHimmelfahrt, 'Christi Himmelfahrt');
  const pfingstmontag = new Date(easter);
  pfingstmontag.setDate(easter.getDate() + 50);
  addHoliday(pfingstmontag, 'Pfingstmontag');

  // State-specific holidays
  if (['BW', 'BY', 'ST'].includes(bundesland)) {
    addHoliday(new Date(year, 0, 6), 'Heilige Drei Könige');
  }
  if (['BW', 'BY', 'HE', 'NW', 'RP', 'SL'].includes(bundesland)) {
    const fronleichnam = new Date(easter);
    fronleichnam.setDate(easter.getDate() + 60);
    addHoliday(fronleichnam, 'Fronleichnam');
  }
  if (['BY', 'SL'].includes(bundesland)) {
    addHoliday(new Date(year, 7, 15), 'Mariä Himmelfahrt');
  }
  if (['BB', 'MV', 'SN', 'ST', 'TH'].includes(bundesland)) {
    addHoliday(new Date(year, 9, 31), 'Reformationstag');
  }
  if (['BW', 'BY', 'NW', 'RP', 'SL'].includes(bundesland)) {
    addHoliday(new Date(year, 10, 1), 'Allerheiligen');
  }
  if (bundesland === 'SN') {
    // Buß- und Bettag: Wednesday before Nov 23
    const nov23 = new Date(year, 10, 23);
    const dayOfWeek = nov23.getDay();
    const daysToWednesday = (dayOfWeek + 4) % 7;
    const bussUndBettag = new Date(nov23);
    bussUndBettag.setDate(nov23.getDate() - daysToWednesday);
    addHoliday(bussUndBettag, 'Buß- und Bettag');
  }
  return holidays;
};

// Check if a date is a weekend (Saturday=6, Sunday=0)
const isWeekend = date => {
  const day = date.getDay();
  return day === 0 || day === 6;
};

// Get weekday index (0=Monday, 6=Sunday) from JavaScript Date
const getWeekdayIndex = date => {
  const day = date.getDay();
  return day === 0 ? 6 : day - 1; // Convert: Sun=0 -> 6, Mon=1 -> 0, etc.
};

// Calculate ISO week number
const getISOWeekNumber = date => {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
};

// Get Monday of the week containing a date
const getMondayOfWeek = date => {
  const d = new Date(date);
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  d.setDate(diff);
  return d;
};

// Calculate end date based on working days
// Duration = 1 means start date = end date (start day is the first working day)
// For PRD systems: weekends (Sat/Sun) ARE working days (work happens on weekends)
// For non-PRD systems: weekends are NOT working days
const calculateEndDate = (startDateStr, durationDays, year, bundesland, isPRD = false) => {
  // Duration 0 = sub-day activity (time-based), start and end are the same day
  if (durationDays === 0) return startDateStr;
  const holidays = getGermanHolidays(year, bundesland);
  const holidayDates = new Set(holidays.keys());
  let current = new Date(startDateStr);
  let workingDaysCount = 0;
  while (workingDaysCount < durationDays) {
    const dateStr = formatDateISO(current);
    const dayOfWeek = current.getDay();
    let isWorkingDay;
    if (isPRD) {
      // PRD systems: weekends ARE working days, only holidays are excluded
      isWorkingDay = !holidayDates.has(dateStr);
    } else {
      // Non-PRD systems: weekends and holidays are NOT working days
      isWorkingDay = dayOfWeek !== 0 && dayOfWeek !== 6 && !holidayDates.has(dateStr);
    }
    if (isWorkingDay) {
      workingDaysCount++;
      if (workingDaysCount >= durationDays) {
        break;
      }
    }
    current.setDate(current.getDate() + 1);
  }
  return formatDateISO(current);
};

// Adjust start date for PRD systems (move to Saturday)
const adjustStartDateForPRD = (startDateStr, isPRD) => {
  if (!isPRD) return startDateStr;
  const date = new Date(startDateStr);
  const day = date.getDay();
  if (day !== 6) {
    const daysUntilSaturday = (6 - day + 7) % 7 || 7;
    date.setDate(date.getDate() + daysUntilSaturday);
  }
  return date.toISOString().split('T')[0];
};

// Format date as German locale
const formatDateDE = dateStr => {
  if (!dateStr) return '';
  const date = new Date(dateStr);
  return date.toLocaleDateString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
};

// Format date for comparison (YYYY-MM-DD)
const formatDateISO = date => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

// Calculate activity segments (split at weekends/holidays for non-PRD systems)
const getActivitySegments = (startDateStr, endDateStr, isPRD, holidays) => {
  const segments = [];
  const holidayDates = new Set(holidays.keys());
  const start = new Date(startDateStr);
  const end = new Date(endDateStr);

  // For PRD systems, return single continuous segment
  if (isPRD) {
    return [{
      start: startDateStr,
      end: endDateStr
    }];
  }

  // For non-PRD systems, split at weekends and holidays
  let currentSegmentStart = null;
  let currentDate = new Date(start);
  while (currentDate <= end) {
    const dateStr = formatDateISO(currentDate);
    const dayOfWeek = currentDate.getDay();
    const isNonWorkingDay = dayOfWeek === 0 || dayOfWeek === 6 || holidayDates.has(dateStr);
    if (!isNonWorkingDay) {
      // Working day
      if (currentSegmentStart === null) {
        currentSegmentStart = dateStr;
      }
    } else {
      // Non-working day - close current segment if open
      if (currentSegmentStart !== null) {
        const prevDate = new Date(currentDate);
        prevDate.setDate(prevDate.getDate() - 1);
        segments.push({
          start: currentSegmentStart,
          end: formatDateISO(prevDate)
        });
        currentSegmentStart = null;
      }
    }
    currentDate.setDate(currentDate.getDate() + 1);
  }

  // Close final segment
  if (currentSegmentStart !== null) {
    segments.push({
      start: currentSegmentStart,
      end: formatDateISO(end)
    });
  }
  return segments;
};

// =========================================================================
// ICONS
// =========================================================================

const CalendarIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "24",
  height: "24",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("rect", {
  x: "3",
  y: "4",
  width: "18",
  height: "18",
  rx: "2",
  ry: "2"
}), /*#__PURE__*/React.createElement("line", {
  x1: "16",
  y1: "2",
  x2: "16",
  y2: "6"
}), /*#__PURE__*/React.createElement("line", {
  x1: "8",
  y1: "2",
  x2: "8",
  y2: "6"
}), /*#__PURE__*/React.createElement("line", {
  x1: "3",
  y1: "10",
  x2: "21",
  y2: "10"
}));
const PlusIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("line", {
  x1: "12",
  y1: "5",
  x2: "12",
  y2: "19"
}), /*#__PURE__*/React.createElement("line", {
  x1: "5",
  y1: "12",
  x2: "19",
  y2: "12"
}));
const SaveIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("path", {
  d: "M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"
}), /*#__PURE__*/React.createElement("polyline", {
  points: "17 21 17 13 7 13 7 21"
}), /*#__PURE__*/React.createElement("polyline", {
  points: "7 3 7 8 15 8"
}));
const DocumentDuplicateIcon = () => /*#__PURE__*/React.createElement("svg", {
  xmlns: "http://www.w3.org/2000/svg",
  className: "h-5 w-5",
  fill: "none",
  viewBox: "0 0 24 24",
  stroke: "currentColor"
}, /*#__PURE__*/React.createElement("path", {
  strokeLinecap: "round",
  strokeLinejoin: "round",
  strokeWidth: 2,
  d: "M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
}));
const DownloadIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("path", {
  d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
}), /*#__PURE__*/React.createElement("polyline", {
  points: "7 10 12 15 17 10"
}), /*#__PURE__*/React.createElement("line", {
  x1: "12",
  y1: "15",
  x2: "12",
  y2: "3"
}));

// Custom Time Picker Component (replaces native input[type=time] to avoid unstyled Chromium popup)
const TimePicker = ({
  value,
  onChange,
  min,
  max,
  disabled,
  size = 'sm'
}) => {
  const [open, setOpen] = useState(false);
  const ref = React.useRef(null);

  // Parse "HH:MM" string
  const parsed = value ? value.split(':') : [null, null];
  const selH = parsed[0];
  const selM = parsed[1];

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = e => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);
  const hours = Array.from({
    length: 24
  }, (_, i) => String(i).padStart(2, '0'));
  const minutes = Array.from({
    length: 12
  }, (_, i) => String(i * 5).padStart(2, '0'));
  const handleSelect = (h, m) => {
    const newVal = `${h}:${m}`;
    // Validate against min/max
    if (min && newVal < min) return;
    if (max && newVal > max) return;
    onChange(newVal);
    setOpen(false);
  };
  const textSize = size === 'xs' ? 'text-xs' : 'text-sm';
  return /*#__PURE__*/React.createElement("div", {
    className: "relative inline-block",
    ref: ref
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => !disabled && setOpen(!open),
    disabled: disabled,
    className: `px-1.5 py-0.5 border border-gray-300 rounded ${textSize} cursor-pointer flex items-center gap-1 min-w-[65px] justify-center ${disabled ? 'bg-gray-100 cursor-default' : 'hover:border-purple-400'}`
  }, /*#__PURE__*/React.createElement("span", null, value || '--:--'), /*#__PURE__*/React.createElement("svg", {
    width: "10",
    height: "10",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2.5",
    className: "opacity-50"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "12 6 12 12 16 14"
  }))), open && /*#__PURE__*/React.createElement("div", {
    className: "absolute z-50 mt-1 bg-gray-800 border border-gray-600 rounded-lg shadow-xl p-2 flex gap-1",
    style: {
      minWidth: '140px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col max-h-48 overflow-y-auto scrollbar-thin",
    style: {
      scrollbarWidth: 'thin'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 text-center mb-1 sticky top-0 bg-gray-800"
  }, "Std"), hours.map(h => /*#__PURE__*/React.createElement("button", {
    key: h,
    type: "button",
    onClick: () => handleSelect(h, selM || '00'),
    className: `px-2 py-0.5 text-xs rounded text-center transition-colors ${h === selH ? 'bg-purple-600 text-white font-bold' : 'text-gray-300 hover:bg-purple-500/30'}`
  }, h))), /*#__PURE__*/React.createElement("div", {
    className: "w-px bg-gray-600"
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col max-h-48 overflow-y-auto scrollbar-thin",
    style: {
      scrollbarWidth: 'thin'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 text-center mb-1 sticky top-0 bg-gray-800"
  }, "Min"), minutes.map(m => /*#__PURE__*/React.createElement("button", {
    key: m,
    type: "button",
    onClick: () => handleSelect(selH || '00', m),
    className: `px-2 py-0.5 text-xs rounded text-center transition-colors ${m === selM ? 'bg-purple-600 text-white font-bold' : 'text-gray-300 hover:bg-purple-500/30'}`
  }, m))), value && /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col justify-end"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => {
      onChange(null);
      setOpen(false);
    },
    className: "px-1.5 py-0.5 text-[10px] text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded",
    title: "Zeit l\xF6schen"
  }, "\u2715"))));
};
const TrashIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "14",
  height: "14",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("polyline", {
  points: "3 6 5 6 21 6"
}), /*#__PURE__*/React.createElement("path", {
  d: "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"
}));
const ChevronLeftIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("polyline", {
  points: "15 18 9 12 15 6"
}));
const ChevronRightIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("polyline", {
  points: "9 18 15 12 9 6"
}));
const UploadIcon = () => /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "2"
}, /*#__PURE__*/React.createElement("path", {
  d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
}), /*#__PURE__*/React.createElement("polyline", {
  points: "17 8 12 3 7 8"
}), /*#__PURE__*/React.createElement("line", {
  x1: "12",
  y1: "3",
  x2: "12",
  y2: "15"
}));

// =========================================================================
// SERIES POPUP EDITOR COMPONENT
// =========================================================================
const SeriesPopupEditor = ({
  series,
  activityTypes,
  teamMembers,
  canEdit,
  year,
  api,
  onClose
}) => {
  const seriesType = activityTypes.find(t => t.id === series.typeId);
  const [localRule, setLocalRule] = useState({
    type: series.ruleType || 'manual',
    value: series.ruleValue || 0,
    startDate: series.ruleStartDate || ''
  });
  const [localOccs, setLocalOccs] = useState(series.occurrences || []);
  const [localDefaults, setLocalDefaults] = useState({
    startTime: series.defaultStartTime || '',
    endTime: series.defaultEndTime || '',
    teamMemberId: series.teamMemberId || ''
  });
  const [saving, setSaving] = useState(false);
  const handleGenerate = async () => {
    if (!localRule.startDate) {
      alert('Bitte Startdatum angeben');
      return;
    }
    if (localOccs.length > 0 && !confirm('Alle bestehenden Termine werden ersetzt. Fortfahren?')) return;
    try {
      await api.updateSeries(series.id, {
        rule_type: localRule.type,
        rule_value: localRule.value,
        rule_start_date: localRule.startDate,
        default_start_time: localDefaults.startTime,
        default_end_time: localDefaults.endTime,
        team_member_id: localDefaults.teamMemberId || null
      });
      const result = await api.regenerateSeries(series.id, year);
      setLocalOccs(result.occurrences || []);
    } catch (e) {
      alert('Fehler: ' + e.message);
    }
  };
  const handleAddOcc = async () => {
    try {
      const newOcc = await api.createOccurrence(series.id, {
        date: new Date().toISOString().split('T')[0],
        start_time: localDefaults.startTime,
        end_time: localDefaults.endTime,
        team_member_id: localDefaults.teamMemberId || null
      });
      setLocalOccs(prev => [...prev, newOcc]);
    } catch (e) {
      alert('Fehler: ' + e.message);
    }
  };
  const handleCsvUpload = async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async e => {
      try {
        const text = e.target?.result;
        if (typeof text !== 'string') return;
        const lines = text.split(/\r?\n/).filter(line => line.trim());
        if (lines.length <= 1) return; // Only header or empty

        const header = lines[0].split(';').map(h => h.trim().toLowerCase());
        const dateIdx = header.indexOf('datum');
        const fromIdx = header.indexOf('von');
        const toIdx = header.indexOf('bis');
        const weIdx = header.indexOf('we');
        if (dateIdx === -1) {
          throw new Error('CSV muss eine Spalte "Datum" enthalten (Format: TT.MM.JJJJ)');
        }
        const newOccurrences = [];
        for (let i = 1; i < lines.length; i++) {
          const cols = lines[i].split(';');
          const dateStr = cols[dateIdx]?.trim();
          if (!dateStr) continue;

          // Parse DD.MM.YY or DD.MM.YYYY to YYYY-MM-DD
          let parsedDate = '';
          const parts = dateStr.split('.');
          if (parts.length === 3) {
            let yearPart = parts[2];
            if (yearPart.length === 2) {
              yearPart = `20${yearPart}`; // Assume 20xx for 2-digit years
            }
            parsedDate = `${yearPart}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`;
          } else {
            parsedDate = dateStr; // Fallback
          }
          let startTime = fromIdx !== -1 ? cols[fromIdx]?.trim() : localDefaults.startTime;
          let endTime = toIdx !== -1 ? cols[toIdx]?.trim() : localDefaults.endTime;
          if (startTime && !startTime.includes(':')) startTime = '';
          if (endTime && !endTime.includes(':')) endTime = '';
          let includesWeekend = false;
          if (weIdx !== -1) {
            const weStr = cols[weIdx]?.trim().toLowerCase();
            includesWeekend = ['ja', 'x', '1', 'true', 'y', 'yes'].includes(weStr);
          }
          try {
            const newOcc = await api.createOccurrence(series.id, {
              date: parsedDate,
              start_time: startTime || '',
              end_time: endTime || '',
              includes_weekend: includesWeekend,
              team_member_id: localDefaults.teamMemberId || null
            });
            newOccurrences.push(newOcc);
          } catch (createErr) {
            console.error('Fehler beim Erstellen eines hochgeladenen Termins:', createErr);
          }
        }
        if (newOccurrences.length > 0) {
          setLocalOccs(prev => [...prev, ...newOccurrences]);
          alert(`${newOccurrences.length} Termine erfolgreich importiert.`);
        }
      } catch (err) {
        alert('Fehler beim CSV Upload: ' + err.message);
      }
    };
    reader.readAsText(file, 'UTF-8');
    event.target.value = ''; // Reset input
  };
  const handleUpdateOcc = async (occId, field, value) => {
    try {
      const occ = localOccs.find(o => o.id === occId);
      if (occ && occ.status && occ.status !== 'PLANNED') return;
      const data = {};
      if (field === 'date') data.date = value;else if (field === 'start_time') data.start_time = value;else if (field === 'end_time') data.end_time = value;else if (field === 'includes_weekend') data.includes_weekend = value;else if (field === 'team_member_id') data.team_member_id = value || null;
      await api.updateOccurrence(series.id, occId, data);
      setLocalOccs(prev => prev.map(o => o.id === occId ? {
        ...o,
        ...data,
        includesWeekend: data.includes_weekend !== undefined ? data.includes_weekend : o.includesWeekend,
        teamMemberId: data.team_member_id !== undefined ? data.team_member_id : o.teamMemberId
      } : o));
    } catch (e) {
      alert('Fehler: ' + e.message);
    }
  };
  const handleDeleteOcc = async occId => {
    try {
      if (!window.confirm('Termin wirklich unwiderruflich löschen?')) return;
      await api.deleteOccurrence(series.id, occId);
      setLocalOccs(prev => prev.filter(o => o.id !== occId));
    } catch (e) {
      alert('Fehler: ' + e.message);
    }
  };
  const handleArchiveOcc = async occId => {
    try {
      if (!window.confirm('Termin wirklich archivieren? Er wird dadurch im Plan eingefroren.')) return;
      await api.archiveOccurrence(series.id, occId);
      setLocalOccs(prev => prev.map(o => o.id === occId ? {
        ...o,
        status: 'ARCHIVED'
      } : o));
    } catch (e) {
      alert('Fehler: ' + e.message);
    }
  };
  const handleClose = async () => {
    setSaving(true);
    try {
      await api.updateSeries(series.id, {
        rule_type: localRule.type,
        rule_value: localRule.value,
        rule_start_date: localRule.startDate,
        default_start_time: localDefaults.startTime,
        default_end_time: localDefaults.endTime,
        team_member_id: localDefaults.teamMemberId || null
      });
    } catch (e) {
      console.error(e);
    }
    setSaving(false);
    onClose();
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 pb-48 w-full max-w-3xl mx-4 max-h-[85vh] overflow-y-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 rounded-full",
    style: {
      backgroundColor: seriesType?.color
    }
  }), /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold dark:text-gray-100"
  }, seriesType?.label || series.typeId, " \u2013 Serie (", localOccs.length, " Termine)")), /*#__PURE__*/React.createElement("button", {
    onClick: handleClose,
    className: "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 text-2xl"
  }, "\xD7")), /*#__PURE__*/React.createElement("div", {
    className: "bg-gray-50 dark:bg-slate-700/50 rounded-lg p-4 mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap items-center gap-3"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm font-medium text-gray-700 dark:text-gray-300"
  }, "Regel:"), /*#__PURE__*/React.createElement("select", {
    value: localRule.type,
    onChange: e => setLocalRule(prev => ({
      ...prev,
      type: e.target.value
    })),
    className: "px-2 py-1 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm"
  }, /*#__PURE__*/React.createElement("option", {
    value: "manual"
  }, "Manuell"), /*#__PURE__*/React.createElement("option", {
    value: "every_x_weeks"
  }, "Alle X Wochen"), /*#__PURE__*/React.createElement("option", {
    value: "x_per_year"
  }, "X mal pro Jahr")), localRule.type !== 'manual' && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("input", {
    type: "number",
    min: "1",
    max: "52",
    value: localRule.value,
    onChange: e => setLocalRule(prev => ({
      ...prev,
      value: parseInt(e.target.value) || 0
    })),
    className: "w-16 px-2 py-1 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-600 dark:text-gray-400"
  }, "ab"), /*#__PURE__*/React.createElement("input", {
    type: "date",
    value: localRule.startDate,
    onChange: e => setLocalRule(prev => ({
      ...prev,
      startDate: e.target.value
    })),
    className: "px-2 py-1 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm"
  }), /*#__PURE__*/React.createElement("button", {
    onClick: handleGenerate,
    className: "px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700 font-medium"
  }, "\uD83D\uDD04 Generieren"))), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap items-center gap-3 mt-3"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-600 dark:text-gray-400"
  }, "Standard Von:"), /*#__PURE__*/React.createElement(TimePicker, {
    value: localDefaults.startTime,
    onChange: v => setLocalDefaults(prev => ({
      ...prev,
      startTime: v
    }))
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-600 dark:text-gray-400"
  }, "Bis:"), /*#__PURE__*/React.createElement(TimePicker, {
    value: localDefaults.endTime,
    onChange: v => setLocalDefaults(prev => ({
      ...prev,
      endTime: v
    }))
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-600 dark:text-gray-400"
  }, "\uD83D\uDC64"), /*#__PURE__*/React.createElement("select", {
    value: localDefaults.teamMemberId,
    onChange: e => setLocalDefaults(prev => ({
      ...prev,
      teamMemberId: e.target.value
    })),
    className: "px-2 py-1 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm"
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "-"), teamMembers.map(m => /*#__PURE__*/React.createElement("option", {
    key: m.id,
    value: m.id
  }, m.abbreviation))))), localOccs.length > 0 ? /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("table", {
    className: "w-full text-sm"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", {
    className: "border-b border-gray-300 dark:border-slate-600 text-left dark:text-gray-300"
  }, /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1 w-8"
  }, "Nr."), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1"
  }, "Datum"), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1"
  }, "Von"), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1"
  }, "Bis"), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1 w-10"
  }, "WE"), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1"
  }, "\uD83D\uDC64"), /*#__PURE__*/React.createElement("th", {
    className: "py-2 px-1 w-8"
  }))), /*#__PURE__*/React.createElement("tbody", null, localOccs.map((occ, idx) => /*#__PURE__*/React.createElement("tr", {
    key: occ.id,
    className: "border-b border-gray-100 dark:border-slate-700 hover:bg-gray-50 dark:hover:bg-slate-700/50"
  }, /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1 text-gray-500 dark:text-gray-400"
  }, idx + 1), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1"
  }, /*#__PURE__*/React.createElement("input", {
    type: "date",
    value: occ.date,
    onChange: e => handleUpdateOcc(occ.id, 'date', e.target.value),
    className: "px-1 py-0.5 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm",
    disabled: !canEdit || occ.status && occ.status !== 'PLANNED'
  })), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1"
  }, /*#__PURE__*/React.createElement(TimePicker, {
    value: occ.start_time || '',
    onChange: v => handleUpdateOcc(occ.id, 'start_time', v),
    disabled: !canEdit || occ.status && occ.status !== 'PLANNED'
  })), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1"
  }, /*#__PURE__*/React.createElement(TimePicker, {
    value: occ.end_time || '',
    onChange: v => handleUpdateOcc(occ.id, 'end_time', v),
    disabled: !canEdit || occ.status && occ.status !== 'PLANNED'
  })), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1 text-center"
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: !!occ.includesWeekend,
    onChange: e => handleUpdateOcc(occ.id, 'includes_weekend', e.target.checked),
    disabled: !canEdit || occ.status && occ.status !== 'PLANNED',
    className: "w-4 h-4 rounded border-gray-300"
  })), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1"
  }, /*#__PURE__*/React.createElement("select", {
    value: occ.teamMemberId || occ.team_member_id || '',
    onChange: e => handleUpdateOcc(occ.id, 'team_member_id', e.target.value || null),
    disabled: !canEdit || occ.status && occ.status !== 'PLANNED',
    className: "px-1 py-0.5 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-gray-200 rounded text-sm w-full"
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "-"), teamMembers.map(m => /*#__PURE__*/React.createElement("option", {
    key: m.id,
    value: m.id
  }, m.abbreviation)))), /*#__PURE__*/React.createElement("td", {
    className: "py-1 px-1"
  }, canEdit && /*#__PURE__*/React.createElement(React.Fragment, null, (!occ.status || occ.status === 'PLANNED') && /*#__PURE__*/React.createElement("button", {
    onClick: () => handleDeleteOcc(occ.id),
    className: "w-6 h-6 bg-red-50 dark:bg-red-900/40 text-red-600 dark:text-red-400 rounded flex items-center justify-center hover:bg-red-100 dark:hover:bg-red-900/60 transition-colors",
    title: "Termin unwiderruflich l\xF6schen"
  }, /*#__PURE__*/React.createElement(TrashIcon, null)), occ.status === 'COMPLETED' && /*#__PURE__*/React.createElement("button", {
    onClick: () => handleArchiveOcc(occ.id),
    className: "w-6 h-6 bg-stone-200 text-stone-700 border border-stone-300 rounded flex items-center justify-center hover:bg-stone-300 shadow-sm",
    title: "Termin archivieren"
  }, "\uD83D\uDCE6")))))))) : /*#__PURE__*/React.createElement("div", {
    className: "text-center py-6 text-gray-500 dark:text-gray-400"
  }, "Keine Termine vorhanden. Klicken Sie auf \"Generieren\" oder f\xFCgen Sie manuell Termine hinzu."), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mt-4 border-t border-gray-200 dark:border-slate-700 pt-4"
  }, canEdit && /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: handleAddOcc,
    className: "px-3 py-1.5 bg-purple-600 hover:bg-purple-700 dark:bg-purple-700 dark:hover:bg-purple-600 text-white rounded text-sm font-medium transition-colors"
  }, "+ Termin hinzuf\xFCgen"), /*#__PURE__*/React.createElement("label", {
    className: "cursor-pointer px-3 py-1.5 bg-purple-600 hover:bg-purple-700 dark:bg-purple-700 dark:hover:bg-purple-600 text-white rounded text-sm font-medium transition-colors flex items-center justify-center"
  }, "+ CSV Upload", /*#__PURE__*/React.createElement("input", {
    type: "file",
    accept: ".csv",
    className: "hidden",
    onChange: handleCsvUpload
  }))), /*#__PURE__*/React.createElement("button", {
    onClick: handleClose,
    disabled: saving,
    className: "ml-auto px-4 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 text-white rounded-lg font-medium disabled:opacity-50 transition-colors"
  }, saving ? 'Speichern...' : 'Fertig'))));
};

// =========================================================================
// MAIN APPLICATION
// =========================================================================

const SAPBasisPlanner = () => {
  // Auth state
  const [user, setUser] = useState(null);
  const [loginError, setLoginError] = useState('');
  const [loading, setLoading] = useState(true);
  const [mustChangePassword, setMustChangePassword] = useState(false);

  // Dark mode state (initialized from localStorage for pre-login, synced with server after login)
  const [darkMode, setDarkMode] = useState(() => {
    try {
      return localStorage.getItem('darkMode') === 'true';
    } catch (e) {
      return false;
    }
  });

  // Helper: apply dark mode CSS class and sync localStorage
  const applyDarkMode = useCallback(enabled => {
    document.documentElement.classList.add('dark-mode-transition');
    if (enabled) {
      document.documentElement.classList.add('dark-mode');
    } else {
      document.documentElement.classList.remove('dark-mode');
    }
    try {
      localStorage.setItem('darkMode', String(enabled));
    } catch (e) {}
    setTimeout(() => document.documentElement.classList.remove('dark-mode-transition'), 350);
    setDarkMode(enabled);
  }, []);

  // Toggle dark mode and save to server
  const toggleDarkMode = useCallback(() => {
    setDarkMode(prev => {
      const next = !prev;
      applyDarkMode(next);
      // Save to server (fire-and-forget)
      api.setDarkMode(next).catch(() => {});
      return next;
    });
  }, [applyDarkMode]);

  // App state
  const [year, setYear] = useState(2026);
  const [bundesland, setBundesland] = useState('BW');
  const [landscapes, setLandscapes] = useState([]);
  // View state
  const [viewMode, setViewMode] = useState('week');
  const [selectedQuarter, setSelectedQuarter] = useState(1);
  const [viewOffset, setViewOffset] = useState(() => {
    // Start at Today if current year matches default year (2026)
    const currentYear = new Date().getFullYear();
    const defaultYear = 2026;
    if (currentYear === defaultYear) {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const rangeStart = new Date(defaultYear, 0, 1);
      rangeStart.setDate(rangeStart.getDate() - 60);
      return Math.max(0, Math.round((today - rangeStart) / (1000 * 60 * 60 * 24)));
    }
    return 60; // Default fallback (approx Jan 1) if not current year
  });
  const [collapsedLandscapes, setCollapsedLandscapes] = useState(new Set());
  const [collapsedSids, setCollapsedSids] = useState(new Set());
  const [collapsedActivities, setCollapsedActivities] = useState(new Set());
  const [editingSidInfo, setEditingSidInfo] = useState(null); // { landscapeId, sidId, notes }
  const [activityTypes, setActivityTypes] = useState(defaultActivityTypes);
  const [editingTypeId, setEditingTypeId] = useState(null);
  // Tab navigation
  const [activeTab, setActiveTab] = useState('gantt'); // 'gantt', 'team', 'skills', 'bereitschaft', 'auswertung'
  // Auswertung (Analysis) tab filter
  const [auswertungFilter, setAuswertungFilter] = useState({
    type: 'year',
    value: ''
  });
  // Auswertung chart refs (must be at top level to satisfy Rules of Hooks)
  const pieCanvasRef = React.useRef(null);
  const barCanvasRef = React.useRef(null);
  const pieChartRef = React.useRef(null);
  const barChartRef = React.useRef(null);
  // Team members
  const [teamMembers, setTeamMembers] = useState([]);
  // Version
  const [appVersion, setAppVersion] = useState(APP_VERSION_FALLBACK);

  // Update document title when appVersion changes
  useEffect(() => {
    document.title = `SAP Basis Jahresplaner ${appVersion}`;
  }, [appVersion]);
  // Multi-User Locking
  const [activeSidId, setActiveSidId] = useState(null);
  const [mySidLocks, setMySidLocks] = useState(new Set());
  const [onlineUsers, setOnlineUsers] = useState([]);
  // Skills & Schulungen
  const [matrixColumns, setMatrixColumns] = useState([]);
  const [matrixValues, setMatrixValues] = useState([]);
  const [trainings, setTrainings] = useState([]);
  const [bereitschaft, setBereitschaft] = useState([]);
  const [bView, setBView] = useState('annual');
  const [bMonthIdx, setBMonthIdx] = useState(1);
  const [bPendingDelete, setBPendingDelete] = useState(null); // mondayISO of week pending deletion
  const [showCsvDropdown, setShowCsvDropdown] = useState(false);
  const [showDataDropdown, setShowDataDropdown] = useState(false);

  // Check permissions
  // canEdit: Admin OR Teamlead can edit landscapes, SIDs, activities
  const canEdit = user?.role === 'admin' || user?.role === 'teamlead';

  // canManageTeam: ONLY Teamlead can manage team members (add/delete/edit days)
  const canManageTeam = user?.role === 'teamlead';

  // Load data from API
  const loadData = useCallback(async () => {
    try {
      const [settings, types, lands, sundays, members, matrix, trns, bereitschaftList, initialUsers] = await Promise.all([api.getSettings(), api.getActivityTypes(), api.getLandscapes(), api.getMaintenanceSundays().catch(() => []), api.getTeamMembers().catch(() => []), api.getMatrix().catch(() => ({
        columns: [],
        values: []
      })), api.getTrainings().catch(() => []), api.getBereitschaft().catch(() => []), api.getUsers().catch(() => [])]);
      if (settings.year) setYear(parseInt(settings.year));
      if (settings.bundesland) setBundesland(settings.bundesland);
      const v = settings.version || user && user.version || APP_VERSION_FALLBACK;
      if (v) setAppVersion(v);
      if (types.length > 0) setActivityTypes(types);
      setTeamMembers(members);
      setMatrixColumns(matrix.columns || []);
      setMatrixValues(matrix.values || []);
      setTrainings(trns || []);
      setBereitschaft(bereitschaftList || []);
      if (initialUsers && initialUsers.length > 0) setUsers(initialUsers);

      // Calculate endDate for all activities and sub-activities on load
      const loadedYear = settings.year ? parseInt(settings.year) : new Date().getFullYear();
      const loadedBundesland = settings.bundesland || 'BW';
      const landsWithEndDates = lands.map(landscape => ({
        ...landscape,
        sids: landscape.sids.map(sid => ({
          ...sid,
          activities: sid.activities.map(activity => ({
            ...activity,
            teamMemberId: activity.teamMemberId || activity.team_member_id || null,
            endDate: calculateEndDate(activity.startDate, parseInt(activity.duration) >= 0 ? parseInt(activity.duration) : 1, loadedYear, loadedBundesland, activity.includesWeekend || false),
            subActivities: (activity.subActivities || []).map(sub => ({
              ...sub,
              teamMemberId: sub.teamMemberId || sub.team_member_id || null,
              endDate: calculateEndDate(sub.startDate, parseInt(sub.duration) >= 0 ? parseInt(sub.duration) : 1, loadedYear, loadedBundesland, sub.includesWeekend || false)
            }))
          }))
        }))
      }));
      setLandscapes(landsWithEndDates);
      // Collapse all SIDs by default on load (only if not already tracking state)
      const allSidIds = new Set();
      landsWithEndDates.forEach(l => l.sids.forEach(s => allSidIds.add(s.id)));
      setCollapsedSids(prev => {
        if (prev && prev.size > 0) return prev; // Preserve user's current view state
        return allSidIds; // Initial load
      });
      setMaintenanceSundays(sundays);
    } catch (error) {
      if (error.message === 'SESSION_EXPIRED') {
        setUser(null);
      } else {
        console.error('Error loading data:', error);
      }
    }
  }, []);
  const handleRefresh = async () => {
    setLoading(true);
    await loadData();
    setLoading(false);
  };

  // Heartbeat for locks
  useEffect(() => {
    if (mySidLocks.size === 0) return;
    const interval = setInterval(async () => {
      for (const sidId of mySidLocks) {
        try {
          await api.acquireLock(sidId);
        } catch (err) {
          console.warn(`Failed to renew lock for SID ${sidId}:`, err);
          // If lock lost, remove from mySidLocks to stop trying
          setMySidLocks(prev => {
            const newSet = new Set(prev);
            newSet.delete(sidId);
            return newSet;
          });
          if (activeSidId === sidId) setActiveSidId(null);
        }
      }
    }, 1000 * 60 * 4); // Every 4 minutes

    return () => clearInterval(interval);
  }, [mySidLocks, activeSidId]);

  // Online Users tracking heartbeat
  useEffect(() => {
    if (!user) return; // Only if logged in

    const trackOnline = async () => {
      try {
        await api.ping(activeSidId);
        const [users, locks] = await Promise.all([api.getOnlineUsers(), api.getLocks()]);
        setOnlineUsers(users);

        // Merge fresh lock data into landscapes state
        const locksMap = {};
        locks.forEach(lock => {
          locksMap[lock.sid_id] = {
            user_id: lock.user_id,
            username: lock.username,
            abbreviation: lock.abbreviation || lock.username.substring(0, 3).toUpperCase(),
            expires_at: lock.expires_at
          };
        });
        setLandscapes(prev => prev.map(landscape => ({
          ...landscape,
          sids: landscape.sids.map(sid => ({
            ...sid,
            lock: locksMap[sid.id] || null
          }))
        })));
      } catch (err) {
        console.warn('Online tracking failed', err);
      }
    };
    trackOnline(); // Initial call
    const interval = setInterval(trackOnline, 15000); // Poll every 15 seconds

    return () => clearInterval(interval);
  }, [user, activeSidId]);

  // Lock acquisition handler
  const handleSidInteraction = useCallback(async sidId => {
    if (activeSidId === sidId) return; // Already active/locked by us
    if (!canEdit) return; // Viewers shouldn't lock

    try {
      await api.acquireLock(sidId);

      // Success: release previous lock if any
      if (activeSidId) {
        try {
          await api.releaseLock(activeSidId);
        } catch (e) {}
      }
      setActiveSidId(sidId);
      setMySidLocks(new Set([sidId]));
      api.ping(sidId).catch(e => console.error(e)); // Broadcast active status immediately
    } catch (error) {
      console.warn('SID already locked or lock failed', error);
    }
  }, [activeSidId, canEdit]);

  // Release lock when changing tabs away from gantt
  useEffect(() => {
    if (activeTab !== 'gantt' && activeSidId) {
      api.releaseLock(activeSidId).catch(e => console.error(e));
      api.ping(null).catch(e => console.error(e));
      setActiveSidId(null);
      setMySidLocks(new Set());
    }
  }, [activeTab, activeSidId]);

  // Release lock on window unload (refresh or close)
  useEffect(() => {
    const handleBeforeUnload = () => {
      if (activeSidId) {
        // Use fetch with keepalive instead of sendBeacon to ensure auth cookies are sent
        fetch(`/api/sids/${activeSidId}/lock`, {
          method: 'DELETE',
          keepalive: true
        }).catch(() => {});
        fetch('/api/users/ping', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            activeSidId: null
          }),
          keepalive: true
        }).catch(() => {});
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [activeSidId]);

  // Check authentication on mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const userData = await api.getMe();
        setUser(userData);
        if (userData.version) setAppVersion(userData.version);
        // Apply user's dark mode preference from server
        applyDarkMode(!!userData.dark_mode);
        // Check if user must change password
        if (userData.must_change_password) {
          setMustChangePassword(true);
        } else {
          await loadData();
        }
      } catch {
        // Not logged in or session expired
        api.setToken(null);
      }
      setLoading(false);
    };
    checkAuth();
  }, [loadData, applyDarkMode]);

  // Login handler
  const handleLogin = async e => {
    e.preventDefault();
    const form = e.target;
    const username = form.username.value;
    const password = form.password.value;
    try {
      setLoginError('');
      const userData = await api.login(username, password);

      // Reset UI state manually for instant transition (avoid slow reload)
      setActiveTab('gantt');
      setCollapsedLandscapes(new Set());
      setCollapsedSids(new Set());
      setCollapsedActivities(new Set());
      setEditingSidInfo(null);
      setBPendingDelete(null);
      setShowCsvDropdown(false);

      // Reset Gantt scroll position to "Today"
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const rangeStart = new Date(year, 0, 1);
      rangeStart.setDate(rangeStart.getDate() - 60);
      const offset = Math.max(0, Math.round((today - rangeStart) / (1000 * 60 * 60 * 24)));
      setViewOffset(offset);
      setUser(userData);
      if (userData.version) setAppVersion(userData.version);
      applyDarkMode(!!userData.dark_mode);
      if (userData.must_change_password) {
        setMustChangePassword(true);
      } else {
        await loadData();
      }
    } catch (error) {
      setLoginError(error.message);
    }
  };

  // Logout handler
  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (e) {}
    window.location.reload();
  };

  // Password change dialog state
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');

  // Password change handler
  const handlePasswordChange = async e => {
    e.preventDefault();
    const form = e.target;
    const currentPassword = form.currentPassword.value;
    const newPassword = form.newPassword.value;
    const confirmPassword = form.confirmPassword.value;
    setPasswordError('');
    setPasswordSuccess('');
    if (newPassword !== confirmPassword) {
      setPasswordError('Die neuen Passwörter stimmen nicht überein');
      return;
    }
    try {
      await api.changePassword(currentPassword, newPassword);
      setPasswordSuccess('Passwort erfolgreich geändert!');
      form.reset();

      // If this was a forced password change, load app data and enter the app
      if (mustChangePassword) {
        setMustChangePassword(false);
        setTimeout(async () => {
          setPasswordSuccess('');
          await loadData();
        }, 1500);
      } else {
        setTimeout(() => {
          setShowPasswordDialog(false);
          setPasswordSuccess('');
        }, 2000);
      }
    } catch (error) {
      setPasswordError(error.message);
    }
  };

  // User management state
  const [showUserDialog, setShowUserDialog] = useState(false);
  const [users, setUsers] = useState([]);
  const [userError, setUserError] = useState('');
  const [editingUser, setEditingUser] = useState(null);
  const [resetPasswordUserId, setResetPasswordUserId] = useState(null);
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [confirmDeleteUserId, setConfirmDeleteUserId] = useState(null);

  // Load users
  const loadUsers = async () => {
    try {
      const userList = await api.getUsers();
      setUsers(userList);
    } catch (error) {
      setUserError(error.message);
    }
  };

  // Open user dialog
  const openUserDialog = async () => {
    setShowUserDialog(true);
    setUserError('');
    setEditingUser(null);
    await loadUsers();
  };

  // Add new user
  const handleAddUser = async e => {
    e.preventDefault();
    const form = e.target;
    const username = form.newUsername.value.trim();
    const password = form.newPassword.value;
    const role = form.newRole.value;
    const first_name = form.newFirstName ? form.newFirstName.value.trim() : '';
    const last_name = form.newLastName ? form.newLastName.value.trim() : '';
    if (!username || !password || !first_name || !last_name) {
      setUserError('Benutzername, Passwort, Vorname und Nachname erforderlich');
      return;
    }
    try {
      setUserError('');
      await api.createUser({
        username,
        password,
        role,
        first_name,
        last_name
      });
      form.reset();
      await loadUsers();
    } catch (error) {
      setUserError(error.message);
    }
  };

  // Edit existing user - populate form
  const handleEditUser = u => {
    setEditingUser(u);
    setUserError('');
    // We need to set form values after React renders, so use a timeout
    setTimeout(() => {
      const form = document.querySelector('#userForm');
      if (form) {
        form.newUsername.value = u.username;
        form.newPassword.value = '••••••';
        form.newRole.value = u.role;
        form.newFirstName.value = u.first_name || '';
        form.newLastName.value = u.last_name || '';
        // Generate Kürzel from name
        const fn = (u.first_name || '').trim().toUpperCase();
        const ln = (u.last_name || '').trim().toUpperCase();
        form.newAbbreviation.value = fn && ln ? fn[0] + ln[0] + ln[ln.length - 1] : '';
      }
    }, 50);
  };

  // Cancel editing
  const handleCancelEdit = () => {
    setEditingUser(null);
    setUserError('');
    const form = document.querySelector('#userForm');
    if (form) form.reset();
  };

  // Update existing user
  const handleUpdateUser = async e => {
    e.preventDefault();
    if (!editingUser) return;
    const form = e.target;
    const role = form.newRole.value;
    const first_name = form.newFirstName ? form.newFirstName.value.trim() : '';
    const last_name = form.newLastName ? form.newLastName.value.trim() : '';
    if (!first_name || !last_name) {
      setUserError('Vorname und Nachname erforderlich');
      return;
    }
    try {
      setUserError('');
      await api.updateUser(editingUser.id, {
        role,
        first_name,
        last_name
      });
      setEditingUser(null);
      form.reset();
      await loadUsers();
    } catch (error) {
      setUserError(error.message);
    }
  };

  // Delete user
  const handleDeleteUser = async (userId, username) => {
    if (userId === user.id) {
      setUserError('Sie können sich nicht selbst löschen');
      return;
    }
    // Toggle inline confirmation
    if (confirmDeleteUserId === userId) {
      setConfirmDeleteUserId(null);
    } else {
      setConfirmDeleteUserId(userId);
      setUserError('');
    }
  };
  const confirmDeleteUser = async () => {
    try {
      await api.deleteUser(confirmDeleteUserId);
      setConfirmDeleteUserId(null);
      await loadUsers();
    } catch (error) {
      setUserError(error.message);
    }
  };

  // Reset user password - toggle inline input
  const handleResetPassword = userId => {
    if (resetPasswordUserId === userId) {
      // Toggle off if already open for this user
      setResetPasswordUserId(null);
      setResetPasswordValue('');
    } else {
      setResetPasswordUserId(userId);
      setResetPasswordValue('');
      setUserError('');
    }
  };

  // Submit the password reset
  const submitResetPassword = async () => {
    if (!resetPasswordValue || resetPasswordValue.length < 6) {
      setUserError('Passwort muss mindestens 6 Zeichen haben');
      return;
    }
    try {
      await api.updateUser(resetPasswordUserId, {
        password: resetPasswordValue
      });
      setResetPasswordUserId(null);
      setResetPasswordValue('');
      setUserError('');
      alert('Passwort wurde zurückgesetzt');
    } catch (error) {
      setUserError(error.message);
    }
  };

  // =========================================
  // LOGS MANAGEMENT
  // =========================================
  const [showLogsDialog, setShowLogsDialog] = useState(false);
  const [logs, setLogs] = useState('');
  const [logsLoading, setLogsLoading] = useState(false);
  const openLogsDialog = async () => {
    setShowLogsDialog(true);
    setLogsLoading(true);
    try {
      const logData = await api.getLogs();
      setLogs(logData.logs || '');
    } catch (error) {
      console.error('Error loading logs:', error);
    }
    setLogsLoading(false);
  };

  // =========================================
  // MAINTENANCE SUNDAYS MANAGEMENT
  // =========================================
  const [showMaintenanceDialog, setShowMaintenanceDialog] = useState(false);
  const [maintenanceSundays, setMaintenanceSundays] = useState([]);
  const [maintenanceLoading, setMaintenanceLoading] = useState(false);
  const [addSkillDialog, setAddSkillDialog] = useState({
    isOpen: false,
    name: ''
  });
  const [copySidDialog, setCopySidDialog] = useState({
    isOpen: false,
    sourceSidId: null,
    sourceLandscapeId: null,
    targetLandscapeId: '',
    newName: ''
  });
  const [deleteConfirm, setDeleteConfirm] = useState({
    isOpen: false,
    title: '',
    message: '',
    onConfirm: null
  });

  // Series popup state
  const [seriesPopup, setSeriesPopup] = useState({
    isOpen: false,
    series: null,
    landscapeId: null,
    sidId: null
  });

  // Load maintenance sundays with other data
  const loadMaintenanceSundays = async () => {
    try {
      const sundays = await api.getMaintenanceSundays();
      setMaintenanceSundays(sundays);
    } catch (error) {
      console.error('Error loading maintenance sundays:', error);
    }
  };
  const openMaintenanceDialog = async () => {
    setShowMaintenanceDialog(true);
    setMaintenanceLoading(true);
    await loadMaintenanceSundays();
    setMaintenanceLoading(false);
  };
  const handleMaintenanceSundayUpdate = async (id, date) => {
    try {
      const existing = maintenanceSundays.find(s => s.id === id);
      await api.updateMaintenanceSunday(id, date, existing?.label || `Wartungssonntag ${['I', 'II', 'III', 'IV'][id - 1]}`);
      await loadMaintenanceSundays();
    } catch (error) {
      alert('Fehler beim Speichern: ' + error.message);
    }
  };

  // Toggle collapse state for a single landscape
  const toggleLandscapeCollapse = landscapeId => {
    // If collapsing and our active SID is in this landscape, release the lock
    if (!collapsedLandscapes.has(landscapeId) && activeSidId) {
      const landscape = landscapes.find(l => l.id === landscapeId);
      if (landscape && landscape.sids.some(s => s.id === activeSidId)) {
        api.releaseLock(activeSidId).catch(() => {});
        api.ping(null).catch(() => {});
        setActiveSidId(null);
        setMySidLocks(new Set());
      }
    }
    setCollapsedLandscapes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(landscapeId)) {
        newSet.delete(landscapeId);
      } else {
        newSet.add(landscapeId);
      }
      return newSet;
    });
  };
  const toggleSidCollapse = sidId => {
    // If collapsing and this SID is currently locked by us, release the lock
    if (!collapsedSids.has(sidId) && activeSidId === sidId) {
      api.releaseLock(sidId).catch(() => {});
      api.ping(null).catch(() => {});
      setActiveSidId(null);
      setMySidLocks(new Set());
    }
    setCollapsedSids(prev => {
      const newSet = new Set(prev);
      if (newSet.has(sidId)) {
        newSet.delete(sidId);
      } else {
        newSet.add(sidId);
      }
      return newSet;
    });
  };

  // Collapse all landscapes
  const collapseAllLandscapes = () => {
    setCollapsedLandscapes(new Set(landscapes.map(l => l.id)));
  };

  // Expand all landscapes
  const expandAllLandscapes = () => {
    setCollapsedLandscapes(new Set());
  };

  // Add new activity type
  const addActivityType = async () => {
    if (!canEdit) return;
    const label = prompt('Name des neuen Aktivitätstyps:');
    if (!label || !label.trim()) return;
    const trimmedLabel = label.trim();

    // Derive a short slug ID from the label
    const slugBase = trimmedLabel.toLowerCase().replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss').replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');

    // Ensure uniqueness
    const existingIds = new Set(activityTypes.map(t => t.id));
    let newId = slugBase;
    let suffix = 2;
    while (existingIds.has(newId)) {
      newId = `${slugBase}_${suffix}`;
      suffix++;
    }
    const usedColors = activityTypes.map(t => t.color);
    const availableColor = availableColors.find(c => !usedColors.includes(c)) || '#6b7280';
    try {
      const newType = await api.createActivityType({
        id: newId,
        label: trimmedLabel,
        color: availableColor
      });
      setActivityTypes([...activityTypes, newType]);
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };

  // Rename activity type
  const renameActivityType = async (typeId, newLabel) => {
    if (!canEdit) return;
    try {
      await api.updateActivityType(typeId, {
        label: newLabel
      });
      setActivityTypes(activityTypes.map(t => t.id === typeId ? {
        ...t,
        label: newLabel
      } : t));
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };

  // Delete activity type
  const deleteActivityType = async typeId => {
    if (!canEdit) return;
    if (activityTypes.length <= 1) {
      alert('Es muss mindestens ein Aktivitätstyp vorhanden sein.');
      return;
    }
    if (confirm('Aktivitätstyp wirklich löschen?')) {
      try {
        await api.deleteActivityType(typeId);
        setActivityTypes(activityTypes.filter(t => t.id !== typeId));
      } catch (error) {
        alert('Fehler: ' + error.message);
      }
    }
  };

  // Memoized holidays
  const holidays = useMemo(() => getGermanHolidays(year, bundesland), [year, bundesland]);

  // Get today's date string using proper ISO format
  const todayDate = new Date();
  const today = formatDateISO(todayDate);
  const currentYear = todayDate.getFullYear();

  // =========================================================================
  // DATA MANAGEMENT (API-based)
  // =========================================================================

  const saveSettings = async () => {
    if (!canEdit) return;
    try {
      await api.updateSettings({
        year,
        bundesland
      });
      alert('Einstellungen gespeichert!');
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const addLandscape = async () => {
    if (!canEdit) return;
    try {
      const newLandscape = await api.createLandscape(`Neue Landschaft ${landscapes.length + 1}`);
      setLandscapes([...landscapes, newLandscape]);
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const deleteLandscape = async landscapeId => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Systemlandschaft löschen',
      message: 'Systemlandschaft wirklich löschen?',
      onConfirm: async () => {
        try {
          await api.deleteLandscape(landscapeId);
          setLandscapes(landscapes.filter(l => l.id !== landscapeId));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };
  const updateLandscape = async (landscapeId, field, value) => {
    if (!canEdit) return;
    try {
      const payload = {
        [field]: value
      };
      if (field === 'sort_order') {
        payload.sort_order = parseInt(value) || 0;
      }
      await api.updateLandscape(landscapeId, payload);

      // Reload all landscapes after sort_order change to see collision resolution
      if (field === 'sort_order') {
        const data = await api.getLandscapes();
        setLandscapes(data);
      } else {
        setLandscapes(prev => prev.map(l => l.id === landscapeId ? {
          ...l,
          [field]: value
        } : l));
      }
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const addSID = async landscapeId => {
    if (!canEdit) return;
    try {
      const newSid = await api.createSid(landscapeId, '', 'DEV', true);
      setLandscapes(landscapes.map(l => l.id === landscapeId ? {
        ...l,
        sids: [...l.sids, newSid]
      } : l));
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const deleteSID = async (landscapeId, sidId) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'SID löschen',
      message: 'SID wirklich löschen?',
      onConfirm: async () => {
        try {
          await api.deleteSid(sidId);
          setLandscapes(landscapes.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.filter(s => s.id !== sidId)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };
  const updateSID = async (landscapeId, sidId, field, value) => {
    // visibleInGantt is allowed for ALL users (uses separate endpoint)
    if (field === 'visibleInGantt') {
      try {
        await api.toggleSidVisibility(sidId, value);
        setLandscapes(landscapes.map(l => l.id === landscapeId ? {
          ...l,
          sids: l.sids.map(s => s.id !== sidId ? s : {
            ...s,
            [field]: value
          })
        } : l));
      } catch (error) {
        alert('Fehler: ' + error.message);
      }
      return;
    }
    if (!canEdit) return;
    const apiFieldMap = {
      'isPRD': 'is_prd',
      'visibleInGantt': 'visible_in_gantt'
    };
    const apiField = apiFieldMap[field] || field;
    try {
      await api.updateSid(sidId, {
        [apiField]: value
      });
      // Reload all landscapes after sort_order change to reflect re-sequenced numbers
      if (field === 'sort_order') {
        const data = await api.getLandscapes();
        setLandscapes(data);
      } else {
        setLandscapes(landscapes.map(l => l.id === landscapeId ? {
          ...l,
          sids: l.sids.map(s => s.id !== sidId ? s : {
            ...s,
            [field]: value
          })
        } : l));
      }
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const handleCopySid = async () => {
    try {
      if (!copySidDialog.targetLandscapeId || !copySidDialog.newName) return;
      await api.copySid(copySidDialog.sourceSidId, copySidDialog.targetLandscapeId, copySidDialog.newName);
      setCopySidDialog({
        isOpen: false,
        sourceSidId: null,
        sourceLandscapeId: null,
        targetLandscapeId: '',
        newName: ''
      });
      await loadData();
    } catch (error) {
      alert(error.message);
    }
  };
  const addActivity = async (landscapeId, sidId) => {
    if (!canEdit) return;
    const startDate = new Date().toISOString().split('T')[0];
    try {
      const newActivity = await api.createActivity({
        sid_id: sidId,
        type_id: 'installation',
        start_date: startDate,
        duration: 1,
        includes_weekend: false
      });
      newActivity.endDate = calculateEndDate(startDate, 1, year, bundesland, false); // Activities have their own includesWeekend flag

      setLandscapes(landscapes.map(l => l.id === landscapeId ? {
        ...l,
        sids: l.sids.map(s => s.id === sidId ? {
          ...s,
          activities: [...s.activities, newActivity]
        } : s)
      } : l));
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const deleteActivity = async (landscapeId, sidId, activityId) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Aktivität löschen',
      message: 'Aktivität wirklich unwiderruflich löschen?',
      onConfirm: async () => {
        try {
          await api.deleteActivity(activityId);
          setLandscapes(landscapes.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.map(s => s.id === sidId ? {
              ...s,
              activities: s.activities.filter(a => a.id !== activityId)
            } : s)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };
  const archiveActivity = async (landscapeId, sidId, activityId) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Aktivität archivieren',
      message: 'Möchten Sie diese Aktivität wirklich archivieren? Sie wird dadurch im Plan eingefroren.',
      onConfirm: async () => {
        try {
          await api.archiveActivity(activityId);
          setLandscapes(landscapes.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.map(s => s.id === sidId ? {
              ...s,
              activities: s.activities.map(a => a.id === activityId ? {
                ...a,
                status: 'ARCHIVED'
              } : a)
            } : s)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };

  // Convert activity to series
  const convertToSeries = async (landscapeId, sidId, activityId) => {
    if (!canEdit) return;
    try {
      const newSeries = await api.convertToSeries(activityId, sidId);
      setLandscapes(prev => prev.map(l => l.id === landscapeId ? {
        ...l,
        sids: l.sids.map(s => s.id === sidId ? {
          ...s,
          activities: s.activities.filter(a => a.id !== activityId),
          series: [...(s.series || []), newSeries]
        } : s)
      } : l));
      // Open the popup immediately
      setSeriesPopup({
        isOpen: true,
        series: newSeries,
        landscapeId,
        sidId
      });
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };

  // Delete an entire series
  const deleteSeriesHandler = (landscapeId, sidId, seriesId, occCount) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Serie löschen',
      message: `Serie mit ${occCount} Termin${occCount !== 1 ? 'en' : ''} wirklich löschen?`,
      onConfirm: async () => {
        try {
          await api.deleteSeries(seriesId);
          setLandscapes(prev => prev.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.map(s => s.id === sidId ? {
              ...s,
              series: (s.series || []).filter(sr => sr.id !== seriesId)
            } : s)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };

  // Open series popup editor
  const openSeriesPopup = (landscapeId, sidId, series) => {
    setSeriesPopup({
      isOpen: true,
      series,
      landscapeId,
      sidId
    });
  };

  // Refresh series data after editing in popup
  const refreshSeriesInState = async (landscapeId, sidId) => {
    try {
      await loadData();
    } catch (e) {
      console.error('Failed to refresh series', e);
    }
  };
  const updateActivity = async (landscapeId, sidId, activityId, field, value) => {
    const landscape = landscapes.find(l => l.id === landscapeId);
    const sid = landscape?.sids.find(s => s.id === sidId);
    const activity = sid?.activities.find(a => a.id === activityId);
    if (!canEdit) return;
    if (activity && activity.status && activity.status !== 'PLANNED') return; // Cannot edit archived/completed tasks

    if (field === 'teamMemberId' && value) value = parseInt(value, 10);
    if (field === 'duration') value = parseInt(value) >= 0 ? parseInt(value) : 1;
    const apiFieldMap = {
      type: 'type_id',
      startDate: 'start_date',
      includesWeekend: 'includes_weekend',
      teamMemberId: 'team_member_id',
      startTime: 'start_time',
      endTime: 'end_time'
    };
    const apiField = apiFieldMap[field] || field;
    if (activity) {
      if (field === 'startTime' && value && activity.end_time && value > activity.end_time) return;
      if (field === 'endTime' && value && activity.start_time && value < activity.start_time) return;
    }
    setLandscapes(prev => prev.map(l => l.id === landscapeId ? {
      ...l,
      sids: l.sids.map(s => s.id === sidId ? {
        ...s,
        activities: s.activities.map(a => {
          if (a.id === activityId) {
            const updated = {
              ...a,
              [field]: value
            };
            if (field === 'startTime') updated.start_time = value;
            if (field === 'endTime') updated.end_time = value;
            if (field === 'startDate' || field === 'duration' || field === 'includesWeekend') {
              const startDateVal = field === 'startDate' ? value : a.startDate;
              const durationVal = field === 'duration' ? parseInt(value) >= 0 ? parseInt(value) : 1 : parseInt(a.duration) >= 0 ? parseInt(a.duration) : 1;
              const includesWE = field === 'includesWeekend' ? value : a.includesWeekend || false;
              updated.endDate = calculateEndDate(startDateVal, durationVal, year, bundesland, includesWE);
              updated.duration = durationVal;
              // Clear time fields if duration >= 1 (times only valid for duration 0)
              if (durationVal >= 1) {
                updated.start_time = null;
                updated.end_time = null;
              }
            }
            return updated;
          }
          return a;
        })
      } : s)
    } : l));
    try {
      const updatePayload = {
        [apiField]: value
      };
      if (field === 'duration' && parseInt(value) >= 1) {
        updatePayload.start_time = null;
        updatePayload.end_time = null;
      }
      await api.updateActivity(activityId, updatePayload);
    } catch (error) {
      console.error(error);
      alert('Fehler: ' + error.message);
    }
  };

  // =========================================================================
  // SUB-ACTIVITY FUNCTIONS
  // =========================================================================

  const toggleActivityCollapse = activityId => {
    setCollapsedActivities(prev => {
      const newSet = new Set(prev);
      if (newSet.has(activityId)) {
        newSet.delete(activityId);
      } else {
        newSet.add(activityId);
      }
      return newSet;
    });
  };
  const addSubActivity = async (landscapeId, sidId, activityId) => {
    if (!canEdit) return;
    try {
      // Find the parent activity to get its start date as default
      const landscape = landscapes.find(l => l.id === landscapeId);
      const sid = landscape?.sids.find(s => s.id === sidId);
      const activity = sid?.activities.find(a => a.id === activityId);
      const startDate = activity?.startDate || formatDateISO(new Date());
      const newSubActivity = await api.createSubActivity({
        activity_id: activityId,
        name: 'Sub-Aktivität',
        start_date: startDate,
        duration: 1,
        includes_weekend: false
      });
      newSubActivity.endDate = calculateEndDate(startDate, 1, year, bundesland, false);
      setLandscapes(landscapes.map(l => l.id === landscapeId ? {
        ...l,
        sids: l.sids.map(s => s.id === sidId ? {
          ...s,
          activities: s.activities.map(a => a.id === activityId ? {
            ...a,
            subActivities: [...(a.subActivities || []), newSubActivity]
          } : a)
        } : s)
      } : l));
    } catch (error) {
      alert('Fehler: ' + error.message);
    }
  };
  const updateSubActivity = async (landscapeId, sidId, activityId, subActivityId, field, value) => {
    const landscape = landscapes.find(l => l.id === landscapeId);
    const sid = landscape?.sids.find(s => s.id === sidId);
    const activity = sid?.activities.find(a => a.id === activityId);
    const subActivity = activity?.subActivities?.find(sub => sub.id === subActivityId);
    if (!canEdit) return;
    if (subActivity && subActivity.status && subActivity.status !== 'PLANNED') return; // Cannot edit

    if (field === 'teamMemberId' && value) value = parseInt(value, 10);
    if (field === 'duration') value = parseInt(value) >= 0 ? parseInt(value) : 1;
    const apiFieldMap = {
      name: 'name',
      startDate: 'start_date',
      includesWeekend: 'includes_weekend',
      teamMemberId: 'team_member_id',
      startTime: 'start_time',
      endTime: 'end_time'
    };
    const apiField = apiFieldMap[field] || field;
    if (subActivity) {
      if (field === 'startTime' && value && subActivity.end_time && value > subActivity.end_time) return;
      if (field === 'endTime' && value && subActivity.start_time && value < subActivity.start_time) return;
    }
    setLandscapes(prev => prev.map(l => l.id === landscapeId ? {
      ...l,
      sids: l.sids.map(s => s.id === sidId ? {
        ...s,
        activities: s.activities.map(a => a.id === activityId ? {
          ...a,
          subActivities: (a.subActivities || []).map(sub => {
            if (sub.id === subActivityId) {
              const updated = {
                ...sub,
                [field]: value
              };
              if (field === 'startTime') updated.start_time = value;
              if (field === 'endTime') updated.end_time = value;
              if (field === 'startDate' || field === 'duration' || field === 'includesWeekend') {
                const startDateVal = field === 'startDate' ? value : sub.startDate;
                const durationVal = field === 'duration' ? parseInt(value) >= 0 ? parseInt(value) : 1 : parseInt(sub.duration) >= 0 ? parseInt(sub.duration) : 1;
                const includesWE = field === 'includesWeekend' ? value : sub.includesWeekend || false;
                updated.endDate = calculateEndDate(startDateVal, durationVal, year, bundesland, includesWE);
                updated.duration = durationVal;
                // Clear time fields if duration >= 1 (times only valid for duration 0)
                if (durationVal >= 1) {
                  updated.start_time = null;
                  updated.end_time = null;
                }
              }
              return updated;
            }
            return sub;
          })
        } : a)
      } : s)
    } : l));
    try {
      const updatePayload = {
        [apiField]: value
      };
      if (field === 'duration' && parseInt(value) >= 1) {
        updatePayload.start_time = null;
        updatePayload.end_time = null;
      }
      await api.updateSubActivity(subActivityId, updatePayload);
    } catch (error) {
      console.error(error);
      alert('Fehler: ' + error.message);
    }
  };
  const deleteSubActivity = async (landscapeId, sidId, activityId, subActivityId) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Sub-Aktivität löschen',
      message: 'Sub-Aktivität wirklich unwiderruflich löschen?',
      onConfirm: async () => {
        try {
          await api.deleteSubActivity(subActivityId);
          setLandscapes(landscapes.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.map(s => s.id === sidId ? {
              ...s,
              activities: s.activities.map(a => a.id === activityId ? {
                ...a,
                subActivities: (a.subActivities || []).filter(sub => sub.id !== subActivityId)
              } : a)
            } : s)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };
  const archiveSubActivity = async (landscapeId, sidId, activityId, subActivityId) => {
    if (!canEdit) return;
    setDeleteConfirm({
      isOpen: true,
      title: 'Sub-Aktivität archivieren',
      message: 'Sub-Aktivität wirklich archivieren? Sie wird dadurch im Plan eingefroren.',
      onConfirm: async () => {
        try {
          await api.archiveSubActivity(subActivityId);
          setLandscapes(landscapes.map(l => l.id === landscapeId ? {
            ...l,
            sids: l.sids.map(s => s.id === sidId ? {
              ...s,
              activities: s.activities.map(a => a.id === activityId ? {
                ...a,
                subActivities: (a.subActivities || []).map(sub => sub.id === subActivityId ? {
                  ...sub,
                  status: 'ARCHIVED'
                } : sub)
              } : a)
            } : s)
          } : l));
        } catch (error) {
          alert('Fehler: ' + error.message);
        }
      }
    });
  };

  // =========================================================================
  // EXPORT/IMPORT FUNCTIONS  
  // =========================================================================

  const exportJSON = () => {
    try {
      // Filter landscapes and SIDs by visibility
      const filteredLandscapes = landscapes.map(l => ({
        ...l,
        sids: l.sids.filter(sid => sid.visibleInGantt !== false)
      })).filter(l => l.sids.length > 0);
      const dataObj = {
        year,
        bundesland,
        landscapes: filteredLandscapes,
        activityTypes
      };
      const dataStr = JSON.stringify(dataObj, null, 2);
      const blob = new Blob([dataStr], {
        type: 'application/json;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sap-basis-planung-${year}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (err) {
      alert('Fehler beim Export: ' + err.message);
    }
  };
  const exportCSV = () => {
    try {
      const BOM = '\ufeff';
      const now = new Date();
      const timestamp = now.getFullYear().toString() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0') + '-' + String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0') + String(now.getSeconds()).padStart(2, '0');
      const lines = ['Systemlandschaft;SID;Typ;Aktivitätstyp;ID;Sub-Aktivität;Serie;Startdatum;Dauer (Arbeitstage);Enddatum;Startzeit;Endzeit;Wochenende inkludiert'];
      landscapes.forEach(landscape => {
        // Only export landscapes that have at least one visible SID
        const visibleSids = landscape.sids.filter(sid => sid.visibleInGantt !== false);
        if (visibleSids.length === 0) return;
        visibleSids.forEach(sid => {
          // Prepare a flattened list of all "renderables" (activities, sub-activities, series occurrences)
          const exportItems = [];

          // 1. Regular Activities
          (sid.activities || []).forEach(act => {
            const hasSub = (act.subActivities || []).length > 0;
            if (hasSub) {
              act.subActivities.forEach(sub => {
                exportItems.push({
                  id: sub.id,
                  typeId: act.type || act.type_id,
                  name: sub.name,
                  startDate: sub.startDate || sub.start_date,
                  endDate: sub.endDate || sub.end_date,
                  duration: sub.duration,
                  startTime: sub.startTime || sub.start_time || '',
                  endTime: sub.endTime || sub.end_time || '',
                  isSub: true,
                  isSeries: false,
                  includesWeekend: sub.includesWeekend !== undefined ? sub.includesWeekend : sub.includes_weekend || false
                });
              });
            } else {
              exportItems.push({
                id: act.id,
                typeId: act.type || act.type_id,
                name: '',
                startDate: act.startDate || act.start_date,
                endDate: act.endDate || act.end_date,
                duration: act.duration,
                startTime: act.startTime || act.start_time || '',
                endTime: act.endTime || act.end_time || '',
                isSub: false,
                isSeries: false,
                includesWeekend: act.includesWeekend !== undefined ? act.includesWeekend : act.includes_weekend || false
              });
            }
          });

          // 2. Series Occurrences
          (sid.series || []).forEach(series => {
            (series.occurrences || []).forEach(occ => {
              exportItems.push({
                id: `occ_${occ.id}`,
                // Occurrences might need a prefix to distinguish from regular activities if IDs overlap, but using the DB id is fine 'occ.id'
                typeId: series.typeId || series.type_id,
                name: '',
                startDate: occ.date || occ.startDate || occ.start_date,
                endDate: occ.date || occ.endDate || occ.end_date,
                duration: 1,
                startTime: occ.startTime || occ.start_time || series.defaultStartTime || series.default_start_time || '',
                endTime: occ.endTime || occ.end_time || series.defaultEndTime || series.default_end_time || '',
                isSub: false,
                isSeries: true,
                includesWeekend: occ.includesWeekend !== undefined ? occ.includesWeekend : occ.includes_weekend || false
              });
            });
          });
          const sidType = sid.systemType || (sid.isPRD ? 'PRD' : 'DEV');
          if (exportItems.length === 0) {
            lines.push(`${landscape.name};${sid.name};${sidType};;;;;;;;;;`);
          } else {
            exportItems.forEach(item => {
              const actType = activityTypes.find(t => t.id === item.typeId);
              const actLabel = actType?.label || item.typeId || '';
              lines.push(`${landscape.name};${sid.name};${sidType};${actLabel};${item.typeId || ''};${item.name};${item.isSeries ? 'Ja' : 'Nein'};${formatDateDE(item.startDate)};${item.duration};${formatDateDE(item.endDate)};${item.startTime};${item.endTime};${item.includesWeekend ? 'Ja' : 'Nein'}`);
            });
          }
        });
      });
      const csvContent = BOM + lines.join('\r\n');
      const blob = new Blob([csvContent], {
        type: 'text/csv;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SAP-Basis-Planung-${year}-${timestamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (err) {
      alert('Fehler beim CSV Export: ' + err.message);
    }
  };
  const exportTeamCSV = () => {
    try {
      const BOM = '\ufeff';
      const now = new Date();
      const timestamp = now.getFullYear().toString() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0') + '-' + String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0') + String(now.getSeconds()).padStart(2, '0');
      const lines = ['Teammitglied;Kürzel;Arbeitstage;Schulungen;Verplant Q1;Verplant Q2;Verplant Q3;Verplant Q4;Verplante Tage;Verfügbare Tage'];
      teamMembers.forEach(member => {
        let totalDays = 0;
        const quarterDays = [0, 0, 0, 0];
        landscapes.forEach(landscape => {
          landscape.sids.forEach(sid => {
            sid.activities.forEach(activity => {
              const getQuarter = item => {
                const sd = item.startDate || item.start_date;
                if (sd) {
                  const month = new Date(sd).getMonth();
                  return Math.floor(month / 3);
                }
                return -1;
              };
              const actMemberId = activity.teamMemberId || activity.team_member_id;
              if (actMemberId === member.id) {
                if (!activity.subActivities || activity.subActivities.length === 0) {
                  const dur = parseInt(activity.duration) || 0;
                  totalDays += dur;
                  const q = getQuarter(activity);
                  if (q >= 0) quarterDays[q] += dur;
                }
              }
              (activity.subActivities || []).forEach(sub => {
                const subMemberId = sub.teamMemberId || sub.team_member_id;
                if (subMemberId === member.id) {
                  const dur = parseInt(sub.duration) || 0;
                  totalDays += dur;
                  const q = getQuarter(sub);
                  if (q >= 0) quarterDays[q] += dur;
                }
              });
            });
          });
        });
        const availableDays = (member.working_days || 0) - (member.training_days || 0) - totalDays;
        lines.push(`${member.name};${member.abbreviation};${member.working_days || 0};${member.training_days || 0};${quarterDays[0]};${quarterDays[1]};${quarterDays[2]};${quarterDays[3]};${totalDays};${availableDays}`);
      });
      const csvContent = BOM + lines.join('\r\n');
      const blob = new Blob([csvContent], {
        type: 'text/csv;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SAP-Basis-Ressourcen-${year}-${timestamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (err) {
      alert('Fehler beim Team CSV Export: ' + err.message);
    }
  };
  const exportSkillsCSV = () => {
    try {
      const BOM = '\ufeff';
      const now = new Date();
      const timestamp = now.getFullYear().toString() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0') + '-' + String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0') + String(now.getSeconds()).padStart(2, '0');
      const lines = [];

      // Section 1: Skill Matrix
      lines.push('=== Skill-Matrix ===');
      const skillHeaders = ['Teammitglied', ...matrixColumns.map(c => c.name), 'Gesamt'];
      lines.push(skillHeaders.join(';'));
      teamMembers.forEach(member => {
        let total = 0;
        const ratings = matrixColumns.map(col => {
          const val = matrixValues.find(v => v.team_member_id === member.id && v.column_id === col.id);
          const level = val ? val.level : 0;
          total += level;
          return level;
        });
        lines.push([member.name, ...ratings, total].join(';'));
      });

      // Section 2: Schulungen
      lines.push('');
      lines.push('=== Schulungen ===');
      lines.push('Teilnehmer;Kurs;Thema;Kosten;Ort;Termin 1;Termin 2;Termin 3;Tage;Gebucht');
      trainings.forEach(tr => {
        lines.push([tr.participants || '', tr.course || '', tr.topic || '', tr.cost || '', tr.location || '', tr.date1 || '', tr.date2 || '', tr.date3 || '', tr.days || '', tr.booked_date > 0 ? 'Ja' : 'Nein'].join(';'));
      });
      const csvContent = BOM + lines.join('\r\n');
      const blob = new Blob([csvContent], {
        type: 'text/csv;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SAP-Basis-Skills-${year}-${timestamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (err) {
      alert('Fehler beim Skills CSV Export: ' + err.message);
    }
  };
  const exportBereitschaftCSV = () => {
    try {
      const BOM = '\ufeff';
      const now = new Date();
      const timestamp = now.getFullYear().toString() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0') + '-' + String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0') + String(now.getSeconds()).padStart(2, '0');
      const lines = ['KW;Wochenanfang;Wochenende;Kürzel'];

      // Sort bereitschaft by week_start
      const sorted = [...bereitschaft].sort((a, b) => a.week_start.localeCompare(b.week_start));
      sorted.forEach(entry => {
        const startDate = new Date(entry.week_start);
        const endDate = new Date(startDate);
        endDate.setDate(endDate.getDate() + 6);

        // Calculate calendar week (ISO 8601)
        const tempDate = new Date(startDate.getTime());
        tempDate.setDate(tempDate.getDate() + 3 - (tempDate.getDay() + 6) % 7);
        const week1 = new Date(tempDate.getFullYear(), 0, 4);
        const kw = 1 + Math.round(((tempDate - week1) / 86400000 - 3 + (week1.getDay() + 6) % 7) / 7);
        const formatDE = d => `${String(d.getDate()).padStart(2, '0')}.${String(d.getMonth() + 1).padStart(2, '0')}.${d.getFullYear()}`;
        lines.push(`KW${kw};${formatDE(startDate)};${formatDE(endDate)};${entry.abbreviation || ''}`);
      });
      const csvContent = BOM + lines.join('\r\n');
      const blob = new Blob([csvContent], {
        type: 'text/csv;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SAP-Basis-Bereitschaft-${year}-${timestamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (err) {
      alert('Fehler beim Bereitschaft CSV Export: ' + err.message);
    }
  };
  const importJSON = async event => {
    if (!canEdit) return;
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async e => {
      try {
        const text = e.target?.result;
        if (typeof text !== 'string') {
          throw new Error('Datei konnte nicht gelesen werden');
        }
        const data = JSON.parse(text);

        // Import via API
        await api.importJson(data);

        // Reload data from server
        await loadData();
        alert('Daten erfolgreich importiert!');
      } catch (err) {
        alert('Fehler beim Importieren: ' + err.message);
      }
    };
    reader.onerror = () => {
      alert('Fehler beim Lesen der Datei');
    };
    reader.readAsText(file, 'UTF-8');
    // Reset input so same file can be imported again
    event.target.value = '';
  };

  // =========================================================================
  // GANTT CHART RENDERING
  // =========================================================================

  const renderGanttChart = () => {
    const yearStart = new Date(year, 0, 1);
    const yearEnd = new Date(year, 11, 31);
    const totalDaysInYear = Math.ceil((yearEnd - yearStart) / (1000 * 60 * 60 * 24)) + 1;
    let allDays = [];
    let visibleDays = [];
    let headerCells = [];
    let dayWidth = 0;
    const todayDate = new Date();
    todayDate.setHours(0, 0, 0, 0);
    const todayTime = todayDate.getTime();
    const todayStr = formatDateISO(todayDate);

    // Determine the base date range based on view mode
    let rangeStart, rangeEnd;
    if (viewMode === 'year') {
      rangeStart = yearStart;
      rangeEnd = yearEnd;
    } else if (viewMode === 'week') {
      // Week view: 420 days total, starting 60 days before Jan 1 of the selected year
      rangeStart = new Date(year, 0, 1);
      rangeStart.setDate(rangeStart.getDate() - 60);
      rangeEnd = new Date(rangeStart);
      rangeEnd.setDate(rangeEnd.getDate() + 419); // 420 days total
    } else {
      // Quarter view: show selected quarter
      rangeStart = new Date(year, (selectedQuarter - 1) * 3, 1);
      rangeEnd = new Date(year, selectedQuarter * 3, 0);
    }

    // Calculate if today is in the current range
    const isTodayInRange = todayTime >= rangeStart.getTime() && todayTime <= rangeEnd.getTime();
    const todayOffset = isTodayInRange ? Math.max(0, Math.round((todayTime - rangeStart.getTime()) / (1000 * 60 * 60 * 24))) : 0;

    // Calculate all days in the range
    const rangeDays = Math.ceil((rangeEnd - rangeStart) / (1000 * 60 * 60 * 24)) + 1;
    for (let i = 0; i < rangeDays; i++) {
      const date = new Date(rangeStart);
      date.setDate(date.getDate() + i);
      allDays.push(date);
    }

    // Apply offset for navigation (slider/buttons)
    // For week/quarter view: show a window of days that slides across the range
    const daysToShow = 65; // Number of days visible at once
    const maxOffset = Math.max(0, allDays.length - daysToShow);
    const effectiveOffset = Math.min(viewOffset, maxOffset);
    const visibleCount = viewMode === 'year' ? allDays.length : Math.min(daysToShow, allDays.length - effectiveOffset);
    visibleDays = allDays.slice(effectiveOffset, effectiveOffset + visibleCount);
    dayWidth = 100 / visibleDays.length;

    // Build header cells based on view mode
    if (viewMode === 'year') {
      // Month headers for year view
      for (let m = 0; m < 12; m++) {
        const monthStart = new Date(year, m, 1);
        const monthEnd = new Date(year, m + 1, 0);

        // Find indices in visibleDays
        const startIdx = visibleDays.findIndex(d => formatDateISO(d) === formatDateISO(monthStart));
        const endIdx = visibleDays.findIndex(d => formatDateISO(d) === formatDateISO(monthEnd));
        if (startIdx >= 0 && endIdx >= 0) {
          const width = (endIdx - startIdx + 1) / visibleDays.length * 100;
          headerCells.push({
            label: monthStart.toLocaleDateString('de-DE', {
              month: 'short'
            }),
            width,
            startDay: startIdx
          });
        }
      }
    } else if (viewMode === 'quarter') {
      // Week headers for quarter view
      let weekProcessed = new Set();
      visibleDays.forEach((date, idx) => {
        const weekNum = getISOWeekNumber(date);
        const weekdayIdx = getWeekdayIndex(date);
        if (weekdayIdx === 0 || idx === 0) {
          // Monday or first day
          if (!weekProcessed.has(weekNum)) {
            weekProcessed.add(weekNum);
            // Count how many days in this week are visible
            let weekDayCount = 0;
            for (let i = idx; i < visibleDays.length && weekDayCount < 7; i++) {
              if (getISOWeekNumber(visibleDays[i]) === weekNum) {
                weekDayCount++;
              } else {
                break;
              }
            }
            const width = weekDayCount / visibleDays.length * 100;
            headerCells.push({
              label: `KW ${weekNum}`,
              width,
              startDay: idx
            });
          }
        }
      });
    } else if (viewMode === 'week') {
      // Individual day headers with weekday letters and day numbers
      let currentWeek = -1;
      visibleDays.forEach((date, idx) => {
        const weekNum = getISOWeekNumber(date);
        const weekdayIdx = getWeekdayIndex(date); // 0=Mon, 6=Sun
        const dayLetter = weekDayLetters[weekdayIdx];
        const dayNumber = date.getDate(); // Day of month (1-31)
        const isNewWeek = weekNum !== currentWeek;
        headerCells.push({
          label: dayLetter,
          dayNumber: dayNumber,
          weekNum: weekNum,
          width: dayWidth,
          startDay: idx,
          isNewWeek: isNewWeek,
          monthName: date.toLocaleDateString('de-DE', {
            month: 'long',
            year: 'numeric'
          }) // Add month name with year
        });
        currentWeek = weekNum;
      });
    }

    // Use maxOffset for slider (already calculated above)
    const sliderMax = maxOffset;
    return /*#__PURE__*/React.createElement("div", {
      className: "bg-white rounded-lg shadow-lg p-4 mb-6 overflow-hidden"
    }, /*#__PURE__*/React.createElement("h2", {
      className: "text-xl font-bold mb-4"
    }, "Gantt-Chart ", year), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 mb-4 flex-wrap w-1/2"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setViewOffset(Math.max(0, viewOffset - 7)),
      className: "flex items-center gap-1 px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 text-sm",
      title: "7 Tage zur\xFCck"
    }, /*#__PURE__*/React.createElement(ChevronLeftIcon, null), " Woche"), /*#__PURE__*/React.createElement("button", {
      onClick: () => setViewOffset(Math.max(0, viewOffset - 1)),
      className: "flex items-center gap-1 px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 text-sm",
      title: "1 Tag zur\xFCck"
    }, /*#__PURE__*/React.createElement(ChevronLeftIcon, null), " Tag"), /*#__PURE__*/React.createElement("input", {
      name: "autoField_1",
      type: "range",
      min: "0",
      max: sliderMax,
      value: Math.min(viewOffset, sliderMax),
      onChange: e => setViewOffset(parseInt(e.target.value)),
      className: "flex-1 min-w-32",
      title: `Tag ${viewOffset + 1}`
    }), /*#__PURE__*/React.createElement("button", {
      onClick: () => setViewOffset(Math.min(sliderMax, viewOffset + 1)),
      className: "flex items-center gap-1 px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 text-sm",
      title: "1 Tag vor"
    }, "Tag ", /*#__PURE__*/React.createElement(ChevronRightIcon, null)), /*#__PURE__*/React.createElement("button", {
      onClick: () => setViewOffset(Math.min(sliderMax, viewOffset + 7)),
      className: "flex items-center gap-1 px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 text-sm",
      title: "7 Tage vor"
    }, "Woche ", /*#__PURE__*/React.createElement(ChevronRightIcon, null)), /*#__PURE__*/React.createElement("button", {
      onClick: () => setViewOffset(todayOffset),
      disabled: !isTodayInRange,
      className: `px-3 py-1 rounded text-sm transition-colors ${isTodayInRange ? 'bg-blue-100 text-blue-700 hover:bg-blue-200' : 'bg-gray-100 text-gray-400 cursor-not-allowed opacity-60'}`,
      title: isTodayInRange ? "Heute anzeigen" : "Heute liegt nicht im gewählten Zeitraum"
    }, "Heute")), /*#__PURE__*/React.createElement("div", {
      className: "min-w-max"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex border-b-2 border-gray-300 mb-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "gantt-row-label min-w-48 font-semibold p-2 bg-gray-50"
    }, "Systemlandschaft / SID"), /*#__PURE__*/React.createElement("div", {
      className: "flex-1 flex relative"
    }, viewMode === 'week' ?
    /*#__PURE__*/
    // Week view: three rows - KW on top, weekday letters middle, day numbers bottom
    React.createElement("div", {
      className: "flex flex-col w-full"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex w-full border-b border-gray-200"
    }, (() => {
      const monthGroups = [];
      let currentMonthStr = null;
      let monthStartIdx = 0;

      // Group days by Month
      headerCells.forEach((cell, idx) => {
        // headerCells are days in 'week' view mode
        // We can use the monthName we already pre-calculated in cell
        if (cell.monthName !== currentMonthStr) {
          if (currentMonthStr !== null) {
            monthGroups.push({
              monthName: currentMonthStr,
              count: idx - monthStartIdx
            });
          }
          currentMonthStr = cell.monthName;
          monthStartIdx = idx;
        }
      });
      // Push last group
      if (currentMonthStr !== null) {
        monthGroups.push({
          monthName: currentMonthStr,
          count: headerCells.length - monthStartIdx
        });
      }
      return monthGroups.map((mg, idx) => /*#__PURE__*/React.createElement("div", {
        key: idx,
        className: "relative h-6 bg-white border-l border-gray-300",
        style: {
          flex: mg.count,
          minWidth: `${mg.count * 20}px`
        }
      }, /*#__PURE__*/React.createElement("span", {
        className: "absolute left-0 top-0 pl-1 font-bold text-gray-800 text-xs whitespace-nowrap bg-white pr-2 z-10"
      }, mg.monthName)));
    })()), /*#__PURE__*/React.createElement("div", {
      className: "flex w-full"
    }, (() => {
      // Group days by week number
      const weekGroups = [];
      let currentWeekNum = null;
      let weekStartIdx = 0;
      headerCells.forEach((cell, idx) => {
        if (cell.weekNum !== currentWeekNum) {
          if (currentWeekNum !== null) {
            weekGroups.push({
              weekNum: currentWeekNum,
              count: idx - weekStartIdx
            });
          }
          currentWeekNum = cell.weekNum;
          weekStartIdx = idx;
        }
      });
      if (currentWeekNum !== null) {
        weekGroups.push({
          weekNum: currentWeekNum,
          count: headerCells.length - weekStartIdx
        });
      }
      return weekGroups.map((wg, idx) => {
        return /*#__PURE__*/React.createElement("div", {
          key: idx,
          className: "text-center text-[10px] text-blue-600 font-medium border-l border-blue-400 relative",
          style: {
            flex: wg.count,
            minWidth: `${wg.count * 20}px`
          }
        }, "KW", wg.weekNum);
      });
    })()), /*#__PURE__*/React.createElement("div", {
      className: "flex w-full"
    }, headerCells.map((cell, idx) => /*#__PURE__*/React.createElement("div", {
      key: idx,
      className: `text-center text-xs font-medium border-l border-gray-200 flex-1 ${cell.isNewWeek ? 'border-l border-blue-400' : ''}`,
      style: {
        minWidth: '20px'
      }
    }, cell.label))), /*#__PURE__*/React.createElement("div", {
      className: "flex w-full"
    }, headerCells.map((cell, idx) => /*#__PURE__*/React.createElement("div", {
      key: idx,
      className: `text-center text-[10px] text-gray-500 border-l border-gray-200 flex-1 ${cell.isNewWeek ? 'border-l border-blue-400' : ''}`,
      style: {
        minWidth: '20px'
      }
    }, cell.dayNumber)))) :
    // Year/Quarter view
    headerCells.map((cell, idx) => /*#__PURE__*/React.createElement("div", {
      key: idx,
      className: "text-center text-sm font-medium border-l border-gray-200 px-1 py-2 whitespace-nowrap overflow-hidden text-ellipsis",
      style: {
        width: `${cell.width}%`
      }
    }, cell.label)))), landscapes.map(landscape => {
      const visibleSids = landscape.sids.filter(sid => sid.visibleInGantt !== false);
      if (visibleSids.length === 0) return null;
      return /*#__PURE__*/React.createElement("div", {
        key: landscape.id,
        className: "mb-4"
      }, /*#__PURE__*/React.createElement("div", {
        className: "font-semibold text-lg mb-1 text-blue-700 px-2"
      }, landscape.name), visibleSids.map(sid => {
        // Build a unified flat array of all renderables (normal activities AND subActivities)
        const allRenderables = [];
        sid.activities.forEach(act => {
          if (act.type === 'update' && (act.subActivities || []).length > 0) {
            (act.subActivities || []).forEach(sub => {
              allRenderables.push({
                ...sub,
                isSub: true,
                parentType: act.type,
                endDate: sub.endDate || calculateEndDate(sub.startDate, sub.duration || 1, year, bundesland, sub.includesWeekend || false)
              });
            });
          } else {
            allRenderables.push({
              ...act,
              isSub: false,
              endDate: act.endDate || calculateEndDate(act.startDate, act.duration || 1, year, bundesland, act.includesWeekend || false)
            });
          }
        });

        // Add series occurrences
        (sid.series || []).forEach(series => {
          const seriesType = activityTypes.find(t => t.id === series.typeId);
          (series.occurrences || []).forEach(occ => {
            allRenderables.push({
              ...occ,
              id: `occ-${occ.id}`,
              color: seriesType?.color || '#3B82F6',
              name: seriesType?.label || series.typeId,
              startDate: occ.date,
              endDate: occ.date,
              duration: 1,
              isSub: false,
              isSeriesOccurrence: true,
              seriesId: series.id,
              type: series.typeId
            });
          });
        });
        const checkOverlap = (a, b) => new Date(a.startDate) <= new Date(b.endDate) && new Date(b.startDate) <= new Date(a.endDate);
        const assigned = [];
        let maxLanes = 1;

        // Sort by start date for a better left-to-right packing
        allRenderables.sort((a, b) => new Date(a.startDate).getTime() - new Date(b.startDate).getTime());
        allRenderables.forEach(item => {
          const usedLanes = new Set();
          assigned.forEach(prev => {
            if (checkOverlap(prev, item)) usedLanes.add(prev.lane);
          });
          let lane = 0;
          while (usedLanes.has(lane)) lane++;
          assigned.push({
            ...item,
            lane
          });
          maxLanes = Math.max(maxLanes, lane + 1);
        });
        if (assigned.length === 0) maxLanes = 1;

        // Row height and bar sizing based on lanes
        const barHeight = maxLanes === 1 ? 24 : maxLanes === 2 ? 20 : maxLanes === 3 ? 16 : 12;
        const baseTop = 4;
        const rowHeight = Math.max(40, baseTop + maxLanes * (barHeight + 2) + 4);
        const darkenColor = (color, amt) => {
          const hex = (color || '#3B82F6').replace('#', '');
          const r = Math.max(0, parseInt(hex.substring(0, 2), 16) - amt);
          const g = Math.max(0, parseInt(hex.substring(2, 4), 16) - amt);
          const b = Math.max(0, parseInt(hex.substring(4, 6), 16) - amt);
          return `rgb(${r}, ${g}, ${b})`;
        };
        return /*#__PURE__*/React.createElement("div", {
          key: sid.id,
          className: "flex items-stretch"
        }, /*#__PURE__*/React.createElement("div", {
          className: `gantt-row-label min-w-48 pl-4 text-sm flex items-center gap-1 py-1 border-b ${viewMode === 'year' ? 'border-gray-400' : 'border-gray-100'}`
        }, /*#__PURE__*/React.createElement("span", {
          className: sid.systemType === 'PRD' || sid.isPRD ? 'font-bold text-red-600' : ''
        }, sid.name || 'Neue SID'), /*#__PURE__*/React.createElement("span", {
          className: `text-[10px] ml-2 px-1.5 py-0.5 rounded ${getSystemTypeColor(sid.systemType || (sid.isPRD ? 'PRD' : 'DEV'))}`
        }, sid.systemType || (sid.isPRD ? 'PRD' : 'DEV'))), /*#__PURE__*/React.createElement("div", {
          className: `flex-1 relative border-l border-gray-200 border-b ${viewMode === 'year' ? 'border-gray-400' : 'border-gray-100'}`,
          style: {
            height: `${rowHeight}px`
          }
        }, /*#__PURE__*/React.createElement("div", {
          className: "absolute inset-0 flex"
        }, visibleDays.map((date, idx) => {
          const dateStr = formatDateISO(date);
          const isWE = isWeekend(date);
          const isHoliday = holidays.has(dateStr);
          const isMaintenanceSunday = maintenanceSundays.some(s => s.date === dateStr);
          const isToday = dateStr === today && year === currentYear;
          return /*#__PURE__*/React.createElement("div", {
            key: idx,
            className: `
                                  h-full border-r border-gray-100
                                  ${isWE ? 'weekend-pattern' : ''}
                                  ${isHoliday ? 'holiday-pattern' : ''}
                                  ${isMaintenanceSunday ? 'maintenance-pattern' : ''}
                                  ${isToday ? 'today-marker' : ''}
                                `,
            style: {
              width: `${dayWidth}%`,
              minWidth: viewMode === 'week' ? '20px' : '0'
            },
            title: `${date.toLocaleDateString('de-DE', {
              weekday: 'short',
              day: '2-digit',
              month: '2-digit'
            })}${isHoliday ? ' - ' + holidays.get(dateStr) : ''}${isMaintenanceSunday ? ' - Wartungssonntag' : ''}`
          });
        })), assigned.flatMap(item => {
          const actType = activityTypes.find(t => t.id === (item.isSub ? item.parentType : item.type));
          const baseColor = actType?.color || '#3B82F6';
          const barColor = item.lane % 2 === 0 ? baseColor : darkenColor(baseColor, 40);
          const topOffset = baseTop + item.lane * (barHeight + 2);
          const segments = getActivitySegments(item.startDate, item.endDate, item.includesWeekend || false, holidays);
          const frame = segments.length > 1 && !item.includesWeekend ? (() => {
            const startIdx = visibleDays.findIndex(d => formatDateISO(d) === formatDateISO(new Date(item.startDate)));
            const endIdx = visibleDays.findIndex(d => formatDateISO(d) === formatDateISO(new Date(item.endDate)));
            if (endIdx < 0 && startIdx < 0) return null;
            if (startIdx >= 0 && startIdx >= visibleDays.length) return null;
            if (endIdx >= 0 && endIdx < 0) return null;
            const effStart = startIdx >= 0 ? startIdx : 0;
            const effEnd = endIdx >= 0 ? endIdx : visibleDays.length - 1;
            const lPct = effStart / visibleDays.length * 100;
            const wPct = (effEnd - effStart + 1) / visibleDays.length * 100;
            if (wPct <= 0) return null;
            return /*#__PURE__*/React.createElement("div", {
              key: `frame-${item.isSub ? 'sub-' : ''}${item.id}`,
              className: "absolute rounded border border-solid pointer-events-none",
              style: {
                left: `${lPct}%`,
                width: `${wPct}%`,
                borderColor: item.isSub ? barColor : actType?.color,
                borderWidth: '1px',
                top: `${topOffset}px`,
                height: `${barHeight}px`,
                zIndex: 5
              }
            });
          })() : null;
          return [frame, ...segments.map((segment, segIdx) => {
            const startIdx = visibleDays.findIndex(d => formatDateISO(d) === segment.start);
            const endIdx = visibleDays.findIndex(d => formatDateISO(d) === segment.end);
            if (endIdx < 0 && startIdx < 0) return null;
            const effectiveStartIdx = startIdx >= 0 ? startIdx : 0;
            const effectiveEndIdx = endIdx >= 0 ? endIdx : visibleDays.length - 1;
            if (startIdx >= 0 && startIdx >= visibleDays.length) return null;
            if (endIdx >= 0 && endIdx < 0) return null;
            const leftPct = effectiveStartIdx / visibleDays.length * 100;
            const widthPct = (effectiveEndIdx - effectiveStartIdx + 1) / visibleDays.length * 100;
            if (widthPct <= 0) return null;
            const isFirstSegment = segIdx === 0;
            let titleStr = '';
            if (item.isSub) {
              titleStr = `${item.name}: ${formatDateDE(item.startDate)} - ${formatDateDE(item.endDate)} (${item.duration} AT)${item.start_time && item.end_time ? ` (${item.start_time} - ${item.end_time})` : ''}${item.teamMemberId ? ` [${teamMembers.find(m => m.id === parseInt(item.teamMemberId))?.abbreviation || '?'}]` : ''}`;
            } else {
              let teamInfo = '';
              if (item.teamMemberId) {
                const member = teamMembers.find(m => m.id === parseInt(item.teamMemberId));
                teamInfo = member ? ` [${member.abbreviation}]` : '';
              }
              const timeInfo = item.start_time && item.end_time ? ` (${item.start_time} - ${item.end_time})` : '';
              titleStr = `${actType?.label}: ${formatDateDE(item.startDate)} - ${formatDateDE(item.endDate)} (${item.duration} Arbeitstage)${timeInfo}${teamInfo}${segments.length > 1 ? ` [Teil ${segIdx + 1}/${segments.length}]` : ''}`;
            }
            const labelStr = item.isSub ? item.name : actType?.label;
            return /*#__PURE__*/React.createElement("div", {
              key: `${item.isSub ? 'sub-' : ''}${item.id}-${segIdx}`,
              className: `activity-bar absolute rounded text-xs text-white flex items-center justify-center cursor-pointer overflow-hidden ${item.status === 'ARCHIVED' ? 'opacity-40 grayscale pointer-events-none' : item.status === 'COMPLETED' ? 'opacity-80' : ''}`,
              style: {
                left: `${leftPct}%`,
                width: `${Math.max(widthPct, 0.5)}%`,
                backgroundColor: item.isSub ? barColor : actType?.color,
                top: `${topOffset}px`,
                height: `${barHeight}px`,
                minWidth: '8px',
                zIndex: 10
              },
              title: titleStr
            }, (isFirstSegment || item.isSub) && /*#__PURE__*/React.createElement("span", {
              className: "truncate px-1",
              style: {
                fontSize: maxLanes > 1 ? '8px' : '12px'
              }
            }, labelStr));
          })];
        })));
      }));
    })));
  };

  // =========================================================================
  // RENDER
  // =========================================================================

  // Loading state
  if (loading) {
    return /*#__PURE__*/React.createElement("div", {
      className: "min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col items-center justify-center"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-xl text-gray-600"
    }, "Lade..."), /*#__PURE__*/React.createElement("div", {
      className: "text-center text-gray-400 text-xs mt-8"
    }, "SAP Basis Jahresplaner \u2022 Optima Solutions GmbH"));
  }

  // Login form
  if (!user) {
    return /*#__PURE__*/React.createElement("div", {
      className: "min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col items-center justify-center p-4"
    }, /*#__PURE__*/React.createElement("div", {
      className: "bg-white rounded-lg shadow-lg p-8 w-full max-w-md"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3 mb-6"
    }, /*#__PURE__*/React.createElement(CalendarIcon, null), /*#__PURE__*/React.createElement("h1", {
      className: "text-2xl font-bold text-gray-800"
    }, "SAP Basis Jahresplaner")), /*#__PURE__*/React.createElement("form", {
      onSubmit: handleLogin
    }, /*#__PURE__*/React.createElement("div", {
      className: "mb-4"
    }, /*#__PURE__*/React.createElement("label", {
      htmlFor: "login-username",
      className: "block text-sm font-medium text-gray-700 mb-1"
    }, "Benutzername"), /*#__PURE__*/React.createElement("input", {
      id: "login-username",
      type: "text",
      name: "username",
      required: true,
      className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500",
      placeholder: "Benutzername"
    })), /*#__PURE__*/React.createElement("div", {
      className: "mb-6"
    }, /*#__PURE__*/React.createElement("label", {
      htmlFor: "login-password",
      className: "block text-sm font-medium text-gray-700 mb-1"
    }, "Passwort"), /*#__PURE__*/React.createElement("input", {
      id: "login-password",
      type: "password",
      name: "password",
      required: true,
      className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500",
      placeholder: "Passwort"
    })), loginError && /*#__PURE__*/React.createElement("div", {
      className: "mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm"
    }, loginError), /*#__PURE__*/React.createElement("button", {
      type: "submit",
      className: "w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
    }, "Anmelden"))), /*#__PURE__*/React.createElement("div", {
      className: "text-center text-gray-500 text-xs mt-8"
    }, "SAP Basis Jahresplaner \u2022 ", appVersion && `Version ${appVersion} • `, "Optima Solutions GmbH"));
  }

  // Forced password change screen (after login, before app access)
  if (user && mustChangePassword) {
    return /*#__PURE__*/React.createElement("div", {
      className: "min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col items-center justify-center p-4"
    }, /*#__PURE__*/React.createElement("div", {
      className: "bg-white rounded-lg shadow-lg p-8 w-full max-w-md"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3 mb-2"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-2xl"
    }, "\uD83D\uDD10"), /*#__PURE__*/React.createElement("h1", {
      className: "text-2xl font-bold text-gray-800"
    }, "Passwort \xE4ndern")), /*#__PURE__*/React.createElement("p", {
      className: "text-sm text-gray-500 mb-6"
    }, "Willkommen, ", /*#__PURE__*/React.createElement("strong", null, user.username), "! Bitte \xE4ndern Sie Ihr Passwort, bevor Sie die Anwendung verwenden k\xF6nnen."), /*#__PURE__*/React.createElement("form", {
      onSubmit: handlePasswordChange
    }, /*#__PURE__*/React.createElement("div", {
      className: "mb-4"
    }, /*#__PURE__*/React.createElement("label", {
      htmlFor: "init-current-password",
      className: "block text-sm font-medium text-gray-700 mb-1"
    }, "Aktuelles Passwort"), /*#__PURE__*/React.createElement("input", {
      id: "init-current-password",
      type: "password",
      name: "currentPassword",
      required: true,
      minLength: "6",
      className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500",
      placeholder: "Initiales Passwort eingeben"
    })), /*#__PURE__*/React.createElement("div", {
      className: "mb-4"
    }, /*#__PURE__*/React.createElement("label", {
      htmlFor: "init-new-password",
      className: "block text-sm font-medium text-gray-700 mb-1"
    }, "Neues Passwort"), /*#__PURE__*/React.createElement("input", {
      id: "init-new-password",
      type: "password",
      name: "newPassword",
      required: true,
      minLength: "6",
      className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500",
      placeholder: "Mind. 6 Zeichen"
    })), /*#__PURE__*/React.createElement("div", {
      className: "mb-4"
    }, /*#__PURE__*/React.createElement("label", {
      htmlFor: "init-confirm-password",
      className: "block text-sm font-medium text-gray-700 mb-1"
    }, "Neues Passwort best\xE4tigen"), /*#__PURE__*/React.createElement("input", {
      id: "init-confirm-password",
      type: "password",
      name: "confirmPassword",
      required: true,
      minLength: "6",
      className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500",
      placeholder: "Neues Passwort wiederholen"
    })), passwordError && /*#__PURE__*/React.createElement("div", {
      className: "mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm"
    }, passwordError), passwordSuccess && /*#__PURE__*/React.createElement("div", {
      className: "mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm"
    }, passwordSuccess), /*#__PURE__*/React.createElement("button", {
      type: "submit",
      className: "w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
    }, "Passwort \xE4ndern"))), /*#__PURE__*/React.createElement("div", {
      className: "text-center text-gray-500 text-xs mt-8"
    }, "SAP Basis Jahresplaner \u2022 ", appVersion && `Version ${appVersion} • `, "Optima Solutions GmbH"));
  }

  // Main application
  return /*#__PURE__*/React.createElement("div", {
    className: "min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4 md:p-6"
  }, user && onlineUsers.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "fixed right-4 top-24 z-40 max-h-[80vh] overflow-y-auto flex flex-col gap-2"
  }, onlineUsers.map(u => /*#__PURE__*/React.createElement("div", {
    key: u.id,
    className: "flex items-center gap-1 justify-center px-2 py-1 bg-gray-200 rounded border border-gray-300 text-sm font-medium",
    title: u.username
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-600"
  }, "\uD83D\uDC64"), u.abbreviation))), /*#__PURE__*/React.createElement("div", {
    className: "max-w-7xl mx-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-lg p-4 md:p-6 mb-6"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3"
  }, /*#__PURE__*/React.createElement(CalendarIcon, null), /*#__PURE__*/React.createElement("h1", {
    className: "text-2xl md:text-3xl font-bold text-gray-800"
  }, "SAP Basis Jahresplaner")), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 flex-wrap header-controls items-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-600"
  }, user.username, " (", user.role === 'teamlead' ? 'Teamleiter' : user.role === 'admin' ? 'Administrator' : user.role === 'viewer' ? 'Viewer' : 'Benutzer', ")"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowPasswordDialog(true),
    className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border border-gray-300 rounded"
  }, "\uD83D\uDD11 Passwort"), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: openUserDialog,
    className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border border-gray-300 rounded"
  }, "\uD83D\uDC65 Benutzer"), /*#__PURE__*/React.createElement("button", {
    onClick: handleLogout,
    className: "px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border border-gray-300 rounded"
  }, "Abmelden"), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: saveSettings,
    className: "flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
  }, /*#__PURE__*/React.createElement(SaveIcon, null), " Einstellungen speichern"), /*#__PURE__*/React.createElement("button", {
    onClick: handleRefresh,
    className: "flex items-center gap-2 px-4 py-2 bg-blue-100 text-blue-700 border border-blue-300 rounded-lg hover:bg-blue-200 text-sm",
    title: "Daten vom Server aktualisieren"
  }, "\uD83D\uDD04 Aktualisieren"), /*#__PURE__*/React.createElement("div", {
    className: "relative",
    style: {
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      setShowCsvDropdown(!showCsvDropdown);
      setShowDataDropdown(false);
    },
    className: "flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 text-sm"
  }, /*#__PURE__*/React.createElement(DownloadIcon, null), " CSV Export \u25BE"), showCsvDropdown && /*#__PURE__*/React.createElement("div", {
    className: "csv-dropdown-panel absolute top-full left-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-xl z-50 min-w-48",
    style: {
      zIndex: 9999
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      exportCSV();
      setShowCsvDropdown(false);
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-emerald-50 hover:text-emerald-700 rounded-t-lg flex items-center gap-2"
  }, "\uD83D\uDCCA Gantt-Ansicht"), user?.role !== 'viewer' && /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      exportSkillsCSV();
      setShowCsvDropdown(false);
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-emerald-50 hover:text-emerald-700 flex items-center gap-2 border-t border-gray-100"
  }, "\uD83C\uDF93 Skills & Schulungen"), user?.role !== 'viewer' && /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      exportBereitschaftCSV();
      setShowCsvDropdown(false);
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-emerald-50 hover:text-emerald-700 flex items-center gap-2 border-t border-gray-100"
  }, "\uD83D\uDD14 Bereitschaft"), (user?.role === 'admin' || user?.role === 'teamlead') && /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      exportTeamCSV();
      setShowCsvDropdown(false);
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-emerald-50 hover:text-emerald-700 rounded-b-lg flex items-center gap-2 border-t border-gray-100"
  }, "\uD83D\uDC65 Team-Auslastung")), showCsvDropdown && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0",
    style: {
      zIndex: 9998
    },
    onClick: () => setShowCsvDropdown(false)
  })), (user?.role === 'teamlead' || user?.role === 'admin') && /*#__PURE__*/React.createElement("div", {
    className: "relative",
    style: {
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      setShowDataDropdown(!showDataDropdown);
      setShowCsvDropdown(false);
    },
    className: "flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
  }, "\uD83D\uDD12 Datensicherung \u25BE"), showDataDropdown && /*#__PURE__*/React.createElement("div", {
    className: "data-dropdown-panel absolute top-full left-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-xl z-50 min-w-52",
    style: {
      zIndex: 9999
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      exportJSON();
      setShowDataDropdown(false);
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 rounded-t-lg flex items-center gap-2"
  }, "\uD83D\uDCE4 JSON Export"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => document.getElementById('jsonImportInput').click(),
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 flex items-center gap-2 border-t border-gray-100"
  }, "\uD83D\uDCE5 JSON Import"), /*#__PURE__*/React.createElement("input", {
    id: "jsonImportInput",
    type: "file",
    accept: ".json,application/json",
    onChange: e => {
      importJSON(e);
      setShowDataDropdown(false);
    },
    className: "hidden"
  }), user?.role === 'teamlead' && /*#__PURE__*/React.createElement("button", {
    onClick: async () => {
      setShowDataDropdown(false);
      try {
        const backup = await api.exportBackup();
        const blob = new Blob([JSON.stringify(backup, null, 2)], {
          type: 'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SAP-Planner-Backup-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
      } catch (error) {
        alert('❌ Fehler beim Backup: ' + error.message);
      }
    },
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 flex items-center gap-2 border-t border-gray-100"
  }, "\uD83D\uDCE5 Backup"), user?.role === 'teamlead' && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => document.getElementById('restoreBackupInput').click(),
    className: "w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 rounded-b-lg flex items-center gap-2 border-t border-gray-100"
  }, "\uD83D\uDCE4 Restore"), /*#__PURE__*/React.createElement("input", {
    id: "restoreBackupInput",
    type: "file",
    accept: ".json,application/json",
    onChange: async event => {
      setShowDataDropdown(false);
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const backup = JSON.parse(text);
        if (!backup.version) {
          alert('❌ Ungültige Backup-Datei: Version fehlt');
          return;
        }
        const confirmed = confirm(`Backup importieren?\n\n` + `Backup-Version: ${backup.version}\n` + `Export-Datum: ${backup.exportDate ? new Date(backup.exportDate).toLocaleString('de-DE') : 'unbekannt'}\n\n` + `⚠️ Alle aktuellen Daten werden überschrieben!`);
        if (confirmed) {
          const result = await api.importBackup(backup);
          alert(`✅ Backup erfolgreich importiert!\n\n` + `Importierte Daten:\n` + Object.entries(result.imported || {}).map(([k, v]) => `  ${k}: ${v}`).join('\n'));
          window.location.reload();
        }
      } catch (error) {
        alert('❌ Fehler beim Import: ' + error.message);
      }
      event.target.value = '';
    },
    className: "hidden"
  }))), showDataDropdown && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0",
    style: {
      zIndex: 9998
    },
    onClick: () => setShowDataDropdown(false)
  })), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: openLogsDialog,
    className: "flex items-center gap-2 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 text-sm"
  }, "\uD83D\uDCCB Logfiles"), /*#__PURE__*/React.createElement("button", {
    onClick: toggleDarkMode,
    className: "dark-toggle",
    title: darkMode ? 'Heller Modus' : 'Dunkler Modus (Dracula)',
    "aria-label": darkMode ? 'Switch to light mode' : 'Switch to dark mode'
  }))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-4 items-end flex-wrap"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "filter-year",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Jahr"), /*#__PURE__*/React.createElement("input", {
    name: "filterYear",
    id: "filter-year",
    type: "number",
    value: year,
    min: "2026",
    max: "2036",
    onChange: e => {
      const val = parseInt(e.target.value);
      if (val >= 2026 && val <= 2036) {
        setYear(val);
        setViewOffset(60); // Reset to Jan 1 of the new year
      }
    },
    disabled: !canEdit,
    className: `px-4 py-2 border border-gray-300 rounded-lg w-24 ${!canEdit ? 'bg-gray-100' : ''}`
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "filter-bundesland",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Bundesland"), /*#__PURE__*/React.createElement("select", {
    name: "filterBundesland",
    id: "filter-bundesland",
    value: bundesland,
    onChange: e => setBundesland(e.target.value),
    disabled: !canEdit,
    className: `px-4 py-2 border border-gray-300 rounded-lg ${!canEdit ? 'bg-gray-100 appearance-none' : ''}`
  }, bundeslaender.map(bl => /*#__PURE__*/React.createElement("option", {
    key: bl.id,
    value: bl.id
  }, bl.name)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "filter-ansicht",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Ansicht"), /*#__PURE__*/React.createElement("select", {
    name: "filterViewMode",
    id: "filter-ansicht",
    value: viewMode,
    onChange: e => {
      setViewMode(e.target.value);
      setViewOffset(0);
    },
    className: "px-4 py-2 border border-gray-300 rounded-lg"
  }, /*#__PURE__*/React.createElement("option", {
    value: "year"
  }, "Jahresansicht"), /*#__PURE__*/React.createElement("option", {
    value: "quarter"
  }, "Quartalsansicht"), /*#__PURE__*/React.createElement("option", {
    value: "week"
  }, "Kalenderwoche"))), (viewMode === 'quarter' || viewMode === 'week') && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "filter-quartal",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Quartal"), /*#__PURE__*/React.createElement("select", {
    name: "filterQuarter",
    id: "filter-quartal",
    value: selectedQuarter,
    onChange: e => {
      setSelectedQuarter(parseInt(e.target.value));
      setViewOffset(0);
    },
    className: "px-4 py-2 border border-gray-300 rounded-lg"
  }, /*#__PURE__*/React.createElement("option", {
    value: 1
  }, "Q1 (Jan-M\xE4r)"), /*#__PURE__*/React.createElement("option", {
    value: 2
  }, "Q2 (Apr-Jun)"), /*#__PURE__*/React.createElement("option", {
    value: 3
  }, "Q3 (Jul-Sep)"), /*#__PURE__*/React.createElement("option", {
    value: 4
  }, "Q4 (Okt-Dez)"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "filter-wartungssonntag",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Wartungssonntag"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("select", {
    name: "filterMaintenanceSunday",
    id: "filter-wartungssonntag",
    className: "px-4 py-2 border border-gray-300 rounded-lg bg-purple-50",
    defaultValue: "",
    onChange: e => {
      const selectedId = parseInt(e.target.value);
      const selected = maintenanceSundays.find(s => s.id === selectedId);
      if (!selected || !selected.date) return;

      // Ensure week view mode for offset-based navigation
      if (viewMode !== 'week') setViewMode('week');

      // Calculate offset: rangeStart is 60 days before today
      // Calculate offset: rangeStart is 60 days before Jan 1 of selected year
      const rangeStart = new Date(year, 0, 1);
      rangeStart.setDate(rangeStart.getDate() - 60);
      const targetDate = new Date(selected.date);
      const dayIndex = Math.round((targetDate - rangeStart) / (1000 * 60 * 60 * 24));
      const daysToShow = 65;
      const totalDays = 420;
      const centerOffset = Math.max(0, Math.min(totalDays - daysToShow, dayIndex - Math.floor(daysToShow / 2)));
      setViewOffset(centerOffset);
    }
  }, /*#__PURE__*/React.createElement("option", {
    value: "",
    disabled: true
  }, "Ausw\xE4hlen..."), maintenanceSundays.filter(s => s.date).map(s => /*#__PURE__*/React.createElement("option", {
    key: s.id,
    value: s.id
  }, ['I', 'II', 'III', 'IV'][s.id - 1], " - ", formatDateDE(s.date)))), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: openMaintenanceDialog,
    className: "px-3 py-2 text-purple-700 border border-purple-300 rounded-lg hover:bg-purple-50 text-sm",
    title: "Wartungssonntage bearbeiten"
  }, "\u2699\uFE0F"))))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 mb-6"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setActiveTab('gantt'),
    className: `px-6 py-3 rounded-lg font-medium transition-colors ${activeTab === 'gantt' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100'}`
  }, "\uD83D\uDCCA Gantt-Ansicht"), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: () => setActiveTab('team'),
    className: `px-6 py-3 rounded-lg font-medium transition-colors ${activeTab === 'team' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100'}`
  }, "\uD83D\uDC65 Team-Auslastung"), user?.role !== 'viewer' && /*#__PURE__*/React.createElement("button", {
    onClick: () => setActiveTab('skills'),
    className: `px-6 py-3 rounded-lg font-medium transition-colors ${activeTab === 'skills' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100'}`
  }, "\uD83C\uDF93 Skills & Schulungen"), user?.role !== 'viewer' && /*#__PURE__*/React.createElement("button", {
    onClick: () => setActiveTab('bereitschaft'),
    className: `px-6 py-3 rounded-lg font-medium transition-colors ${activeTab === 'bereitschaft' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100'}`
  }, "Bereitschaft"), user?.role === 'teamlead' && /*#__PURE__*/React.createElement("button", {
    onClick: () => setActiveTab('auswertung'),
    className: `px-6 py-3 rounded-lg font-medium transition-colors ${activeTab === 'auswertung' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100'}`
  }, "\uD83D\uDCC8 Auswertung")), /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-lg p-4 mb-6",
    style: {
      display: activeTab === 'gantt' ? 'block' : 'none'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 mb-2"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold"
  }, "Aktivit\xE4tstypen:"), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: addActivityType,
    className: "text-sm px-2 py-1 border border-gray-300 rounded hover:bg-gray-100"
  }, "+ Aktivit\xE4t hinzuf\xFCgen")), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-3"
  }, activityTypes.map(type => /*#__PURE__*/React.createElement("div", {
    key: type.id,
    className: "flex items-center gap-2 group"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 rounded",
    style: {
      backgroundColor: type.color
    }
  }), canEdit && editingTypeId === type.id ? /*#__PURE__*/React.createElement("input", {
    name: "autoField_2",
    type: "text",
    value: type.label,
    onChange: e => renameActivityType(type.id, e.target.value),
    onBlur: () => setEditingTypeId(null),
    onKeyDown: e => e.key === 'Enter' && setEditingTypeId(null),
    className: "text-sm px-1 border border-blue-400 rounded w-32",
    autoFocus: true,
    maxLength: "24"
  }) : /*#__PURE__*/React.createElement("span", {
    className: `text-sm ${canEdit ? 'cursor-pointer hover:text-blue-600' : ''}`,
    onClick: () => canEdit && setEditingTypeId(type.id),
    title: canEdit ? 'Klicken zum Umbenennen' : ''
  }, type.label), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: () => deleteActivityType(type.id),
    className: "opacity-0 group-hover:opacity-100 text-red-500 hover:text-red-700 text-xs",
    title: "L\xF6schen"
  }, "\xD7")))), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-4 mt-3 pt-3 border-t border-gray-200"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 mr-4 font-bold text-gray-700"
  }, "Zeichenschl\xFCssel:"), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 weekend-pattern border border-gray-300"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm"
  }, "Wochenende")), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 holiday-pattern border border-gray-300"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm"
  }, "Feiertag")), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 today-marker border border-gray-300"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm"
  }, "Heute (", formatDateDE(today), ")")), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-4 h-4 maintenance-pattern border border-purple-400"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-sm"
  }, "Wartungssonntag")), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 ml-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "relative h-6 w-24 flex items-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "absolute inset-x-0 top-1 bottom-1 border border-pink-500 rounded z-0"
  }), /*#__PURE__*/React.createElement("div", {
    className: "absolute left-0 top-1 bottom-1 w-3 bg-pink-500 rounded-l z-10 text-[8px] text-white flex items-center justify-center"
  }, "S.."), /*#__PURE__*/React.createElement("div", {
    className: "absolute left-3 right-8 top-1 bottom-1 weekend-pattern opacity-50 z-0"
  }), /*#__PURE__*/React.createElement("div", {
    className: "absolute right-0 top-1 bottom-1 w-8 bg-pink-500 rounded-r z-10"
  })), /*#__PURE__*/React.createElement("span", {
    className: "text-sm"
  }, "Zusammenh\xE4ngende Aktivit\xE4t")))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: activeTab === 'gantt' ? 'block' : 'none'
    }
  }, renderGanttChart()), /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-lg p-4 md:p-6",
    style: {
      display: activeTab === 'gantt' ? 'block' : 'none'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4 flex-wrap gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "Systemlandschaften & SIDs"), /*#__PURE__*/React.createElement("button", {
    onClick: expandAllLandscapes,
    className: "px-3 py-1 border border-gray-300 rounded hover:bg-gray-100 text-sm"
  }, "+ Alle Aufklappen"), /*#__PURE__*/React.createElement("button", {
    onClick: collapseAllLandscapes,
    className: "px-3 py-1 border border-gray-300 rounded hover:bg-gray-100 text-sm"
  }, "- Alle Zuklappen")), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: addLandscape,
    className: "flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
  }, /*#__PURE__*/React.createElement(PlusIcon, null), " Landschaft hinzuf\xFCgen")), landscapes.map(landscape => {
    return /*#__PURE__*/React.createElement("div", {
      key: landscape.id,
      className: "mb-6 border border-gray-200 shadow-sm rounded-lg p-4"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center justify-between mb-3 flex-wrap gap-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3"
    }, /*#__PURE__*/React.createElement("div", {
      className: "relative"
    }, /*#__PURE__*/React.createElement("input", {
      name: `landscapePos-${landscape.id}`,
      type: "number",
      defaultValue: landscape.sort_order || 0,
      key: `sort-${landscape.id}-${landscape.sort_order}`,
      disabled: !canEdit,
      min: "0",
      max: "99",
      onBlur: e => {
        const val = e.target.value.replace(/[^0-9]/g, '');
        if (val !== String(landscape.sort_order || 0)) {
          updateLandscape(landscape.id, 'sort_order', val);
        }
      },
      className: `w-8 h-8 text-center font-bold text-white rounded focus:ring-2 focus:ring-offset-1 focus:ring-blue-500 bg-blue-600 ${!canEdit ? 'cursor-default opacity-50' : 'cursor-text'}`
    })), /*#__PURE__*/React.createElement("input", {
      name: `landscapeName-${landscape.id}`,
      type: "text",
      value: landscape.name,
      onChange: e => updateLandscape(landscape.id, 'name', e.target.value),
      disabled: !canEdit,
      maxLength: 35,
      className: `text-lg font-bold px-2 py-1 border-b-2 border-blue-600 bg-transparent text-blue-700 ${!canEdit ? 'cursor-default' : ''}`
    }), /*#__PURE__*/React.createElement("button", {
      onClick: () => toggleLandscapeCollapse(landscape.id),
      className: "px-3 py-1 border border-purple-300 text-purple-700 rounded hover:bg-purple-50 text-sm"
    }, collapsedLandscapes.has(landscape.id) ? '+ Aufklappen' : '- Zuklappen')), canEdit && /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => addSID(landscape.id),
      className: "flex items-center gap-2 px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-sm"
    }, /*#__PURE__*/React.createElement(PlusIcon, null), " SID hinzuf\xFCgen"), /*#__PURE__*/React.createElement("button", {
      onClick: () => deleteLandscape(landscape.id),
      className: "flex items-center justify-center w-8 h-8 bg-red-100 text-red-700 rounded hover:bg-red-200",
      title: "Landschaft l\xF6schen"
    }, /*#__PURE__*/React.createElement(TrashIcon, null)))), !collapsedLandscapes.has(landscape.id) && landscape.sids.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0)).map(sid => {
      const isLockedByOther = sid.lock && String(sid.lock.user_id) !== String(user?.id);
      const activeOnSid = onlineUsers.filter(u => u.activeSidId === sid.id && String(u.id) !== String(user?.id));
      return /*#__PURE__*/React.createElement("div", {
        key: sid.id,
        "data-sid-id": sid.id,
        className: `ml-0 md:ml-4 mb-4 border-l-4 pl-4 transition-all duration-300 ${isLockedByOther ? 'border-red-400 opacity-75' : 'border-blue-300'}`,
        onFocusCapture: () => handleSidInteraction(sid.id),
        onClickCapture: () => handleSidInteraction(sid.id)
      }, /*#__PURE__*/React.createElement("div", {
        className: "flex items-center gap-3 mb-2 flex-wrap"
      }, isLockedByOther && /*#__PURE__*/React.createElement("div", {
        className: "flex items-center gap-1",
        title: `Gesperrt durch ${sid.lock.username}`
      }, /*#__PURE__*/React.createElement("span", {
        className: "px-2 py-1 bg-red-600 text-white border border-red-700 rounded text-xs font-bold shadow-sm"
      }, "\uD83D\uDD12 ", sid.lock.abbreviation || sid.lock.username.substring(0, 3).toUpperCase())), !isLockedByOther && activeOnSid.length > 0 && /*#__PURE__*/React.createElement("div", {
        className: "flex items-center gap-1",
        title: "Wird gerade bearbeitet"
      }, activeOnSid.map(u => /*#__PURE__*/React.createElement("span", {
        key: u.id,
        className: "px-2 py-1 bg-blue-100 text-blue-800 border border-blue-300 rounded text-xs font-bold animate-pulse shadow-sm"
      }, "\u270D\uFE0F ", u.abbreviation))), /*#__PURE__*/React.createElement("div", {
        className: "relative"
      }, /*#__PURE__*/React.createElement("input", {
        name: `sidPos-${landscape.id}-${sid.id}`,
        type: "number",
        defaultValue: sid.sort_order || 1,
        key: `sid-sort-${sid.id}-${sid.sort_order}`,
        disabled: !canEdit || isLockedByOther,
        min: "1",
        max: "9",
        onKeyDown: e => {
          if (e.key === 'Enter') {
            e.target.blur();
          }
        },
        onBlur: e => {
          let val = Math.max(1, Math.min(9, parseInt(e.target.value) || 1));
          e.target.value = val;
          if (val !== (sid.sort_order || 1)) {
            updateSID(landscape.id, sid.id, 'sort_order', val);
          }
        },
        className: `w-8 h-8 text-center font-bold text-blue-700 bg-blue-100 border border-blue-300 rounded focus:ring-2 focus:ring-offset-1 focus:ring-blue-500 ${!canEdit || isLockedByOther ? 'cursor-default opacity-50' : 'cursor-text dark-mode:bg-blue-800/30'}`,
        title: "Position (1-9, Enter zum Best\xE4tigen)"
      })), /*#__PURE__*/React.createElement("input", {
        name: `sidName-${landscape.id}-${sid.id}`,
        type: "text",
        value: sid.name,
        placeholder: "SID Name",
        onChange: e => {
          const val = e.target.value.toUpperCase().replace(/[^A-Z0-9_\-]/g, '').substring(0, 8);
          updateSID(landscape.id, sid.id, 'name', val);
        },
        maxLength: 8,
        spellCheck: false,
        autoCorrect: "off",
        autoCapitalize: "none",
        autoComplete: "off",
        disabled: !canEdit || isLockedByOther,
        className: `px-2 py-1 border border-gray-300 rounded font-medium w-24 ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
      }), /*#__PURE__*/React.createElement("div", {
        className: "flex items-center gap-1 ml-4 border-l pl-4 border-gray-300"
      }, /*#__PURE__*/React.createElement("select", {
        name: `sidType-${landscape.id}-${sid.id}`,
        value: sid.systemType || (sid.isPRD ? 'PRD' : 'DEV'),
        onChange: e => updateSID(landscape.id, sid.id, 'systemType', e.target.value),
        disabled: !canEdit || isLockedByOther,
        className: `px-1 py-1 border border-gray-300 rounded text-xs font-medium ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''} ${sid.systemType === 'PRD' || sid.isPRD ? 'text-red-600 font-bold border-red-300' : ''}`,
        style: {
          minWidth: '70px'
        }
      }, SYSTEM_TYPES.map(type => /*#__PURE__*/React.createElement("option", {
        key: type,
        value: type
      }, type)))), /*#__PURE__*/React.createElement("label", {
        className: "flex items-center gap-2 text-sm ml-4 border-l pl-4 border-gray-300"
      }, /*#__PURE__*/React.createElement("input", {
        name: `sidVis-${landscape.id}-${sid.id}`,
        type: "checkbox",
        checked: sid.visibleInGantt !== false,
        onChange: e => updateSID(landscape.id, sid.id, 'visibleInGantt', e.target.checked),
        disabled: isLockedByOther,
        className: "w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
      }), /*#__PURE__*/React.createElement("span", null, "Sichtbar in Gantt")), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("button", {
        onClick: () => addActivity(landscape.id, sid.id),
        className: "flex items-center gap-1 px-2 py-1 bg-purple-600 text-white rounded hover:bg-purple-700 text-sm"
      }, /*#__PURE__*/React.createElement(PlusIcon, null), " Aktivit\xE4t"), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("button", {
        onClick: () => setEditingSidInfo({
          landscapeId: landscape.id,
          sidId: sid.id,
          notes: sid.notes || ''
        }),
        className: "flex items-center gap-1 px-2 py-1 bg-blue-100 text-blue-700 border border-blue-300 rounded hover:bg-blue-200 text-sm"
      }, "SID Info"), /*#__PURE__*/React.createElement("button", {
        onClick: () => toggleSidCollapse(sid.id),
        className: "px-2 py-1 border border-purple-300 text-purple-700 bg-white rounded hover:bg-purple-50 text-sm"
      }, collapsedSids.has(sid.id) ? '+ Aufklappen' : '- Zuklappen'), /*#__PURE__*/React.createElement("div", {
        className: "flex gap-2 ml-auto"
      }, canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("button", {
        onClick: () => setCopySidDialog({
          isOpen: true,
          sourceSidId: sid.id,
          sourceLandscapeId: landscape.id,
          targetLandscapeId: landscape.id,
          // Default to same landscape
          newName: `${sid.name}_COPY`
        }),
        className: "p-1.5 text-blue-600 hover:bg-blue-50 rounded",
        title: "SID kopieren"
      }, /*#__PURE__*/React.createElement(DocumentDuplicateIcon, null)), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("button", {
        onClick: () => deleteSID(landscape.id, sid.id),
        className: "flex items-center justify-center w-8 h-8 bg-red-100 text-red-700 rounded hover:bg-red-200"
      }, /*#__PURE__*/React.createElement(TrashIcon, null)))), !collapsedSids.has(sid.id) && sid.activities.map(activity => {
        const actType = activityTypes.find(t => t.id === activity.type);
        const hasSubActivities = activity.type === 'update' && (activity.subActivities || []).length > 0;
        const subActivityTeamMembers = hasSubActivities ? [...new Set((activity.subActivities || []).map(s => s.teamMemberId).filter(id => id))] : [];
        const isSingleUserAcrossSubs = subActivityTeamMembers.length === 1;
        const singleUserAbbr = isSingleUserAcrossSubs ? teamMembers.find(m => String(m.id) === String(subActivityTeamMembers[0]))?.abbreviation : null;
        const totalSubDuration = hasSubActivities ? (activity.subActivities || []).reduce((sum, sub) => sum + (parseInt(sub.duration) || 1), 0) : parseInt(activity.duration) || 1;
        let displayStartDate = activity.startDate;
        let displayEndDate = activity.endDate;
        if (hasSubActivities) {
          const subDates = activity.subActivities.map(sub => sub.startDate).filter(d => d).sort();
          const subEndDates = activity.subActivities.map(sub => sub.endDate).filter(d => d).sort();
          if (subDates.length > 0) displayStartDate = subDates[0];
          if (subEndDates.length > 0) displayEndDate = subEndDates[subEndDates.length - 1];
        }
        return /*#__PURE__*/React.createElement("div", {
          key: activity.id,
          className: "ml-0 md:ml-4 mb-2 pl-3 py-3 pr-1 bg-gray-50 rounded"
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex flex-wrap gap-2 items-center justify-between w-full"
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex flex-wrap gap-2 items-center flex-grow"
        }, /*#__PURE__*/React.createElement("div", {
          className: "w-3 h-3 rounded-full",
          style: {
            backgroundColor: actType?.color
          }
        }), /*#__PURE__*/React.createElement("select", {
          name: "autoField_3",
          value: activity.type,
          onChange: e => updateActivity(landscape.id, sid.id, activity.id, 'type', e.target.value),
          disabled: !canEdit || isLockedByOther,
          className: `px-2 py-1 border border-gray-300 rounded text-sm ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        }, activityTypes.map(type => /*#__PURE__*/React.createElement("option", {
          key: type.id,
          value: type.id
        }, type.label))), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Start:"), hasSubActivities ? /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-1 bg-purple-100 text-purple-700 border border-purple-300 rounded text-sm"
        }, formatDateDE(displayStartDate)) : /*#__PURE__*/React.createElement("input", {
          name: "autoField_4",
          type: "date",
          value: activity.startDate,
          onChange: e => updateActivity(landscape.id, sid.id, activity.id, 'startDate', e.target.value),
          disabled: !canEdit || isLockedByOther,
          className: `px-2 py-1 border border-gray-300 rounded text-sm ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        })), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Dauer:"), hasSubActivities ? /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-1 bg-purple-100 text-purple-700 border border-purple-300 rounded text-sm font-medium"
        }, "\u03A3 ", totalSubDuration) : /*#__PURE__*/React.createElement("input", {
          name: "autoField_5",
          type: "number",
          min: "0",
          value: activity.duration,
          onChange: e => updateActivity(landscape.id, sid.id, activity.id, 'duration', parseInt(e.target.value) >= 0 ? parseInt(e.target.value) : 0),
          disabled: !canEdit || isLockedByOther,
          className: `px-2 py-1 border border-gray-300 rounded w-16 text-sm ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        })), /*#__PURE__*/React.createElement("div", {
          className: "text-sm text-gray-600"
        }, "Ende: ", /*#__PURE__*/React.createElement("span", {
          className: "font-medium"
        }, formatDateDE(displayEndDate))), !hasSubActivities && parseInt(activity.duration) === 0 && /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1 ml-2 pl-2 border-l border-gray-300"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Von:"), /*#__PURE__*/React.createElement(TimePicker, {
          value: activity.start_time || '',
          max: activity.end_time || undefined,
          onChange: val => updateActivity(landscape.id, sid.id, activity.id, 'startTime', val),
          disabled: !canEdit || isLockedByOther
        }), /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Bis:"), /*#__PURE__*/React.createElement(TimePicker, {
          value: activity.end_time || '',
          min: activity.start_time || undefined,
          onChange: val => updateActivity(landscape.id, sid.id, activity.id, 'endTime', val),
          disabled: !canEdit || isLockedByOther
        })), /*#__PURE__*/React.createElement("label", {
          className: "flex items-center gap-1 text-sm ml-4"
        }, /*#__PURE__*/React.createElement("input", {
          name: "autoField_8",
          type: "checkbox",
          checked: activity.includesWeekend || false,
          onChange: e => updateActivity(landscape.id, sid.id, activity.id, 'includesWeekend', e.target.checked),
          disabled: !canEdit || isLockedByOther,
          className: "w-4 h-4"
        }), /*#__PURE__*/React.createElement("span", {
          className: "font-medium"
        }, "WE"))), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-2 ml-auto pl-2 border-l border-gray-200"
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1 w-[110px] justify-center"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "\uD83D\uDC64"), hasSubActivities ? /*#__PURE__*/React.createElement("span", {
          className: "text-sm font-medium px-2 py-0.5 bg-gray-200 rounded border border-gray-300"
        }, subActivityTeamMembers.length === 0 ? '-' : isSingleUserAcrossSubs && singleUserAbbr ? singleUserAbbr : 'Multi') : !canEdit || isLockedByOther ? /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-1 border border-gray-300 rounded text-sm w-full bg-gray-50 text-gray-700 min-h-[28px] flex items-center"
        }, activity.teamMemberId ? teamMembers.find(m => m.id === parseInt(activity.teamMemberId))?.abbreviation || '-' : '-') : /*#__PURE__*/React.createElement("select", {
          name: "autoField_9",
          value: activity.teamMemberId || '',
          onChange: e => updateActivity(landscape.id, sid.id, activity.id, 'teamMemberId', e.target.value || null),
          disabled: isLockedByOther,
          className: "px-2 py-1 border border-gray-300 rounded text-sm w-full"
        }, /*#__PURE__*/React.createElement("option", {
          value: ""
        }, "-"), teamMembers.map(member => /*#__PURE__*/React.createElement("option", {
          key: member.id,
          value: member.id
        }, member.abbreviation)))), canEdit && !isLockedByOther && activity.type !== 'update' && /*#__PURE__*/React.createElement("label", {
          className: "flex items-center gap-1 text-sm cursor-pointer",
          title: "In Serie umwandeln"
        }, /*#__PURE__*/React.createElement("input", {
          type: "checkbox",
          checked: false,
          onChange: () => convertToSeries(landscape.id, sid.id, activity.id),
          className: "w-4 h-4"
        }), /*#__PURE__*/React.createElement("span", {
          className: "font-medium text-blue-600"
        }, "Serie")), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement(React.Fragment, null, (!activity.status || activity.status === 'PLANNED') && /*#__PURE__*/React.createElement("button", {
          onClick: () => deleteActivity(landscape.id, sid.id, activity.id),
          className: "flex items-center justify-center w-8 h-8 bg-red-100 text-red-700 rounded hover:bg-red-200",
          title: "Aktivit\xE4t unwiderruflich l\xF6schen"
        }, /*#__PURE__*/React.createElement(TrashIcon, null)), activity.status === 'COMPLETED' && /*#__PURE__*/React.createElement("button", {
          onClick: () => archiveActivity(landscape.id, sid.id, activity.id),
          className: "flex items-center justify-center w-8 h-8 bg-stone-200 text-stone-700 border border-stone-300 rounded hover:bg-stone-300 transition-colors shadow-sm",
          title: "Aktivit\xE4t archivieren (Einfrieren)"
        }, "\uD83D\uDCE6")))), activity.type === 'update' && canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-2 mt-2 ml-4"
        }, /*#__PURE__*/React.createElement("button", {
          onClick: () => addSubActivity(landscape.id, sid.id, activity.id),
          className: "text-xs px-2 py-0.5 bg-purple-100 text-purple-700 border border-purple-300 rounded hover:bg-purple-200"
        }, "+ Sub-Aktivit\xE4t")), activity.type === 'update' && (activity.subActivities || []).map(subActivity => /*#__PURE__*/React.createElement("div", {
          key: subActivity.id,
          className: "ml-6 mt-2 pl-2 py-2 pr-1 bg-white border-l-2 rounded",
          style: {
            borderColor: actType?.color
          }
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex flex-wrap gap-2 items-center justify-between w-full"
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex flex-wrap gap-2 items-center flex-grow"
        }, /*#__PURE__*/React.createElement("input", {
          name: "autoField_10",
          type: "text",
          value: subActivity.name,
          onChange: e => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'name', e.target.value),
          disabled: !canEdit || isLockedByOther,
          className: `px-2 py-1 border border-gray-300 rounded text-sm w-32 ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        }), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Start:"), /*#__PURE__*/React.createElement("input", {
          name: "autoField_11",
          type: "date",
          value: subActivity.startDate,
          onChange: e => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'startDate', e.target.value),
          disabled: !canEdit || isLockedByOther,
          className: `px-1 py-0.5 border border-gray-300 rounded text-xs ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        })), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Dauer:"), /*#__PURE__*/React.createElement("input", {
          name: "autoField_12",
          type: "number",
          min: "0",
          value: subActivity.duration,
          onChange: e => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'duration', parseInt(e.target.value) >= 0 ? parseInt(e.target.value) : 0),
          disabled: !canEdit || isLockedByOther,
          className: `px-1 py-0.5 border border-gray-300 rounded w-12 text-xs ${!canEdit || isLockedByOther ? 'bg-gray-100' : ''}`
        })), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "Ende:"), /*#__PURE__*/React.createElement("span", {
          className: "font-medium text-sm w-20"
        }, subActivity.endDate ? formatDateDE(subActivity.endDate) : '-')), parseInt(subActivity.duration) === 0 && /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1 ml-1 pl-1 border-l border-gray-300"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-xs text-gray-600"
        }, "Von:"), /*#__PURE__*/React.createElement(TimePicker, {
          value: subActivity.start_time || '',
          max: subActivity.end_time || undefined,
          onChange: val => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'startTime', val),
          disabled: !canEdit || isLockedByOther,
          size: "xs"
        }), /*#__PURE__*/React.createElement("span", {
          className: "text-xs text-gray-600"
        }, "Bis:"), /*#__PURE__*/React.createElement(TimePicker, {
          value: subActivity.end_time || '',
          min: subActivity.start_time || undefined,
          onChange: val => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'endTime', val),
          disabled: !canEdit || isLockedByOther,
          size: "xs"
        })), /*#__PURE__*/React.createElement("label", {
          className: "flex items-center gap-1 text-sm text-gray-600 cursor-pointer"
        }, /*#__PURE__*/React.createElement("input", {
          name: "autoField_15",
          type: "checkbox",
          checked: subActivity.includesWeekend,
          onChange: e => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'includesWeekend', e.target.checked),
          disabled: !canEdit || isLockedByOther,
          className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500"
        }), "WE")), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-2 ml-auto pl-2 border-l border-gray-200"
        }, /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-1 w-[110px] justify-center"
        }, /*#__PURE__*/React.createElement("span", {
          className: "text-sm text-gray-600"
        }, "\uD83D\uDC64"), !canEdit || isLockedByOther ? /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-1 border border-gray-300 rounded text-sm w-full bg-gray-50 text-gray-700 min-h-[28px] flex items-center"
        }, subActivity.teamMemberId ? teamMembers.find(m => m.id === parseInt(subActivity.teamMemberId))?.abbreviation || '-' : '-') : /*#__PURE__*/React.createElement("select", {
          name: "autoField_16",
          value: subActivity.teamMemberId || '',
          onChange: e => updateSubActivity(landscape.id, sid.id, activity.id, subActivity.id, 'teamMemberId', e.target.value || null),
          disabled: isLockedByOther,
          className: "px-2 py-1 border border-gray-300 rounded text-sm w-full"
        }, /*#__PURE__*/React.createElement("option", {
          value: ""
        }, "-"), teamMembers.map(member => /*#__PURE__*/React.createElement("option", {
          key: member.id,
          value: member.id
        }, member.abbreviation)))), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement(React.Fragment, null, (!subActivity.status || subActivity.status === 'PLANNED') && /*#__PURE__*/React.createElement("button", {
          onClick: () => deleteSubActivity(landscape.id, sid.id, activity.id, subActivity.id),
          className: "w-6 h-6 bg-red-50 text-red-600 rounded flex items-center justify-center hover:bg-red-100",
          title: "Sub-Aktivit\xE4t unwiderruflich l\xF6schen"
        }, /*#__PURE__*/React.createElement(TrashIcon, null)), subActivity.status === 'COMPLETED' && /*#__PURE__*/React.createElement("button", {
          onClick: () => archiveSubActivity(landscape.id, sid.id, activity.id, subActivity.id),
          className: "w-6 h-6 bg-stone-200 text-stone-700 border border-stone-300 rounded flex items-center justify-center hover:bg-stone-300 shadow-sm",
          title: "Sub-Aktivit\xE4t archivieren"
        }, "\uD83D\uDCE6")))))));
      }), !collapsedSids.has(sid.id) && (sid.series || []).map(series => {
        const seriesType = activityTypes.find(t => t.id === series.typeId);
        const occCount = (series.occurrences || []).length;
        const today = new Date().toISOString().split('T')[0];
        const nextOcc = (series.occurrences || []).find(o => o.date >= today);
        const ruleLabel = series.ruleType === 'every_x_weeks' ? `Alle ${series.ruleValue} Wochen` : series.ruleType === 'x_per_year' ? `${series.ruleValue}× pro Jahr` : 'Manuell';
        return /*#__PURE__*/React.createElement("div", {
          key: `series-${series.id}`,
          className: "ml-0 md:ml-4 mb-2 pl-3 py-2 pr-1 bg-blue-50 dark:bg-slate-800 border border-blue-200 dark:border-slate-700 rounded flex flex-wrap items-center gap-3"
        }, /*#__PURE__*/React.createElement("div", {
          className: "w-3 h-3 rounded-full flex-shrink-0",
          style: {
            backgroundColor: seriesType?.color
          }
        }), /*#__PURE__*/React.createElement("span", {
          className: "font-medium text-sm dark:text-gray-200"
        }, seriesType?.label || series.typeId), /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 border border-blue-300 dark:border-blue-800 rounded text-xs font-bold"
        }, "Serie (", occCount, "\xD7)"), /*#__PURE__*/React.createElement("span", {
          className: "text-xs text-gray-500 dark:text-gray-400"
        }, ruleLabel), nextOcc && /*#__PURE__*/React.createElement("span", {
          className: "text-xs text-gray-600 dark:text-gray-400"
        }, "N\xE4chste: ", /*#__PURE__*/React.createElement("span", {
          className: "font-medium dark:text-gray-300"
        }, formatDateDE(nextOcc.date))), /*#__PURE__*/React.createElement("div", {
          className: "flex items-center gap-2 ml-auto"
        }, /*#__PURE__*/React.createElement("button", {
          onClick: () => openSeriesPopup(landscape.id, sid.id, series),
          className: "px-2 py-1 bg-blue-600 dark:bg-blue-700 text-white rounded text-xs hover:bg-blue-700 dark:hover:bg-blue-600 font-medium"
        }, "\u25B6 Details"), canEdit && !isLockedByOther && /*#__PURE__*/React.createElement("button", {
          onClick: () => deleteSeriesHandler(landscape.id, sid.id, series.id, occCount),
          className: "flex items-center justify-center w-7 h-7 bg-red-100 text-red-700 rounded hover:bg-red-200"
        }, /*#__PURE__*/React.createElement(TrashIcon, null))));
      }));
    }));
  }))), activeTab === 'team' && /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-lg p-6 mb-6 max-w-7xl mx-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-6"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-2xl font-bold text-gray-800"
  }, "\uD83D\uDC65 Team-Auslastung")), /*#__PURE__*/React.createElement("div", {
    className: "mb-8"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-lg font-semibold text-gray-700 mb-4"
  }, "Teammitglieder verwalten"), canManageTeam && /*#__PURE__*/React.createElement("form", {
    onSubmit: async e => {
      e.preventDefault();
      const form = e.target;
      const userId = form.userId.value;
      if (userId) {
        try {
          const newMember = await api.createTeamMember({
            user_id: userId
          });
          setTeamMembers([...teamMembers, newMember]);
          form.reset();
        } catch (error) {
          alert(error.message);
        }
      }
    },
    className: "flex gap-3 mb-4 items-end"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    htmlFor: "add-team-user",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Name"), /*#__PURE__*/React.createElement("select", {
    id: "add-team-user",
    name: "userId",
    required: true,
    className: "px-4 py-2 border border-gray-300 rounded-lg w-64 bg-white"
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "- Bitte w\xE4hlen -"), users && users.filter(u => u.role !== 'viewer').map(u => {
    const displayName = u.first_name || u.last_name ? `${u.first_name} ${u.last_name}`.trim() : u.username;
    return /*#__PURE__*/React.createElement("option", {
      key: u.id,
      value: u.id
    }, displayName);
  }))), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    className: "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
  }, "+ Hinzuf\xFCgen")), /*#__PURE__*/React.createElement("table", {
    className: "w-full border-collapse"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", {
    className: "bg-gray-100"
  }, /*#__PURE__*/React.createElement("th", {
    className: "text-left p-3 font-semibold"
  }, "Teammitglied"), /*#__PURE__*/React.createElement("th", {
    className: "text-left p-3 font-semibold"
  }, "K\xFCrzel"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Arbeitstage"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Schulungen"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Verplant Q1"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Verplant Q2"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Verplant Q3"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Verplant Q4"), /*#__PURE__*/React.createElement("th", {
    className: "text-right p-3 font-semibold"
  }, "Verplante Tage"), /*#__PURE__*/React.createElement("th", {
    className: "text-center p-3 font-semibold"
  }, "Verf\xFCgbare Tage"), canManageTeam && /*#__PURE__*/React.createElement("th", {
    className: "text-right p-3 font-semibold"
  }, "Aktionen"))), /*#__PURE__*/React.createElement("tbody", null, teamMembers.map(member => {
    // Calculate total days for this team member
    let totalDays = 0;
    const quarterDays = [0, 0, 0, 0]; // Q1, Q2, Q3, Q4

    const getQuarter = item => {
      const sd = item.startDate || item.start_date;
      if (sd) {
        const month = new Date(sd).getMonth(); // 0-11
        return Math.floor(month / 3); // 0-3
      }
      return -1;
    };
    landscapes.forEach(landscape => {
      landscape.sids.forEach(sid => {
        sid.activities.forEach(activity => {
          const actMemberId = activity.teamMemberId || activity.team_member_id;
          if (actMemberId === member.id) {
            if (!activity.subActivities || activity.subActivities.length === 0) {
              const sd = activity.startDate || activity.start_date;
              if (sd && new Date(sd).getFullYear() === year) {
                const dur = parseInt(activity.duration) || 0;
                totalDays += dur;
                const q = getQuarter(activity);
                if (q >= 0) quarterDays[q] += dur;
              }
            }
          }
          (activity.subActivities || []).forEach(sub => {
            const subMemberId = sub.teamMemberId || sub.team_member_id;
            if (subMemberId === member.id) {
              const sd = sub.startDate || sub.start_date;
              if (sd && new Date(sd).getFullYear() === year) {
                const dur = parseInt(sub.duration) || 0;
                totalDays += dur;
                const q = getQuarter(sub);
                if (q >= 0) quarterDays[q] += dur;
              }
            }
          });
        });
        // Series occurrences (hours → days at 8h/day)
        (sid.series || []).forEach(series => {
          (series.occurrences || []).forEach(occ => {
            const memberId = occ.teamMemberId || occ.team_member_id || series.teamMemberId || series.team_member_id;
            if (parseInt(memberId) === member.id) {
              const sd = occ.date;
              if (sd && new Date(sd).getFullYear() === year) {
                let dur = 0.5; // Default: 0.5 days
                const st = occ.start_time || '';
                const et = occ.end_time || '';
                if (st && et) {
                  const [sh, sm] = st.split(':').map(Number);
                  const [eh, em] = et.split(':').map(Number);
                  dur = Math.round((eh * 60 + em - (sh * 60 + sm)) / 480 * 100) / 100; // 480 min = 8h
                  if (dur <= 0) dur = 0.5;
                }
                totalDays += dur;
                const q = getQuarter({
                  startDate: sd
                });
                if (q >= 0) quarterDays[q] += dur;
              }
            }
          });
        });
      });
    });
    return /*#__PURE__*/React.createElement("tr", {
      key: member.id,
      className: "border-b border-gray-200 hover:bg-gray-50"
    }, /*#__PURE__*/React.createElement("td", {
      className: "p-3"
    }, member.name), /*#__PURE__*/React.createElement("td", {
      className: "p-3 font-mono font-bold text-blue-600"
    }, member.abbreviation), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, /*#__PURE__*/React.createElement("input", {
      name: "autoField_17",
      type: "number",
      value: member.working_days || 0,
      onChange: async e => {
        const val = Math.min(260, Math.max(0, parseInt(e.target.value) || 0));
        try {
          await api.updateTeamMember(member.id, {
            working_days: val
          });
          setTeamMembers(prev => prev.map(m => m.id === member.id ? {
            ...m,
            working_days: val
          } : m));
        } catch (err) {
          alert(err.message);
        }
      },
      className: "w-16 text-center border border-gray-300 rounded px-1 py-0.5",
      max: "260"
    })), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, /*#__PURE__*/React.createElement("span", {
      className: "font-semibold text-gray-700"
    }, trainings.filter(t => t.booked_date > 0 && t.participants && (t.participants.includes(member.name) || t.participants.includes(member.abbreviation))).reduce((sum, t) => sum + (parseInt(t.days) || 0), 0))), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, Math.round(quarterDays[0])), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, Math.round(quarterDays[1])), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, Math.round(quarterDays[2])), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center"
    }, Math.round(quarterDays[3])), /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-right font-semibold"
    }, Math.round(totalDays + trainings.filter(t => t.booked_date > 0 && t.participants && (t.participants.includes(member.name) || t.participants.includes(member.abbreviation))).reduce((sum, t) => sum + (parseInt(t.days) || 0), 0)), " Tage"), /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-center font-bold"
    }, /*#__PURE__*/React.createElement("span", null, Math.round((member.working_days || 0) - trainings.filter(t => t.booked_date > 0 && t.participants && (t.participants.includes(member.name) || t.participants.includes(member.abbreviation))).reduce((sum, t) => sum + (parseInt(t.days) || 0), 0) - totalDays))), canManageTeam && /*#__PURE__*/React.createElement("td", {
      className: "p-3 text-right"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: async () => {
        setDeleteConfirm({
          isOpen: true,
          title: 'Teammitglied löschen',
          message: `"${member.name}" wirklich löschen?`,
          onConfirm: async () => {
            try {
              await api.deleteTeamMember(member.id);
              setTeamMembers(teamMembers.filter(m => m.id !== member.id));
              await loadData(); // Reload to refresh activity assignments
            } catch (error) {
              alert(error.message);
            }
          }
        });
      },
      className: "px-3 py-1 text-red-600 hover:bg-red-100 rounded text-sm"
    }, "L\xF6schen")));
  }), teamMembers.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: canManageTeam ? 11 : 6,
    className: "p-6 text-center text-gray-500"
  }, "Noch keine Teammitglieder vorhanden. F\xFCgen Sie oben ein neues Teammitglied hinzu.")))))), deleteConfirm.isOpen && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-sm border border-gray-200"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-lg font-bold mb-2"
  }, deleteConfirm.title), /*#__PURE__*/React.createElement("p", {
    className: "mb-6 text-sm text-gray-600"
  }, deleteConfirm.message), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end gap-3 mt-6"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setDeleteConfirm({
      isOpen: false,
      title: '',
      message: '',
      onConfirm: null
    }),
    className: "px-4 py-2 border rounded hover:bg-gray-100 transition-colors text-sm"
  }, "Abbrechen"), /*#__PURE__*/React.createElement("button", {
    onClick: async () => {
      if (deleteConfirm.onConfirm) await deleteConfirm.onConfirm();
      setDeleteConfirm({
        isOpen: false,
        title: '',
        message: '',
        onConfirm: null
      });
    },
    className: "px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors text-sm"
  }, "L\xF6schen")))), copySidDialog.isOpen && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-md border border-gray-200"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-xl font-bold mb-4"
  }, "SID kopieren"), /*#__PURE__*/React.createElement("p", {
    className: "mb-4 text-sm text-gray-600"
  }, "Kopiert die gesamte SID inklusive aller zugeh\xF6rigen Aktivit\xE4ten und Sub-Aktivit\xE4ten."), /*#__PURE__*/React.createElement("div", {
    className: "space-y-4"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "block text-sm font-medium mb-1"
  }, "Ziel-Landschaft"), /*#__PURE__*/React.createElement("select", {
    name: "copySidTargetLandscape",
    value: copySidDialog.targetLandscapeId,
    onChange: e => setCopySidDialog(prev => ({
      ...prev,
      targetLandscapeId: e.target.value
    })),
    className: "w-full p-2 border border-gray-300 rounded focus:ring-2 focus:border-blue-500 bg-white"
  }, /*#__PURE__*/React.createElement("option", {
    value: "",
    disabled: true
  }, "-- Bitte w\xE4hlen --"), landscapes.map(l => /*#__PURE__*/React.createElement("option", {
    key: l.id,
    value: l.id
  }, l.name)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "block text-sm font-medium mb-1"
  }, "Name der neuen SID"), /*#__PURE__*/React.createElement("input", {
    name: "copySidNewName",
    type: "text",
    value: copySidDialog.newName,
    onChange: e => {
      const val = e.target.value.toUpperCase().replace(/[^A-Z0-9_\-]/g, '').substring(0, 8);
      setCopySidDialog(prev => ({
        ...prev,
        newName: val
      }));
    },
    maxLength: 8,
    placeholder: "Z.B. SID_COPY",
    className: "w-full p-2 border border-gray-300 rounded focus:ring-2 focus:border-blue-500 bg-white"
  }))), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end gap-3 mt-6"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setCopySidDialog({
      isOpen: false,
      sourceSidId: null,
      sourceLandscapeId: null,
      targetLandscapeId: '',
      newName: ''
    }),
    className: "px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
  }, "Abbrechen"), /*#__PURE__*/React.createElement("button", {
    onClick: handleCopySid,
    disabled: !copySidDialog.targetLandscapeId || !copySidDialog.newName,
    className: "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors",
    title: "SID kopieren ausf\xFChren"
  }, "Kopieren")))), editingSidInfo && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-2xl mx-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "SID Informationen bearbeiten"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setEditingSidInfo(null),
    className: "text-gray-500 hover:text-gray-700 text-2xl"
  }, "\xD7")), /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("label", {
    className: "block text-gray-700 font-medium mb-2"
  }, "Notizen & Infos (max. 5000 Zeichen)"), /*#__PURE__*/React.createElement("textarea", {
    name: "autoField_18",
    value: editingSidInfo.notes,
    onChange: e => setEditingSidInfo({
      ...editingSidInfo,
      notes: e.target.value
    }),
    className: "w-full h-64 p-3 border border-gray-300 rounded focus:border-blue-500 focus:ring-1 focus:ring-blue-500",
    placeholder: "Hier wichtige Informationen zum System eintragen...",
    maxLength: 5000
  }), /*#__PURE__*/React.createElement("div", {
    className: "text-right text-xs text-gray-500 mt-1"
  }, editingSidInfo.notes.length, " / 5000 Zeichen")), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end gap-3"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setEditingSidInfo(null),
    className: "px-4 py-2 border border-gray-300 rounded hover:bg-gray-50"
  }, "Abbrechen"), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      updateSID(editingSidInfo.landscapeId, editingSidInfo.sidId, 'notes', editingSidInfo.notes);
      setEditingSidInfo(null);
    },
    className: "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
  }, "Speichern")))), showPasswordDialog && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "Passwort \xE4ndern"), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      setShowPasswordDialog(false);
      setPasswordError('');
      setPasswordSuccess('');
    },
    className: "text-gray-500 hover:text-gray-700 text-2xl"
  }, "\xD7")), /*#__PURE__*/React.createElement("form", {
    onSubmit: handlePasswordChange
  }, /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "settings-current-password",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Aktuelles Passwort"), /*#__PURE__*/React.createElement("input", {
    id: "settings-current-password",
    type: "password",
    name: "currentPassword",
    required: true,
    className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
  })), /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "settings-new-password",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Neues Passwort"), /*#__PURE__*/React.createElement("input", {
    id: "settings-new-password",
    type: "password",
    name: "newPassword",
    required: true,
    minLength: "6",
    className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
  })), /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "settings-confirm-password",
    className: "block text-sm font-medium text-gray-700 mb-1"
  }, "Neues Passwort best\xE4tigen"), /*#__PURE__*/React.createElement("input", {
    id: "settings-confirm-password",
    type: "password",
    name: "confirmPassword",
    required: true,
    minLength: "6",
    className: "w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
  })), passwordError && /*#__PURE__*/React.createElement("div", {
    className: "mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm"
  }, passwordError), passwordSuccess && /*#__PURE__*/React.createElement("div", {
    className: "mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm"
  }, passwordSuccess), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => {
      setShowPasswordDialog(false);
      setPasswordError('');
      setPasswordSuccess('');
    },
    className: "flex-1 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
  }, "Abbrechen"), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    className: "flex-1 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
  }, "Speichern"))))), showUserDialog && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "\uD83D\uDC65 Benutzerverwaltung"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowUserDialog(false),
    className: "text-gray-500 hover:text-gray-700 text-2xl"
  }, "\xD7")), userError && /*#__PURE__*/React.createElement("div", {
    className: "mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm"
  }, userError), /*#__PURE__*/React.createElement("div", {
    className: "mb-6"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold mb-2"
  }, "Vorhandene Benutzer:"), /*#__PURE__*/React.createElement("div", {
    className: "border rounded-lg divide-y"
  }, users.map(u => {
    // Determine if current user can delete this user
    const canDeleteThisUser = u.id !== user.id && u.username !== 'teamlead' && (user.role === 'teamlead' || user.role === 'admin' && (u.role === 'user' || u.role === 'viewer'));

    // Determine if current user can reset this user's password
    let canResetPassword = false;
    if (user.role === 'teamlead') {
      if (user.username === 'teamlead') {
        canResetPassword = true; // original system teamlead can reset anyone
      } else {
        canResetPassword = u.username !== 'teamlead'; // other teamleads cannot reset original teamlead
      }
    } else if (user.role === 'admin') {
      canResetPassword = u.role !== 'teamlead'; // admins cannot reset any teamlead
    }
    return /*#__PURE__*/React.createElement("div", {
      key: u.id,
      className: "p-3 hover:bg-gray-50"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center justify-between"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3"
    }, user?.role === 'teamlead' ? /*#__PURE__*/React.createElement("span", {
      className: "font-medium cursor-pointer hover:text-blue-600 hover:underline",
      onClick: () => handleEditUser(u),
      title: "Klicken zum Bearbeiten"
    }, u.username) : /*#__PURE__*/React.createElement("span", {
      className: "font-medium"
    }, u.username), (u.first_name || u.last_name) && /*#__PURE__*/React.createElement("span", {
      className: "text-sm text-gray-500"
    }, u.first_name, " ", u.last_name), /*#__PURE__*/React.createElement("span", {
      className: `text-xs px-2 py-0.5 rounded ${u.role === 'teamlead' ? 'bg-amber-100 text-amber-700' : u.role === 'admin' ? 'bg-purple-100 text-purple-700' : u.role === 'viewer' ? 'bg-sky-100 text-sky-700' : 'bg-gray-100 text-gray-600'}`
    }, u.role === 'teamlead' ? 'Teamleiter' : u.role === 'admin' ? 'Administrator' : u.role === 'viewer' ? 'Viewer' : 'Benutzer')), /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2"
    }, canResetPassword && /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: () => handleResetPassword(u.id),
      className: `text-sm px-2 py-1 border rounded ${resetPasswordUserId === u.id ? 'bg-blue-600 text-white border-blue-600' : 'text-blue-600 hover:text-blue-800 border-blue-300'}`
    }, "\uD83D\uDD11 PW Reset"), canDeleteThisUser && /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: e => {
        e.preventDefault();
        handleDeleteUser(u.id, u.username);
      },
      className: "text-sm px-2 py-1 text-red-600 hover:text-red-800 border border-red-300 rounded"
    }, "\uD83D\uDDD1\uFE0F L\xF6schen"))), resetPasswordUserId === u.id && /*#__PURE__*/React.createElement("div", {
      className: "mt-2 flex items-center gap-2 pl-4"
    }, /*#__PURE__*/React.createElement("input", {
      name: "autoField_19",
      type: "password",
      value: resetPasswordValue,
      onChange: e => setResetPasswordValue(e.target.value),
      onKeyDown: e => {
        if (e.key === 'Enter') {
          e.preventDefault();
          submitResetPassword();
        }
      },
      placeholder: "Neues Passwort (mind. 6 Zeichen)",
      className: "flex-1 px-3 py-1.5 border border-gray-300 rounded text-sm",
      autoFocus: true
    }), /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: submitResetPassword,
      className: "px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
    }, "Speichern"), /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: () => {
        setResetPasswordUserId(null);
        setResetPasswordValue('');
      },
      className: "px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50"
    }, "Abbrechen")), confirmDeleteUserId === u.id && /*#__PURE__*/React.createElement("div", {
      className: "mt-2 flex items-center gap-2 pl-4 p-2 bg-red-50 rounded border border-red-200"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-sm text-red-700 flex-1"
    }, "Benutzer \"", u.username, "\" wirklich l\xF6schen?"), /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: confirmDeleteUser,
      className: "px-3 py-1.5 bg-red-600 text-white rounded text-sm hover:bg-red-700"
    }, "Ja, l\xF6schen"), /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: () => setConfirmDeleteUserId(null),
      className: "px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50"
    }, "Abbrechen")));
  }))), user?.role === 'teamlead' && /*#__PURE__*/React.createElement("div", {
    className: "border-t pt-4"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold mb-2"
  }, editingUser ? `Benutzer "${editingUser.username}" bearbeiten:` : 'Neuen Benutzer anlegen:'), /*#__PURE__*/React.createElement("form", {
    id: "userForm",
    onSubmit: editingUser ? handleUpdateUser : handleAddUser,
    className: "flex flex-col gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-2 items-end"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-32"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newUsername",
    className: "block text-xs text-gray-600 mb-1"
  }, "Benutzername"), /*#__PURE__*/React.createElement("input", {
    id: "newUsername",
    type: "text",
    name: "newUsername",
    required: !editingUser,
    disabled: !!editingUser,
    placeholder: "username",
    className: `w-full px-3 py-2 border border-gray-300 rounded-lg text-sm ${editingUser ? 'bg-gray-100 text-gray-500' : ''}`
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-32"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newPassword",
    className: "block text-xs text-gray-600 mb-1"
  }, "Passwort"), /*#__PURE__*/React.createElement("input", {
    id: "newPassword",
    type: "password",
    name: "newPassword",
    required: !editingUser,
    disabled: !!editingUser,
    minLength: "6",
    placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022",
    className: `w-full px-3 py-2 border border-gray-300 rounded-lg text-sm ${editingUser ? 'bg-gray-100 text-gray-500' : ''}`
  })), /*#__PURE__*/React.createElement("div", {
    className: "w-36"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newRole",
    className: "block text-xs text-gray-600 mb-1"
  }, "Rolle"), /*#__PURE__*/React.createElement("select", {
    id: "newRole",
    name: "newRole",
    className: "w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
  }, /*#__PURE__*/React.createElement("option", {
    value: "user"
  }, "Benutzer (Lesen)"), user.role === 'teamlead' && /*#__PURE__*/React.createElement("option", {
    value: "admin"
  }, "Administrator"), user.role === 'teamlead' && /*#__PURE__*/React.createElement("option", {
    value: "teamlead"
  }, "Teamleiter"), user.role === 'teamlead' && /*#__PURE__*/React.createElement("option", {
    value: "viewer"
  }, "Viewer (Nur Gantt)"))), /*#__PURE__*/React.createElement("div", {
    className: "w-20"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newAbbreviation",
    className: "block text-xs text-gray-600 mb-1"
  }, "K\xFCrzel"), /*#__PURE__*/React.createElement("input", {
    id: "newAbbreviation",
    type: "text",
    name: "newAbbreviation",
    readOnly: true,
    tabIndex: -1,
    className: "w-full px-3 py-2 border border-gray-200 rounded-lg text-sm bg-gray-100 font-mono font-bold text-center uppercase"
  }))), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-2 items-end"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-32"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newFirstName",
    className: "block text-xs text-gray-600 mb-1"
  }, "Vorname"), /*#__PURE__*/React.createElement("input", {
    id: "newFirstName",
    type: "text",
    name: "newFirstName",
    required: true,
    placeholder: "Vorname",
    className: "w-full px-3 py-2 border border-gray-300 rounded-lg text-sm",
    onInput: e => {
      const form = e.target.form;
      const fn = (form.newFirstName.value || '').trim().toUpperCase();
      const ln = (form.newLastName.value || '').trim().toUpperCase();
      form.newAbbreviation.value = fn && ln ? fn[0] + ln[0] + ln[ln.length - 1] : '';
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-32"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "newLastName",
    className: "block text-xs text-gray-600 mb-1"
  }, "Nachname"), /*#__PURE__*/React.createElement("input", {
    id: "newLastName",
    type: "text",
    name: "newLastName",
    required: true,
    placeholder: "Nachname",
    className: "w-full px-3 py-2 border border-gray-300 rounded-lg text-sm",
    onInput: e => {
      const form = e.target.form;
      const fn = (form.newFirstName.value || '').trim().toUpperCase();
      const ln = (form.newLastName.value || '').trim().toUpperCase();
      form.newAbbreviation.value = fn && ln ? fn[0] + ln[0] + ln[ln.length - 1] : '';
    }
  })), editingUser ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    type: "submit",
    className: "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
  }, "\uD83D\uDCBE Speichern"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: handleCancelEdit,
    className: "px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 text-sm"
  }, "Abbrechen")) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    type: "submit",
    className: "px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
  }, "+ Anlegen"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => setShowUserDialog(false),
    className: "px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 text-sm"
  }, "Schlie\xDFen"))))))), activeTab === 'skills' && /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-lg p-6 mb-6 max-w-7xl mx-auto block-theme"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-6 border-b pb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-2xl font-bold text-gray-800 flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-2xl"
  }, "\uD83C\uDF93"), " Skills & Schulungen"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, user?.role === 'teamlead' && /*#__PURE__*/React.createElement("button", {
    onClick: () => setAddSkillDialog({
      isOpen: true,
      name: ''
    }),
    className: "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 font-medium text-sm transition-colors"
  }, "+ Skill hinzuf\xFCgen"))), /*#__PURE__*/React.createElement("div", {
    className: "mb-12"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-xl font-semibold mb-4 text-gray-700"
  }, "Qualifikationsmatrix"), /*#__PURE__*/React.createElement("div", {
    className: "matrix-scroll-clip pb-4"
  }, /*#__PURE__*/React.createElement("table", {
    className: "w-full border-collapse"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", {
    className: "bg-[#00b0f0] text-white"
  }, /*#__PURE__*/React.createElement("th", {
    className: "p-3 text-left w-[180px] min-w-[180px] max-w-[180px] whitespace-normal break-words border-b border-[#00b0f0] font-semibold sticky left-0 z-20 bg-[#00b0f0] shadow-[1px_0_0_#00b0f0]"
  }, "Teammitglied"), matrixColumns.map(col => /*#__PURE__*/React.createElement("th", {
    key: col.id,
    className: "p-2 border-b border-[#00b0f0] bg-[#00b0f0] text-center w-[85px] min-w-[85px] max-w-[85px]"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-center"
  }, user?.role === 'teamlead' ? /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-center relative group w-full"
  }, /*#__PURE__*/React.createElement("textarea", {
    name: "autoField_20",
    className: "bg-transparent border-b border-transparent hover:border-white focus:border-white text-center font-semibold text-white w-full px-1 outline-none placeholder-blue-200 resize-none overflow-hidden",
    rows: 2,
    style: {
      wordBreak: 'break-word',
      lineHeight: '1.2'
    },
    onKeyDown: e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        e.target.blur();
      }
    },
    defaultValue: col.name,
    onBlur: async e => {
      const newName = e.target.value.trim();
      if (newName && newName !== col.name) {
        try {
          await api.updateMatrixColumn(col.id, newName);
          setMatrixColumns(matrixColumns.map(c => c.id === col.id ? {
            ...c,
            name: newName
          } : c));
        } catch (error) {
          alert(error.message);
          e.target.value = col.name;
        }
      } else {
        e.target.value = col.name;
      }
    }
  }), /*#__PURE__*/React.createElement("button", {
    onClick: async () => {
      if (confirm(`Spalte "${col.name}" wirklich löschen?`)) {
        try {
          await api.deleteMatrixColumn(col.id);
          setMatrixColumns(matrixColumns.filter(c => c.id !== col.id));
          setMatrixValues(matrixValues.filter(v => v.column_id !== col.id));
        } catch (error) {
          alert(error.message);
        }
      }
    },
    className: "absolute right-0 text-white opacity-0 group-hover:opacity-100 p-1 hover:text-red-200",
    title: "Spalte l\xF6schen"
  }, "\xD7")) : /*#__PURE__*/React.createElement("span", {
    className: "font-semibold text-white text-sm whitespace-normal break-words inline-block w-full"
  }, col.name)))), /*#__PURE__*/React.createElement("th", {
    className: "w-full p-0 border-b border-[#00b0f0] bg-[#00b0f0]"
  }), matrixColumns.length > 0 && /*#__PURE__*/React.createElement("th", {
    className: "p-0 border-b border-[#00b0f0] bg-[#00b0f0] text-center w-[46px] min-w-[46px] max-w-[46px]"
  }), matrixColumns.length > 0 && /*#__PURE__*/React.createElement("th", {
    className: "p-0 border-b border-[#00b0f0] bg-[#00b0f0] w-8 min-w-[32px] max-w-[32px]"
  }))), /*#__PURE__*/React.createElement("tbody", null, teamMembers.map((member, index) => {
    let memberTotalScore = 0;
    const possibleScore = matrixColumns.length * 4;
    const userFullName = ((user?.first_name || '') + ' ' + (user?.last_name || '')).trim().toLowerCase();
    const userAbbrev = (user?.abbreviation || '').toLowerCase();
    const userName = (user?.username || '').toLowerCase();
    const memberName = (member.name || '').toLowerCase();
    const memberAbbrev = (member.abbreviation || '').toLowerCase();
    let isMatch = userName === memberName || userName === memberAbbrev;
    if (userFullName) isMatch = isMatch || userFullName === memberName;
    if (userAbbrev) isMatch = isMatch || userAbbrev === memberAbbrev;

    // Fallback fuzzy match for old users (e.g. 'KraemerS' -> 'Sven Kraemer')
    if (!isMatch && userName && memberName) {
      if (memberName.includes(userName) || userName.includes(memberName)) {
        isMatch = true;
      } else {
        const parts = memberName.split(' ');
        for (const part of parts) {
          if (part.length > 3 && userName.includes(part)) {
            isMatch = true;
            break;
          }
        }
      }
    }
    const memberCanEdit = user?.role === 'teamlead' || user?.role !== 'viewer' && isMatch;
    return /*#__PURE__*/React.createElement("tr", {
      key: member.id,
      className: index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
    }, /*#__PURE__*/React.createElement("td", {
      className: `p-3 border-b border-gray-200 font-medium text-gray-800 sticky left-0 ${index % 2 === 0 ? 'bg-white matrix-sticky-left-even' : 'bg-gray-50 matrix-sticky-left-odd'} w-[180px] min-w-[180px] max-w-[180px] whitespace-normal break-words`
    }, member.name.split(' ').map((part, i, arr) => /*#__PURE__*/React.createElement("span", {
      key: i
    }, part, arr.length > 1 && i === 0 && /*#__PURE__*/React.createElement("br", null), arr.length > 1 && i > 0 && i < arr.length - 1 && ' '))), matrixColumns.map(col => {
      const val = matrixValues.find(v => v.team_member_id === member.id && v.column_id === col.id);
      const level = val ? val.level : 0;
      memberTotalScore += level;
      let bgColor = 'bg-transparent text-transparent'; // Default is invisible (0) // MODIFIED: bg-white -> bg-transparent to match mockup
      let borderColor = 'border-gray-500/30'; // MODIFIED: To match mockup default cell border
      let textColor = 'text-transparent';
      if (level === 1) {
        bgColor = 'bg-red-500';
        borderColor = 'border-red-500';
        textColor = 'text-white';
      } else if (level === 2) {
        bgColor = 'bg-amber-400';
        borderColor = 'border-amber-400';
        textColor = 'text-white';
      } else if (level === 3) {
        bgColor = 'bg-[#92d050]';
        borderColor = 'border-[#92d050]';
        textColor = 'text-white';
      } else if (level === 4) {
        bgColor = 'bg-[#00b050]';
        borderColor = 'border-[#00b050]';
        textColor = 'text-white';
      }
      return /*#__PURE__*/React.createElement("td", {
        key: col.id,
        className: "p-1 border-b border-gray-200 text-center"
      }, /*#__PURE__*/React.createElement("div", {
        className: "flex justify-center"
      }, /*#__PURE__*/React.createElement("button", {
        disabled: !memberCanEdit,
        onClick: async () => {
          if (!memberCanEdit) return;
          const nextLevel = level >= 4 ? 0 : level + 1;
          try {
            await api.updateMatrixValue(member.id, col.id, nextLevel);
            setMatrixValues(prev => {
              const filtered = prev.filter(v => !(v.team_member_id === member.id && v.column_id === col.id));
              return [...filtered, {
                team_member_id: member.id,
                column_id: col.id,
                level: nextLevel
              }];
            });
          } catch (error) {
            alert(error.message);
          }
        },
        className: `w-6 h-6 rounded-sm border shrink-0 flex items-center justify-center font-bold text-xs transition-opacity focus:outline-none focus:ring-1 focus:ring-offset-1 focus:ring-blue-400 ${bgColor} ${borderColor} ${textColor} ${memberCanEdit ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`,
        title: level > 0 ? `Level: ${level}` : 'Kein Level'
      }, level > 0 ? level : '')));
    }), /*#__PURE__*/React.createElement("td", {
      className: "w-full p-0 border-b border-gray-200"
    }), matrixColumns.length > 0 && /*#__PURE__*/React.createElement("td", {
      className: `py-2 pl-0 pr-[6px] border-b border-gray-200 text-center font-bold text-gray-800 text-sm sticky right-[28px] ${index % 2 === 0 ? 'bg-white matrix-sticky-percentage-even' : 'bg-gray-50 matrix-sticky-percentage-odd'} w-[46px] min-w-[46px] max-w-[46px]`
    }, possibleScore > 0 ? Math.round(memberTotalScore / possibleScore * 100) : 0, "%"), matrixColumns.length > 0 && index === 0 && /*#__PURE__*/React.createElement("td", {
      rowSpan: teamMembers.length + 1,
      className: "p-0 border-t border-b border-gray-300 bg-gray-200 text-center w-8 min-w-[32px] max-w-[32px] align-middle sticky right-0 matrix-sticky-vertical-header"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex flex-col items-center justify-center h-full"
    }, /*#__PURE__*/React.createElement("span", {
      className: "transform -rotate-180 text-gray-900 font-bold tracking-wider text-sm whitespace-nowrap",
      style: {
        writingMode: 'vertical-rl'
      }
    }, "Themenabdeckung Mitarbeiter"))));
  }), teamMembers.length > 0 && matrixColumns.length > 0 && /*#__PURE__*/React.createElement("tr", {
    className: "bg-gray-100 relative"
  }, /*#__PURE__*/React.createElement("td", {
    className: "p-3 border-t-2 border-b border-gray-300 font-bold text-gray-800 sticky left-0 z-10 bg-gray-100 matrix-sticky-left-footer text-center w-[180px] min-w-[180px] max-w-[180px]"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col items-center"
  }, /*#__PURE__*/React.createElement("span", null, "Themenabdeckung"), /*#__PURE__*/React.createElement("span", null, "Team"))), matrixColumns.map(col => {
    let colTotalScore = 0;
    const possibleColScore = teamMembers.length * 4;
    teamMembers.forEach(member => {
      const val = matrixValues.find(v => v.team_member_id === member.id && v.column_id === col.id);
      if (val) {
        colTotalScore += val.level;
      }
    });
    return /*#__PURE__*/React.createElement("td", {
      key: `total-${col.id}`,
      className: "p-2 border-t-2 border-b border-gray-300 text-center font-bold text-gray-800 text-sm"
    }, possibleColScore > 0 ? Math.round(colTotalScore / possibleColScore * 100) : 0, "%");
  }), /*#__PURE__*/React.createElement("td", {
    className: "w-full p-0 border-t-2 border-b border-gray-300 bg-gray-100"
  }), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border-t-2 border-b border-gray-300 bg-gray-100 sticky right-[28px] z-10 matrix-sticky-percentage-footer w-[46px] min-w-[46px] max-w-[46px]"
  })), teamMembers.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: matrixColumns.length + 1,
    className: "p-6 text-center text-gray-500 italic"
  }, "Bitte legen Sie zuerst Teammitglieder im Reiter \"Team-Auslastung\" an.")))))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-xl font-semibold text-gray-700"
  }, "Schulungen"), canEdit && /*#__PURE__*/React.createElement("button", {
    onClick: async () => {
      try {
        const newTr = await api.createTraining();
        setTrainings([...trainings, newTr]);
      } catch (error) {
        alert(error.message);
      }
    },
    className: "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 font-medium text-sm transition-colors"
  }, "+ Schulung eintragen")), /*#__PURE__*/React.createElement("div", {
    className: "overflow-x-auto"
  }, /*#__PURE__*/React.createElement("table", {
    className: "w-full border-collapse border border-[#00b0f0]"
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", {
    className: "bg-[#00b0f0] text-white"
  }, /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-left"
  }, "Teilnehmer"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-left"
  }, "Kurs"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-left"
  }, "Thema"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-left"
  }, "Kosten"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-left"
  }, "Location"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-center"
  }, "Termin1"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-center"
  }, "Termin2"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-center"
  }, "Termin3"), /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-center whitespace-nowrap"
  }, "Anzahl Tage"), user?.role === 'teamlead' && /*#__PURE__*/React.createElement("th", {
    className: "p-2 border border-[#00b0f0] bg-[#00b0f0] font-semibold text-center w-12"
  }, "Aktion"))), /*#__PURE__*/React.createElement("tbody", null, trainings.map((tr, index) => /*#__PURE__*/React.createElement("tr", {
    key: tr.id,
    className: index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
  }, /*#__PURE__*/React.createElement("td", {
    className: `p-0 border border-gray-300 transition-colors ${tr.booked_date > 0 ? 'booked-green' : ''}`
  }, /*#__PURE__*/React.createElement("select", {
    name: `trainingParts-${tr.id}`,
    value: tr.participants || '',
    onChange: e => {
      setTrainings(trainings.map(t => t.id === tr.id ? {
        ...t,
        participants: e.target.value
      } : t));
      api.updateTraining(tr.id, {
        participants: e.target.value
      }).catch(err => console.error(err));
    },
    disabled: !canEdit,
    className: `w-full p-2 outline-none text-sm appearance-none ${tr.booked_date > 0 ? 'booked-green font-medium' : 'bg-transparent text-gray-800 hover:bg-gray-100 focus:bg-blue-50'}`
  }, /*#__PURE__*/React.createElement("option", {
    value: "",
    className: "text-gray-800"
  }, "-- Ausw\xE4hlen --"), teamMembers.map(m => /*#__PURE__*/React.createElement("option", {
    key: m.id,
    value: m.name,
    className: "text-gray-800"
  }, m.name)))), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border border-gray-300"
  }, /*#__PURE__*/React.createElement("input", {
    name: `trainingCourse-${tr.id}`,
    type: "text",
    value: tr.course || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      course: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      course: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: "w-full p-2 bg-transparent outline-none focus:bg-blue-50 text-sm"
  })), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border border-gray-300"
  }, /*#__PURE__*/React.createElement("input", {
    name: `trainingTopic-${tr.id}`,
    type: "text",
    value: tr.topic || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      topic: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      topic: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: "w-full p-2 bg-transparent outline-none focus:bg-blue-50 text-sm"
  })), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border border-gray-300 min-w-28"
  }, /*#__PURE__*/React.createElement("input", {
    name: `trainingCost-${tr.id}`,
    type: "text",
    value: tr.cost || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      cost: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      cost: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: "w-full p-2 bg-transparent outline-none focus:bg-blue-50 text-sm",
    placeholder: "\u20AC..."
  })), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border border-gray-300"
  }, /*#__PURE__*/React.createElement("input", {
    name: `trainingLocation-${tr.id}`,
    type: "text",
    value: tr.location || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      location: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      location: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: "w-full p-2 bg-transparent outline-none focus:bg-blue-50 text-sm"
  })), /*#__PURE__*/React.createElement("td", {
    className: `p-1 border border-gray-300 w-36 transition-colors ${tr.booked_date === 1 ? 'booked-green' : ''}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center space-x-1 h-full"
  }, user?.role === 'teamlead' && tr.date1 && /*#__PURE__*/React.createElement("input", {
    name: `trainingBook1-${tr.id}`,
    type: "checkbox",
    checked: tr.booked_date === 1,
    onChange: async e => {
      const termDate = new Date(tr.date1);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      if (termDate < today) {
        e.preventDefault();
        alert('Ein Termin in der Vergangenheit kann nicht gebucht werden.');
        return;
      }
      const newStatus = tr.booked_date === 1 ? 0 : 1;
      try {
        await api.updateTraining(tr.id, {
          booked_date: newStatus
        });
        setTrainings(trainings.map(t => t.id === tr.id ? {
          ...t,
          booked_date: newStatus
        } : t));
      } catch (error) {
        alert('Fehler beim Speichern: ' + error.message);
      }
    },
    className: "cursor-pointer w-4 h-4 ml-1",
    title: "Diesen Termin buchen"
  }), /*#__PURE__*/React.createElement("input", {
    name: `trainingDate1-${tr.id}`,
    type: "date",
    value: tr.date1 || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      date1: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      date1: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: `w-full p-1 outline-none text-xs flex-1 ${tr.booked_date === 1 ? 'booked-green font-medium' : 'bg-transparent text-inherit hover:bg-gray-100 focus:bg-blue-50'}`
  }))), /*#__PURE__*/React.createElement("td", {
    className: `p-1 border border-gray-300 w-36 transition-colors ${tr.booked_date === 2 ? 'booked-green' : ''}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center space-x-1 h-full"
  }, user?.role === 'teamlead' && tr.date2 && /*#__PURE__*/React.createElement("input", {
    name: `trainingBook2-${tr.id}`,
    type: "checkbox",
    checked: tr.booked_date === 2,
    onChange: async e => {
      const termDate = new Date(tr.date2);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      if (termDate < today) {
        e.preventDefault();
        alert('Ein Termin in der Vergangenheit kann nicht gebucht werden.');
        return;
      }
      const newStatus = tr.booked_date === 2 ? 0 : 2;
      try {
        await api.updateTraining(tr.id, {
          booked_date: newStatus
        });
        setTrainings(trainings.map(t => t.id === tr.id ? {
          ...t,
          booked_date: newStatus
        } : t));
      } catch (error) {
        alert('Fehler beim Speichern: ' + error.message);
      }
    },
    className: "cursor-pointer w-4 h-4 ml-1",
    title: "Diesen Termin buchen"
  }), /*#__PURE__*/React.createElement("input", {
    name: `trainingDate2-${tr.id}`,
    type: "date",
    value: tr.date2 || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      date2: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      date2: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: `w-full p-1 outline-none text-xs flex-1 ${tr.booked_date === 2 ? 'booked-green font-medium' : 'bg-transparent text-inherit hover:bg-gray-100 focus:bg-blue-50'}`
  }))), /*#__PURE__*/React.createElement("td", {
    className: `p-1 border border-gray-300 w-36 transition-colors ${tr.booked_date === 3 ? 'booked-green' : ''}`
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center space-x-1 h-full"
  }, user?.role === 'teamlead' && tr.date3 && /*#__PURE__*/React.createElement("input", {
    name: `trainingBook3-${tr.id}`,
    type: "checkbox",
    checked: tr.booked_date === 3,
    onChange: async e => {
      const termDate = new Date(tr.date3);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      if (termDate < today) {
        e.preventDefault();
        alert('Ein Termin in der Vergangenheit kann nicht gebucht werden.');
        return;
      }
      const newStatus = tr.booked_date === 3 ? 0 : 3;
      try {
        await api.updateTraining(tr.id, {
          booked_date: newStatus
        });
        setTrainings(trainings.map(t => t.id === tr.id ? {
          ...t,
          booked_date: newStatus
        } : t));
      } catch (error) {
        alert('Fehler beim Speichern: ' + error.message);
      }
    },
    className: "cursor-pointer w-4 h-4 ml-1",
    title: "Diesen Termin buchen"
  }), /*#__PURE__*/React.createElement("input", {
    name: `trainingDate3-${tr.id}`,
    type: "date",
    value: tr.date3 || '',
    onChange: e => setTrainings(trainings.map(t => t.id === tr.id ? {
      ...t,
      date3: e.target.value
    } : t)),
    onBlur: e => api.updateTraining(tr.id, {
      date3: e.target.value
    }).catch(err => console.error(err)),
    disabled: !canEdit,
    className: `w-full p-1 outline-none text-xs flex-1 ${tr.booked_date === 3 ? 'booked-green font-medium' : 'bg-transparent text-inherit hover:bg-gray-100 focus:bg-blue-50'}`
  }))), /*#__PURE__*/React.createElement("td", {
    className: "p-0 border border-gray-300 w-16"
  }, /*#__PURE__*/React.createElement("input", {
    name: `trainingDays-${tr.id}`,
    type: "number",
    min: "0",
    value: tr.days !== undefined && tr.days !== null ? tr.days : '',
    onChange: e => {
      const v = e.target.value !== '' ? parseInt(e.target.value) || 0 : '';
      setTrainings(trainings.map(t => t.id === tr.id ? {
        ...t,
        days: v
      } : t));
    },
    onBlur: e => {
      const v = e.target.value !== '' ? parseInt(e.target.value) || 0 : 0;
      api.updateTraining(tr.id, {
        days: v
      }).catch(err => console.error(err));
    },
    disabled: !canEdit,
    className: "w-full p-2 bg-transparent outline-none focus:bg-blue-50 text-sm text-center"
  })), user?.role === 'teamlead' && /*#__PURE__*/React.createElement("td", {
    className: "p-2 border border-gray-300 text-center"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: async () => {
      if (confirm('Schulung wirklich löschen?')) {
        try {
          await api.deleteTraining(tr.id);
          setTrainings(trainings.filter(t => t.id !== tr.id));
        } catch (error) {
          alert(error.message);
        }
      }
    },
    className: "text-red-500 hover:text-red-700 font-bold",
    title: "Schulung l\xF6schen"
  }, "\xD7")))), trainings.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: user?.role === 'teamlead' ? 10 : 9,
    className: "p-6 text-center text-gray-500 italic border border-gray-300"
  }, "Noch keine Schulungen eingetragen."))))))), activeTab === 'bereitschaft' && (() => {
    // --- Helper: get ISO Monday of the week containing a given date ---
    const getMonday = d => {
      const date = new Date(d);
      const day = date.getDay();
      const diff = day === 0 ? -6 : 1 - day;
      date.setDate(date.getDate() + diff);
      date.setHours(0, 0, 0, 0);
      return date;
    };
    const toISO = d => {
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${y}-${m}-${dd}`;
    };

    // Build a lookup: week_start -> bereitschaft entry
    const bereitschaftMap = {};
    bereitschaft.forEach(b => {
      bereitschaftMap[b.week_start] = b;
    });

    // Build the 14 months: Dec(year-1) ... Jan(year+1)
    const months = [];
    for (let m = -1; m <= 12; m++) {
      const d = new Date(year, m, 1);
      months.push({
        year: d.getFullYear(),
        month: d.getMonth()
      });
    }
    const MONTH_NAMES = ['Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember'];
    const DAY_LETTERS = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];

    // For each month, build week rows (Mon-Sun)
    const buildMonthWeeks = (y, m) => {
      const firstDay = new Date(y, m, 1);
      const lastDay = new Date(y, m + 1, 0);
      const startMonday = getMonday(firstDay);
      const weeks = [];
      let cur = new Date(startMonday);
      while (cur <= lastDay) {
        const days = [];
        for (let i = 0; i < 7; i++) {
          days.push(new Date(cur));
          cur.setDate(cur.getDate() + 1);
        }
        weeks.push({
          monday: new Date(days[0]),
          days
        });
      }
      return weeks;
    };
    const handleWeekClick = async mondayISO => {
      const entry = bereitschaftMap[mondayISO];
      if (entry) {
        // Already claimed — only deletable by own user or teamlead
        const canDelete = user?.role === 'teamlead' || Number(entry.user_id) === Number(user?.id);
        if (!canDelete) return;
        // Use inline confirmation instead of confirm()
        if (bPendingDelete === mondayISO) {
          // Second click = confirmed → delete
          try {
            await api.deleteBereitschaft(mondayISO);
            setBereitschaft(bereitschaft.filter(b => b.week_start !== mondayISO));
            setBPendingDelete(null);
          } catch (e) {
            alert(e.message);
          }
        } else {
          // First click → arm for deletion
          setBPendingDelete(mondayISO);
        }
      } else {
        // Empty week → claim it; also cancel any pending delete
        setBPendingDelete(null);
        try {
          const result = await api.claimBereitschaft(mondayISO);
          setBereitschaft([...bereitschaft, {
            week_start: mondayISO,
            user_id: result.user_id,
            abbreviation: result.abbreviation
          }]);
        } catch (e) {
          alert(e.message);
        }
      }
    };

    // Single month mini-calendar component
    const MonthCalendar = ({
      y,
      m,
      compact
    }) => {
      const weeks = buildMonthWeeks(y, m);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      return /*#__PURE__*/React.createElement("div", {
        className: `${compact ? '' : 'min-w-[320px]'} select-none`
      }, /*#__PURE__*/React.createElement("div", {
        className: "text-center font-bold text-base mb-2 text-[#00b0f0]"
      }, MONTH_NAMES[m], " ", y), /*#__PURE__*/React.createElement("table", {
        className: "w-full border-collapse text-xs table-fixed"
      }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
        className: "text-center py-1 font-semibold w-[10%] text-gray-300 border-r border-gray-100"
      }, "KW"), DAY_LETTERS.map((l, i) => /*#__PURE__*/React.createElement("th", {
        key: i,
        className: `text-center py-1 font-semibold w-[12.85%] ${i >= 5 ? 'text-red-400' : 'text-gray-500'}`
      }, l)))), /*#__PURE__*/React.createElement("tbody", null, weeks.map((week, wi) => {
        const mondayISO = toISO(week.monday);
        const entry = bereitschaftMap[mondayISO];
        const isOwn = entry && entry.user_id === user?.id;
        const canDelete = entry && (user?.role === 'teamlead' || isOwn);
        const isThisWeek = (() => {
          const todayMonday = toISO(getMonday(today));
          return todayMonday === mondayISO;
        })();
        let rowBg = '';
        if (entry) {
          rowBg = isOwn ? 'bg-indigo-50/50' : 'bg-emerald-50/50';
        }
        return /*#__PURE__*/React.createElement("tr", {
          key: wi,
          onClick: () => handleWeekClick(mondayISO),
          className: `cursor-pointer rounded ${rowBg} ${entry && !canDelete ? 'cursor-default' : ''} group`,
          title: entry ? `${entry.abbreviation}${canDelete ? ' – Klicken zum Löschen' : ''}` : 'Woche beanspruchen'
        }, /*#__PURE__*/React.createElement("td", {
          className: `text-center py-1 px-0.5 text-[9px] border-r border-gray-100 font-mono ${isThisWeek ? '!bg-amber-400 !text-amber-950 font-bold !brightness-100' : 'text-gray-300'}`
        }, getISOWeekNumber(week.monday)), week.days.map((day, di) => {
          const inMonth = day.getMonth() === m;
          const isToday = toISO(day) === toISO(today);
          return /*#__PURE__*/React.createElement("td", {
            key: di,
            className: `text-center py-1 px-0 rounded relative transition-all group-hover:brightness-95
                                    ${di >= 5 ? 'text-red-400' : ''}
                                    ${!inMonth ? 'text-gray-300' : ''}
                                    ${isToday ? 'font-bold underline' : ''}
                                  `
          }, /*#__PURE__*/React.createElement("div", {
            className: "flex items-center justify-center min-h-[1.25rem] w-full overflow-hidden"
          }, di === 0 && entry ? /*#__PURE__*/React.createElement("span", {
            className: `text-[9px] font-bold px-1 rounded shadow-sm truncate w-[90%] ${isOwn ? 'bg-indigo-600 text-white' : 'bg-emerald-600 text-white'}`
          }, entry.abbreviation) : /*#__PURE__*/React.createElement("span", null, inMonth ? day.getDate() : '')));
        }));
      }))));
    };
    return /*#__PURE__*/React.createElement("div", {
      className: "bg-white rounded-lg shadow-lg p-6 mb-6 max-w-7xl mx-auto block-theme"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex justify-between items-center mb-4 border-b pb-4 flex-wrap gap-2"
    }, /*#__PURE__*/React.createElement("h2", {
      className: "text-2xl font-bold text-gray-800"
    }, "\uD83D\uDD14 Bereitschaftskalender ", year), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex gap-3 text-xs items-center"
    }, /*#__PURE__*/React.createElement("span", {
      className: "flex items-center gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-3 h-3 rounded bg-indigo-600 inline-block shadow-sm"
    }), " Eigene"), /*#__PURE__*/React.createElement("span", {
      className: "flex items-center gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-3 h-3 rounded bg-emerald-600 inline-block shadow-sm"
    }), " Andere"), /*#__PURE__*/React.createElement("span", {
      className: "flex items-center gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-3 h-3 rounded bg-amber-400 inline-block shadow-sm"
    }), " Akt. Woche")), /*#__PURE__*/React.createElement("div", {
      className: "flex rounded-lg overflow-hidden border border-gray-200"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setBView('annual'),
      className: `px-3 py-1.5 text-sm font-medium transition-colors ${bView === 'annual' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`
    }, "Jahresansicht"), /*#__PURE__*/React.createElement("button", {
      onClick: () => setBView('monthly'),
      className: `px-3 py-1.5 text-sm font-medium transition-colors border-l border-gray-200 ${bView === 'monthly' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`
    }, "Monatsansicht")))), /*#__PURE__*/React.createElement("p", {
      className: "text-xs text-gray-500 mb-4 italic"
    }, "Klicke auf eine Woche, um Bereitschaft zu beanspruchen. Eigene Eintr\xE4ge k\xF6nnen mit einem Doppelklick gel\xF6scht werden."), bView === 'annual' && /*#__PURE__*/React.createElement("div", {
      className: "grid gap-6",
      style: {
        gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))'
      }
    }, months.map(({
      year: y,
      month: m
    }) => /*#__PURE__*/React.createElement("div", {
      key: `${y}-${m}`,
      className: "border border-gray-200 rounded-lg p-3 hover:shadow-md transition-shadow"
    }, /*#__PURE__*/React.createElement(MonthCalendar, {
      y: y,
      m: m,
      compact: true
    })))), bView === 'monthly' && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center justify-between mb-4"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setBMonthIdx(i => Math.max(0, i - 1)),
      disabled: bMonthIdx === 0,
      className: "px-3 py-2 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40 font-bold"
    }, "\u2039"), /*#__PURE__*/React.createElement("span", {
      className: "font-bold text-xl text-gray-700"
    }, MONTH_NAMES[months[bMonthIdx].month], " ", months[bMonthIdx].year), /*#__PURE__*/React.createElement("button", {
      onClick: () => setBMonthIdx(i => Math.min(months.length - 1, i + 1)),
      disabled: bMonthIdx === months.length - 1,
      className: "px-3 py-2 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40 font-bold"
    }, "\u203A")), /*#__PURE__*/React.createElement("div", {
      className: "flex flex-wrap gap-1.5 mb-6"
    }, months.map(({
      year: y,
      month: m
    }, idx) => /*#__PURE__*/React.createElement("button", {
      key: `${y}-${m}`,
      onClick: () => setBMonthIdx(idx),
      className: `px-2 py-0.5 rounded text-xs font-medium transition-colors ${idx === bMonthIdx ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`
    }, MONTH_NAMES[m].slice(0, 3), " ", y !== year ? y : ''))), (() => {
      const {
        year: y,
        month: m
      } = months[bMonthIdx];
      const weeks = buildMonthWeeks(y, m);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      return /*#__PURE__*/React.createElement("div", {
        className: "border border-gray-200 rounded-xl overflow-hidden shadow-sm"
      }, /*#__PURE__*/React.createElement("div", {
        className: "grid grid-cols-[50px_repeat(7,1fr)] bg-[#00b0f0] text-white"
      }, /*#__PURE__*/React.createElement("div", {
        className: "text-center py-2 text-sm font-semibold border-r border-white/20"
      }, "KW"), ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'].map((d, i) => /*#__PURE__*/React.createElement("div", {
        key: i,
        className: `text-center py-2 text-sm font-semibold ${i >= 5 ? 'opacity-70' : ''}`
      }, d))), weeks.map((week, wi) => {
        const mondayISO = toISO(week.monday);
        const entry = bereitschaftMap[mondayISO];
        const isOwn = entry && entry.user_id === user?.id;
        const canDelete = entry && (user?.role === 'teamlead' || isOwn);
        const isThisWeek = toISO(getMonday(today)) === mondayISO;

        // Strong, clearly visible background colours
        let weekBg = wi % 2 === 0 ? 'bg-white' : 'bg-gray-50';
        if (entry) {
          weekBg = isOwn ? 'bg-indigo-50/50' : 'bg-emerald-50/50';
        }
        // Pending delete overrides background
        if (bPendingDelete === mondayISO) {
          weekBg = 'bg-red-50/50';
        }
        return /*#__PURE__*/React.createElement("div", {
          key: wi,
          onClick: () => handleWeekClick(mondayISO),
          className: `grid grid-cols-[50px_repeat(7,1fr)] border-t border-gray-200 cursor-pointer transition-all ${weekBg} ${entry && !canDelete ? 'cursor-default' : ''} group relative`,
          title: entry ? `${entry.abbreviation}${canDelete ? ' – Klicken zum Löschen' : ''}` : 'Woche beanspruchen'
        }, entry && /*#__PURE__*/React.createElement("div", {
          className: `absolute left-0 top-0 bottom-0 w-1 ${isOwn ? 'bg-indigo-600' : 'bg-emerald-600'} z-10`
        }), bPendingDelete === mondayISO && /*#__PURE__*/React.createElement("div", {
          className: "absolute left-0 top-0 bottom-0 w-1 bg-red-600 z-10"
        }), /*#__PURE__*/React.createElement("div", {
          className: `flex items-center justify-center border-r border-gray-200 font-mono text-sm ${isThisWeek ? '!bg-amber-400 !text-amber-950 font-bold !brightness-100' : 'bg-gray-50/30 text-gray-300'}`
        }, getISOWeekNumber(week.monday)), week.days.map((day, di) => {
          const inMonth = day.getMonth() === m;
          const isToday = toISO(day) === toISO(today);
          return /*#__PURE__*/React.createElement("div", {
            key: di,
            className: `relative p-2 min-h-[64px] transition-all group-hover:brightness-95 ${di === 0 ? '' : 'border-l border-gray-100'} ${di >= 5 ? 'opacity-60' : ''}`
          }, /*#__PURE__*/React.createElement("span", {
            className: `text-sm font-medium ${!inMonth ? 'text-gray-300' : isToday ? 'text-white bg-blue-500 rounded-full w-6 h-6 flex items-center justify-center' : 'text-gray-700'}`
          }, day.getDate()), di === 0 && entry && /*#__PURE__*/React.createElement("div", {
            className: "absolute left-1 bottom-2"
          }, bPendingDelete === mondayISO ? /*#__PURE__*/React.createElement("span", {
            className: "px-2 py-1 rounded-md text-xs font-bold tracking-wide shadow-md whitespace-nowrap bg-red-600 text-white animate-pulse border border-red-400"
          }, "\uD83D\uDDD1 L\xF6schen?") : /*#__PURE__*/React.createElement("span", {
            className: `px-2 py-1 rounded-md text-xs font-bold tracking-wide shadow-md whitespace-nowrap border ${isOwn ? 'bg-indigo-600 text-white border-indigo-400' : 'bg-emerald-600 text-white border-emerald-400'}`
          }, entry.abbreviation)), di === 0 && entry && canDelete && bPendingDelete !== mondayISO && /*#__PURE__*/React.createElement("div", {
            className: "absolute top-1 right-1 text-gray-500 text-xs opacity-60"
          }, "\u2715"));
        }));
      }));
    })()));
  })(), activeTab === 'auswertung' && (() => {
    // ── Filter helpers ──
    const currentYear = String(year);
    const filterType = auswertungFilter.type || 'year';
    const filterValue = auswertungFilter.value || currentYear;

    // Determine date range from filter
    const getFilterRange = () => {
      if (filterType === 'year') {
        return {
          start: `${currentYear}-01-01`,
          end: `${currentYear}-12-31`
        };
      }
      if (filterType === 'quarter') {
        const q = parseInt(filterValue) || 1;
        const sm = (q - 1) * 3;
        const em = sm + 2;
        const endDay = new Date(year, em + 1, 0).getDate();
        return {
          start: `${currentYear}-${String(sm + 1).padStart(2, '0')}-01`,
          end: `${currentYear}-${String(em + 1).padStart(2, '0')}-${String(endDay).padStart(2, '0')}`
        };
      }
      if (filterType === 'month') {
        const m = parseInt(filterValue) || 1;
        const endDay = new Date(year, m, 0).getDate();
        return {
          start: `${currentYear}-${String(m).padStart(2, '0')}-01`,
          end: `${currentYear}-${String(m).padStart(2, '0')}-${String(endDay).padStart(2, '0')}`
        };
      }
      return {
        start: `${currentYear}-01-01`,
        end: `${currentYear}-12-31`
      };
    };
    const range = getFilterRange();

    // Check if an activity/sub-activity overlaps the filter range
    const overlaps = (startDate, duration) => {
      if (!startDate) return false;
      const actStart = startDate;
      // Rough end estimate: startDate + duration days
      const endD = new Date(startDate);
      endD.setDate(endD.getDate() + Math.max(0, (duration || 1) - 1));
      const actEnd = formatDateISO(endD);
      return actStart <= range.end && actEnd >= range.start;
    };

    // ── Aggregate data ──
    const allActivities = [];
    landscapes.forEach(landscape => {
      landscape.sids.forEach(sid => {
        (sid.activities || []).forEach(activity => {
          if (overlaps(activity.startDate, activity.duration)) {
            allActivities.push({
              landscape: landscape.name,
              sid: sid.name,
              typeId: activity.type || activity.type_id,
              duration: parseInt(activity.duration) || 0,
              teamMemberId: activity.teamMemberId || activity.team_member_id || null,
              startDate: activity.startDate,
              startTime: activity.startTime || activity.start_time || '',
              endTime: activity.endTime || activity.end_time || '',
              isSubActivity: false
            });
          }
          // Sub-activities counted separately
          (activity.subActivities || []).forEach(sub => {
            if (overlaps(sub.startDate, sub.duration)) {
              allActivities.push({
                landscape: landscape.name,
                sid: sid.name,
                typeId: activity.type || activity.type_id,
                duration: parseInt(sub.duration) || 0,
                teamMemberId: sub.teamMemberId || sub.team_member_id || null,
                startDate: sub.startDate,
                startTime: sub.startTime || sub.start_time || '',
                endTime: sub.endTime || sub.end_time || '',
                isSubActivity: true,
                subName: sub.name || ''
              });
            }
          });
        });
        // Series occurrences (hours → days at 8h/day)
        (sid.series || []).forEach(series => {
          (series.occurrences || []).forEach(occ => {
            if (occ.date >= range.start && occ.date <= range.end) {
              let dur = 0.5; // Default: 0.5 days
              const st = occ.start_time || '';
              const et = occ.end_time || '';
              if (st && et) {
                const [sh, sm] = st.split(':').map(Number);
                const [eh, em] = et.split(':').map(Number);
                dur = Math.round((eh * 60 + em - (sh * 60 + sm)) / 480 * 100) / 100;
                if (dur <= 0) dur = 0.5;
              }
              allActivities.push({
                landscape: landscape.name,
                sid: sid.name,
                typeId: series.typeId || series.type_id,
                duration: dur,
                teamMemberId: occ.teamMemberId || occ.team_member_id || series.teamMemberId || series.team_member_id || null,
                startDate: occ.date,
                startTime: occ.start_time || '',
                endTime: occ.end_time || '',
                isSubActivity: false,
                isSeries: true
              });
            }
          });
        });
      });
    });

    // daysByType: Map<typeId, totalDays>
    const daysByType = {};
    allActivities.forEach(a => {
      if (a.duration > 0) {
        daysByType[a.typeId] = (daysByType[a.typeId] || 0) + a.duration;
      }
    });

    // daysByMember: Map<memberId, Map<typeId, days>>
    const daysByMember = {};
    allActivities.forEach(a => {
      if (a.teamMemberId && a.duration > 0) {
        if (!daysByMember[a.teamMemberId]) daysByMember[a.teamMemberId] = {};
        daysByMember[a.teamMemberId][a.typeId] = (daysByMember[a.teamMemberId][a.typeId] || 0) + a.duration;
      }
    });
    const totalDays = Object.values(daysByType).reduce((s, d) => s + d, 0);
    const activeMemberIds = Object.keys(daysByMember);
    const activeMemberCount = activeMemberIds.length;

    // Get display label for filter
    const MONTH_LABELS = ['Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember'];
    const getFilterLabel = () => {
      if (filterType === 'year') return `Jahr ${currentYear}`;
      if (filterType === 'quarter') return `Q${filterValue} ${currentYear}`;
      if (filterType === 'month') return `${MONTH_LABELS[(parseInt(filterValue) || 1) - 1]} ${currentYear}`;
      return currentYear;
    };

    // ── CSV Export ──
    const downloadCSV = () => {
      const BOM = '\uFEFF';
      const header = 'User;SID;Landscape;Aktivitätstyp;Startdatum;Dauer (Tage);Startzeit;Endzeit';
      const rows = allActivities.map(a => {
        const member = teamMembers.find(m => m.id === a.teamMemberId);
        const memberName = member ? member.name : a.teamMemberId ? `ID ${a.teamMemberId}` : 'Nicht zugewiesen';
        const typeLabel = activityTypes.find(t => t.id === a.typeId)?.label || a.typeId;
        return [memberName, a.sid, a.landscape, typeLabel, a.startDate, a.duration, a.startTime || '', a.endTime || ''].join(';');
      });
      const csv = BOM + header + '\n' + rows.join('\n');
      const blob = new Blob([csv], {
        type: 'text/csv;charset=utf-8;'
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `Auswertung_${getFilterLabel().replace(/\s+/g, '_')}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    };

    // ── Print ──
    const handlePrint = () => {
      window.print();
    };

    // Build chart data (non-hook computations)
    const typeEntries = activityTypes.filter(t => daysByType[t.id]);
    const memberList = activeMemberIds.map(id => {
      const m = teamMembers.find(tm => tm.id === parseInt(id));
      return {
        id: parseInt(id),
        name: m ? m.name : `ID ${id}`
      };
    });

    // Imperative chart creation after render (avoids hooks in conditional IIFE)
    requestAnimationFrame(() => {
      if (typeof Chart === 'undefined') return;

      // Destroy old charts
      if (pieChartRef.current) {
        pieChartRef.current.destroy();
        pieChartRef.current = null;
      }
      if (barChartRef.current) {
        barChartRef.current.destroy();
        barChartRef.current = null;
      }

      // Pie chart
      if (pieCanvasRef.current && typeEntries.length > 0) {
        const ctx = pieCanvasRef.current.getContext('2d');
        pieChartRef.current = new Chart(ctx, {
          type: 'pie',
          data: {
            labels: typeEntries.map(t => t.label),
            datasets: [{
              data: typeEntries.map(t => daysByType[t.id]),
              backgroundColor: typeEntries.map(t => t.color),
              borderWidth: 2,
              borderColor: darkMode ? '#44475a' : '#fff'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: darkMode ? '#f8f8f2' : '#374151',
                  padding: 12,
                  font: {
                    size: 12
                  }
                }
              },
              tooltip: {
                callbacks: {
                  label: tooltipCtx => `${tooltipCtx.label}: ${tooltipCtx.parsed} Tage (${totalDays ? Math.round(tooltipCtx.parsed / totalDays * 100) : 0}%)`
                }
              }
            }
          }
        });
      }

      // Bar chart
      if (barCanvasRef.current && memberList.length > 0) {
        const ctx = barCanvasRef.current.getContext('2d');
        barChartRef.current = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: memberList.map(m => m.name),
            datasets: activityTypes.filter(t => memberList.some(m => (daysByMember[m.id] || {})[t.id])).map(t => ({
              label: t.label,
              data: memberList.map(m => (daysByMember[m.id] || {})[t.id] || 0),
              backgroundColor: t.color,
              borderWidth: 1,
              borderColor: darkMode ? '#44475a' : '#fff'
            }))
          },
          options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
              x: {
                stacked: true,
                ticks: {
                  color: darkMode ? '#f8f8f2' : '#374151'
                },
                grid: {
                  color: darkMode ? '#6272a4' : '#e5e7eb'
                }
              },
              y: {
                stacked: true,
                beginAtZero: true,
                title: {
                  display: true,
                  text: 'Tage',
                  color: darkMode ? '#f8f8f2' : '#374151'
                },
                ticks: {
                  color: darkMode ? '#f8f8f2' : '#374151'
                },
                grid: {
                  color: darkMode ? '#6272a4' : '#e5e7eb'
                }
              }
            },
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: darkMode ? '#f8f8f2' : '#374151',
                  padding: 12,
                  font: {
                    size: 11
                  }
                }
              }
            }
          }
        });
      }
    });
    return /*#__PURE__*/React.createElement("div", {
      className: "bg-white rounded-lg shadow-lg p-6 mb-6 max-w-7xl mx-auto"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex justify-between items-center mb-6 border-b pb-4 flex-wrap gap-3"
    }, /*#__PURE__*/React.createElement("h2", {
      className: "text-2xl font-bold text-gray-800"
    }, "\uD83D\uDCC8 Auswertung \u2014 ", getFilterLabel()), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 flex-wrap auswertung-controls"
    }, /*#__PURE__*/React.createElement("select", {
      value: filterType,
      onChange: e => {
        const t = e.target.value;
        const v = t === 'year' ? currentYear : t === 'quarter' ? '1' : '1';
        setAuswertungFilter({
          type: t,
          value: v
        });
      },
      className: "px-3 py-2 border border-gray-300 rounded-lg text-sm"
    }, /*#__PURE__*/React.createElement("option", {
      value: "year"
    }, "Ganzes Jahr"), /*#__PURE__*/React.createElement("option", {
      value: "quarter"
    }, "Quartal"), /*#__PURE__*/React.createElement("option", {
      value: "month"
    }, "Monat")), filterType === 'quarter' && /*#__PURE__*/React.createElement("select", {
      value: filterValue,
      onChange: e => setAuswertungFilter({
        ...auswertungFilter,
        value: e.target.value
      }),
      className: "px-3 py-2 border border-gray-300 rounded-lg text-sm"
    }, /*#__PURE__*/React.createElement("option", {
      value: "1"
    }, "Q1 (Jan\u2013M\xE4r)"), /*#__PURE__*/React.createElement("option", {
      value: "2"
    }, "Q2 (Apr\u2013Jun)"), /*#__PURE__*/React.createElement("option", {
      value: "3"
    }, "Q3 (Jul\u2013Sep)"), /*#__PURE__*/React.createElement("option", {
      value: "4"
    }, "Q4 (Okt\u2013Dez)")), filterType === 'month' && /*#__PURE__*/React.createElement("select", {
      value: filterValue,
      onChange: e => setAuswertungFilter({
        ...auswertungFilter,
        value: e.target.value
      }),
      className: "px-3 py-2 border border-gray-300 rounded-lg text-sm"
    }, MONTH_LABELS.map((label, i) => /*#__PURE__*/React.createElement("option", {
      key: i,
      value: String(i + 1)
    }, label))), /*#__PURE__*/React.createElement("button", {
      onClick: downloadCSV,
      className: "px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 text-sm font-medium flex items-center gap-1.5",
      title: "CSV exportieren"
    }, /*#__PURE__*/React.createElement(DownloadIcon, null), " CSV"), /*#__PURE__*/React.createElement("button", {
      onClick: handlePrint,
      className: "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium no-print",
      title: "Drucken"
    }, "\uD83D\uDDA8\uFE0F Drucken"))), allActivities.length === 0 ?
    /*#__PURE__*/
    /* ── Empty State ── */
    React.createElement("div", {
      className: "text-center py-16"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-6xl mb-4 opacity-30"
    }, "\uD83D\uDCCA"), /*#__PURE__*/React.createElement("p", {
      className: "text-gray-500 text-lg"
    }, "Keine Aktivit\xE4ten im gew\xE4hlten Zeitraum"), /*#__PURE__*/React.createElement("p", {
      className: "text-gray-400 text-sm mt-1"
    }, "W\xE4hlen Sie einen anderen Zeitraum oder erstellen Sie Aktivit\xE4ten in der Gantt-Ansicht.")) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
      className: "grid grid-cols-1 md:grid-cols-3 gap-4 mb-8 auswertung-section"
    }, /*#__PURE__*/React.createElement("div", {
      className: "bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-5 border border-blue-200"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-blue-600 font-medium"
    }, "Gesamte Arbeitstage"), /*#__PURE__*/React.createElement("div", {
      className: "text-3xl font-bold text-blue-800 mt-1"
    }, Math.round(totalDays * 100) / 100)), /*#__PURE__*/React.createElement("div", {
      className: "bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-5 border border-purple-200"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-purple-600 font-medium"
    }, "Aktive Teammitglieder"), /*#__PURE__*/React.createElement("div", {
      className: "text-3xl font-bold text-purple-800 mt-1"
    }, activeMemberCount)), /*#__PURE__*/React.createElement("div", {
      className: "bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-xl p-5 border border-emerald-200"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-emerald-600 font-medium"
    }, "Aktivit\xE4tstypen genutzt"), /*#__PURE__*/React.createElement("div", {
      className: "text-3xl font-bold text-emerald-800 mt-1"
    }, typeEntries.length))), /*#__PURE__*/React.createElement("div", {
      className: "grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8"
    }, /*#__PURE__*/React.createElement("div", {
      className: "bg-gray-50 rounded-xl p-5 border border-gray-200 auswertung-section"
    }, /*#__PURE__*/React.createElement("h3", {
      className: "text-lg font-bold text-gray-700 mb-4"
    }, "Verteilung nach Aktivit\xE4tstyp"), /*#__PURE__*/React.createElement("div", {
      style: {
        maxWidth: '360px',
        margin: '0 auto'
      }
    }, /*#__PURE__*/React.createElement("canvas", {
      ref: pieCanvasRef
    }))), /*#__PURE__*/React.createElement("div", {
      className: "bg-gray-50 rounded-xl p-5 border border-gray-200 auswertung-section"
    }, /*#__PURE__*/React.createElement("h3", {
      className: "text-lg font-bold text-gray-700 mb-4"
    }, "Arbeitstage pro Teammitglied"), memberList.length > 0 ? /*#__PURE__*/React.createElement("canvas", {
      ref: barCanvasRef
    }) : /*#__PURE__*/React.createElement("div", {
      className: "text-center py-8 text-gray-400"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-4xl mb-2 opacity-30"
    }, "\uD83D\uDC64"), /*#__PURE__*/React.createElement("p", null, "Keine Teammitglieder zugewiesen")))), /*#__PURE__*/React.createElement("div", {
      className: "bg-gray-50 rounded-xl p-5 border border-gray-200 auswertung-section"
    }, /*#__PURE__*/React.createElement("h3", {
      className: "text-lg font-bold text-gray-700 mb-4"
    }, "Teammitglieder \xD7 Aktivit\xE4tstypen (Tage)"), /*#__PURE__*/React.createElement("div", {
      className: "overflow-x-auto"
    }, /*#__PURE__*/React.createElement("table", {
      className: "w-full border-collapse text-sm"
    }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
      className: "text-left px-3 py-2 bg-gray-200 border border-gray-300 font-semibold"
    }, "Teammitglied"), activityTypes.filter(t => daysByType[t.id]).map(t => /*#__PURE__*/React.createElement("th", {
      key: t.id,
      className: "text-center px-3 py-2 bg-gray-200 border border-gray-300 font-semibold",
      style: {
        minWidth: '80px'
      }
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center justify-center gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-3 h-3 rounded",
      style: {
        backgroundColor: t.color,
        display: 'inline-block'
      }
    }), t.label))), /*#__PURE__*/React.createElement("th", {
      className: "text-center px-3 py-2 bg-gray-200 border border-gray-300 font-bold"
    }, "Gesamt"))), /*#__PURE__*/React.createElement("tbody", null, memberList.map((member, idx) => {
      const memberData = daysByMember[member.id] || {};
      const memberTotal = Object.values(memberData).reduce((s, d) => s + d, 0);
      const maxDays = Math.max(...Object.values(daysByMember).map(m => Object.values(m).reduce((s, d) => s + d, 0)), 1);
      return /*#__PURE__*/React.createElement("tr", {
        key: member.id,
        className: idx % 2 === 0 ? 'bg-white' : 'bg-gray-50'
      }, /*#__PURE__*/React.createElement("td", {
        className: "px-3 py-2 border border-gray-300 font-medium"
      }, member.name), activityTypes.filter(t => daysByType[t.id]).map(t => {
        const val = memberData[t.id] || 0;
        const intensity = val > 0 ? Math.max(0.1, val / Math.max(...Object.values(daysByType), 1)) : 0;
        return /*#__PURE__*/React.createElement("td", {
          key: t.id,
          className: "text-center px-3 py-2 border border-gray-300 font-mono",
          style: val > 0 ? {
            backgroundColor: `${t.color}${Math.round(intensity * 40 + 15).toString(16).padStart(2, '0')}`
          } : {}
        }, val > 0 ? Math.round(val * 100) / 100 : '–');
      }), /*#__PURE__*/React.createElement("td", {
        className: "text-center px-3 py-2 border border-gray-300 font-bold"
      }, Math.round(memberTotal * 100) / 100));
    }), /*#__PURE__*/React.createElement("tr", {
      className: "bg-gray-100 font-bold"
    }, /*#__PURE__*/React.createElement("td", {
      className: "px-3 py-2 border border-gray-300"
    }, "Gesamt"), activityTypes.filter(t => daysByType[t.id]).map(t => /*#__PURE__*/React.createElement("td", {
      key: t.id,
      className: "text-center px-3 py-2 border border-gray-300"
    }, Math.round(daysByType[t.id] * 100) / 100)), /*#__PURE__*/React.createElement("td", {
      className: "text-center px-3 py-2 border border-gray-300"
    }, Math.round(totalDays * 100) / 100))))))));
  })(), /*#__PURE__*/React.createElement("div", {
    className: "text-center text-gray-500 text-sm mt-8 mb-4"
  }, "SAP Basis Jahresplaner \u2022 ", year, " \u2022 ", appVersion && `Version ${appVersion} • `, "Optima Solutions GmbH \u2022 Daten werden in SQLite-Datenbank gespeichert"), showLogsDialog && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "\uD83D\uDCCB Logfiles"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowLogsDialog(false),
    className: "text-gray-500 hover:text-gray-700 text-2xl"
  }, "\xD7")), logsLoading ? /*#__PURE__*/React.createElement("div", {
    className: "text-center py-8 text-gray-500"
  }, "Lade Logs...") : !logs ? /*#__PURE__*/React.createElement("div", {
    className: "text-center py-8 text-gray-500"
  }, "Keine Logs vorhanden") : /*#__PURE__*/React.createElement("div", {
    className: "bg-gray-100 p-4 rounded-lg overflow-x-auto"
  }, /*#__PURE__*/React.createElement("pre", {
    className: "font-mono text-xs whitespace-pre-wrap max-h-[60vh] overflow-y-auto"
  }, logs)), /*#__PURE__*/React.createElement("div", {
    className: "mt-6 text-right"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowLogsDialog(false),
    className: "px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
  }, "Schlie\xDFen")))), showMaintenanceDialog && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center mb-4"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-bold"
  }, "\uD83D\uDD27 Wartungssonntage"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowMaintenanceDialog(false),
    className: "text-gray-500 hover:text-gray-700 text-2xl"
  }, "\xD7")), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mb-4"
  }, "Wartungssonntage werden im Gantt-Diagramm lila markiert und wie Feiertage behandelt."), maintenanceLoading ? /*#__PURE__*/React.createElement("div", {
    className: "text-center py-8 text-gray-500"
  }, "Laden...") : /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, [1, 2, 3, 4].map(id => {
    const sunday = maintenanceSundays.find(s => s.id === id);
    return /*#__PURE__*/React.createElement("div", {
      key: id,
      className: "flex items-center gap-3"
    }, /*#__PURE__*/React.createElement("label", {
      className: "w-32 font-medium text-purple-700"
    }, "Wartungssonntag ", ['I', 'II', 'III', 'IV'][id - 1]), /*#__PURE__*/React.createElement("input", {
      name: "autoField_21",
      type: "date",
      value: sunday?.date || '',
      min: "2026-01-01",
      max: "2036-12-31",
      onChange: e => handleMaintenanceSundayUpdate(id, e.target.value),
      className: "flex-1 px-3 py-2 border border-gray-300 rounded-lg"
    }));
  })), /*#__PURE__*/React.createElement("div", {
    className: "mt-6 text-right"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowMaintenanceDialog(false),
    className: "px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
  }, "Fertig")))), seriesPopup.isOpen && seriesPopup.series && /*#__PURE__*/React.createElement(SeriesPopupEditor, {
    key: seriesPopup.series.id,
    series: seriesPopup.series,
    activityTypes: activityTypes,
    teamMembers: teamMembers,
    canEdit: canEdit,
    year: year,
    api: api,
    onClose: async () => {
      await refreshSeriesInState(seriesPopup.landscapeId, seriesPopup.sidId);
      setSeriesPopup({
        isOpen: false,
        series: null,
        landscapeId: null,
        sidId: null
      });
    }
  }), addSkillDialog.isOpen && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white p-6 rounded shadow-lg max-w-sm w-full"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "text-xl font-bold mb-4"
  }, "Neuen Skill anlegen"), /*#__PURE__*/React.createElement("form", {
    onSubmit: async e => {
      e.preventDefault();
      if (!addSkillDialog.name.trim()) return;
      try {
        const newCol = await api.createMatrixColumn(addSkillDialog.name.trim());
        setMatrixColumns([...matrixColumns, newCol]);
        setAddSkillDialog({
          isOpen: false,
          name: ''
        });
      } catch (error) {
        alert('Fehler beim Erstellen der Spalte: ' + error.message);
      }
    }
  }, /*#__PURE__*/React.createElement("input", {
    name: "autoField_22",
    type: "text",
    value: addSkillDialog.name,
    onChange: e => setAddSkillDialog({
      ...addSkillDialog,
      name: e.target.value
    }),
    className: "w-full border border-gray-300 p-2 rounded mb-4",
    placeholder: "Name des Skills (z.B. Linux Server)",
    autoFocus: true
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => setAddSkillDialog({
      isOpen: false,
      name: ''
    }),
    className: "px-4 py-2 bg-gray-300 text-gray-800 rounded hover:bg-gray-400"
  }, "Abbrechen"), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    disabled: !addSkillDialog.name.trim(),
    className: "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
  }, "Erstellen"))))));
};
ReactDOM.render(/*#__PURE__*/React.createElement(SAPBasisPlanner, null), document.getElementById('root'));
