const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'sap-planner.db');
const db = new Database(dbPath, { readonly: true });

console.log('--- USERS ---');
const users = db.prepare("SELECT id, username, first_name, last_name, abbreviation, role FROM users WHERE username LIKE '%Kraemer%'").all();
console.table(users);

console.log('--- TEAM MEMBERS ---');
const members = db.prepare("SELECT id, name, abbreviation FROM team_members WHERE name LIKE '%Kraemer%'").all();
console.table(members);

db.close();
