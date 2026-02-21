const Database = require('better-sqlite3');
const db = new Database('./data/sap-planner.db');
console.log(db.prepare('SELECT id, username, first_name, last_name, role FROM users').all());
