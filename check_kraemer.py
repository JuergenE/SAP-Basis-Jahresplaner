import sqlite3
import os

db_path = os.environ.get('DB_PATH', 'sap-planner.db')
if not os.path.exists(db_path):
    print(f"File {db_path} does not exist.")
else:
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        users = cursor.execute("SELECT id, username, first_name, last_name, abbreviation, role FROM users;").fetchall()
        print("--- USERS ---")
        for u in users:
            print(dict(u))
            
        members = cursor.execute("SELECT id, name, abbreviation FROM team_members;").fetchall()
        print("--- TEAM MEMBERS ---")
        for m in members:
            print(dict(m))
            
        conn.close()
    except Exception as e:
        print("Error:", e)
