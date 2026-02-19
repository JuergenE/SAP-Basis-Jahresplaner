Planungstool für SAP Basis Landschaften mit SQLite-Backend und Multi-User-Support.

## Hauptmerkmale

- **Multi-User-Fähigkeit:** Gleichzeitiger Zugriff mehrerer Benutzer durch SQLite WAL-Modus und serverseitiges Locking.
- **Rollen-basiertes User-Management:** Differenzierung zwischen `teamlead` (Superuser), `admin` und `user`.
- **Datenbank-Integration:** Serverseitige Persistenz mit `better-sqlite3`.
- **Sicherheits-Audit:** Regelmäßige Überprüfung der Infrastruktur und des Codes (Stand Feb 2026).

---

## Architektur

```
┌─────────────────────┐      HTTP/REST      ┌─────────────────────┐
│                     │  ←────────────────→ │                     │
│   React Frontend    │                     │   Express.js API    │
│   (Browser)         │   JSON Responses    │   (Node.js)         │
│                     │                     │   Port 3232         │
└─────────────────────┘                     └──────────┬──────────┘
                                                       │
                                                       │ better-sqlite3
                                                       ▼
                                            ┌─────────────────────┐
                                            │                     │
                                            │   SQLite Datenbank  │
                                            │   (sap-planner.db)  │
                                            │                     │
                                            └─────────────────────┘
```

---

## Dateistruktur

```
SAP-Basis-Jahresplaner/
├── ARCHITECTURE.md        # Systemarchitektur und Datenschema
├── README.md              # Installations- und Betriebsanleitung
├── sap-planner.html       # Single-File Frontend (React/Babel/Tailwind)
├── server.js              # Express.js Backend
├── manage-users.js        # CLI zur Benutzerverwaltung
├── package.json           # Projektabhängigkeiten und Versionierung
├── Dockerfile             # Multi-Stage Build-Konfiguration
├── docker-compose.yml     # Container-Orchestrierung
├── sap-planner.db         # SQLite-Datenbank
└── data/                  # Mount-Punkt für Docker-Volumes
```

---

## Installation & Start

### Erstmalige Installation

```bash
# In das Projektverzeichnis wechseln
cd "/Users/juergen/Projekte-Antigravity/SAP-Basis-Jahresplaner"

# Abhängigkeiten installieren
npm ci
```

### Server starten

```bash
npm start
```

Für Entwicklung mit automatischem Neustart:
```bash
npm run dev
```

Der Server startet auf **http://localhost:3232**

### Anwendung öffnen

Öffnen Sie einen Browser und navigieren Sie zu:
```
http://localhost:3232
```

---

## Benutzerrollen

| Rolle | Beschreibung | Berechtigungen |
|-------|--------------|----------------|
| **teamlead** | Superuser | Volle Kontrolle, Benutzerverwaltung (einschl. Admin), Backup/Restore |
| **admin** | Administrator | Schreibzugriff auf Planung, Benutzerverwaltung (nur User), Backup/Restore |
| **user** | Betrachter | Nur Lesezugriff, individueller Dark Mode & Gantt-Sichtbarkeit |

### Standard-Login
- **Benutzername:** `teamlead`
- **Passwort:** `teamlead` (Änderung bei Erstanmeldung erzwungen)

> ⚠️ **Wichtig:** Ändern Sie das Passwort nach der ersten Anmeldung!

---

## Datenbankschema

### Tabellen

#### `users` - Benutzerkonten
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| username | TEXT | Eindeutiger Benutzername (case-insensitive) |
| password_hash | TEXT | Gehasht mit bcrypt |
| role | TEXT | 'teamlead', 'admin', 'user' |
| must_change_password | BOOLEAN | Flag für Passwortänderungszwang |
| dark_mode | BOOLEAN | Benutzerspezifische Theme-Einstellung |
| created_at | DATETIME | Erstellungsdatum |

#### `sessions` - Aktive Sessions
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | TEXT | UUID / Session-Token |
| user_id | INTEGER | Referenz auf users |
| expires_at | DATETIME | Ablaufzeitpunkt (TTL: 24h) |

#### `settings` - Globale Einstellungen
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| key | TEXT | Einstellungsname (year, bundesland) |
| value | TEXT | Einstellungswert |

#### `activity_types` - Aktivitätstypen
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | TEXT | Eindeutige ID |
| label | TEXT | Anzeigename |
| color | TEXT | Farbe (Hex) |
| sort_order | INTEGER | Sortierreihenfolge |

#### `landscapes` - Systemlandschaften
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| name | TEXT | Name der Landschaft |
| sort_order | INTEGER | Sortierreihenfolge |

#### `sids` - SAP System-IDs
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| landscape_id | INTEGER | Referenz auf landscapes |
| name | TEXT | SID (z.B. "PRD") |
| is_prd | BOOLEAN | PRD-Verschlüsselung aktiv? |
| visible_in_gantt | BOOLEAN | Globaler Default für Sichtbarkeit |
| notes | TEXT | Zusätzliche Notizen zum System |
| sort_order | INTEGER | Sortierung innerhalb der Landschaft |

#### `activities` - Planungskalender
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| sid_id | INTEGER | Referenz auf sids |
| type_id | TEXT | Referenz auf activity_types |
| team_member_id | INTEGER | Referenz auf team_members |
| start_date | TEXT | Startdatum (ISO) |
| duration | INTEGER | Arbeitstage |
| includes_weekend | BOOLEAN | WE-Einschluss |
| start_time | TEXT | Optionale Uhrzeit (HH:MM) |
| end_time | TEXT | Optionale Uhrzeit (HH:MM) |

#### `sub_activities` - Detaillierte Planung
Gleiche Struktur wie `activities`, jedoch referenziert auf eine übergeordnete `activity_id`.

#### `user_sid_visibility` - Personalisierung
Speichert die Sichtbarkeit von SIDs im Gantt-Chart pro Benutzer.

#### `landscape_locks` - Concurrency Control
Verhindert gleichzeitiges Bearbeiten derselben Landschaft (Timeout: 5 Min).

#### `logs` - Anwendungsprotokolle
| Spalte | Typ | Beschreibung |
|--------|-----|--------------|
| id | INTEGER | Primärschlüssel |
| timestamp | DATETIME | Zeitstempel |
| level | TEXT | Log-Level (INFO, WARN, ERROR) |
| user_id | INTEGER | Referenz auf users |
| username | TEXT | Benutzername |
| action | TEXT | Ausgeführte Aktion |
| details | TEXT | Zusätzliche Details (JSON) |

---

## REST-API Dokumentation

### Authentifizierung

| Method | Endpoint | Beschreibung |
|--------|----------|--------------|
| POST | `/api/auth/login` | Login (JSON: username, password) |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Aktueller Benutzer |
| POST | `/api/auth/change-password` | Eigenes Passwort ändern |

### Einstellungen

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| GET | `/api/settings` | Einstellungen laden | Alle |
| PUT | `/api/settings` | Einstellungen speichern | Admin |

### Aktivitätstypen

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| GET | `/api/activity-types` | Alle Typen laden | Alle |
| POST | `/api/activity-types` | Neuen Typ anlegen | Admin |
| PUT | `/api/activity-types/:id` | Typ aktualisieren | Admin |
| DELETE | `/api/activity-types/:id` | Typ löschen | Admin |

### Landschaften

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| GET | `/api/landscapes` | Alle Landschaften + SIDs + Activities | Alle |
| POST | `/api/landscapes` | Neue Landschaft anlegen | Admin |
| PUT | `/api/landscapes/:id` | Landschaft aktualisieren | Admin |
| DELETE | `/api/landscapes/:id` | Landschaft löschen | Admin |

### SIDs

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| POST | `/api/sids` | Neue SID anlegen | Admin |
| PUT | `/api/sids/:id` | SID aktualisieren | Admin |
| DELETE | `/api/sids/:id` | SID löschen | Admin |

### Aktivitäten

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| POST | `/api/activities` | Neue Aktivität anlegen | Admin |
| PUT | `/api/activities/:id` | Aktivität aktualisieren | Admin |
| DELETE | `/api/activities/:id` | Aktivität löschen | Admin |

### Benutzerverwaltung (nur Admin)

| Method | Endpoint | Beschreibung |
|--------|----------|--------------|
| GET | `/api/users` | Alle Benutzer auflisten |
| POST | `/api/users` | Neuen Benutzer anlegen |
| PUT | `/api/users/:id` | Benutzer bearbeiten |
| DELETE | `/api/users/:id` | Benutzer löschen |

### Datenimport

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| POST | `/api/import/json` | JSON-Daten importieren | Admin |

### Wartungssonntage

| Method | Endpoint | Beschreibung | Rolle |
|--------|----------|--------------|-------|
| GET | `/api/maintenance-sundays` | Alle Wartungssonntage laden | Alle |
| PUT | `/api/maintenance-sundays/:id` | Wartungssonntag aktualisieren (id: 1-4) | Admin |

### Logs (nur Admin)

| Method | Endpoint | Beschreibung |
|--------|----------|--------------|
| GET | `/api/logs` | Anwendungsprotokolle abrufen (Query: ?limit=100) |

---

## JSON-Import

Zum Importieren bestehender JSON-Daten (z.B. aus localStorage-Export):

1. Melden Sie sich als Admin an
2. Klicken Sie auf "JSON Import"
3. Wählen Sie die JSON-Datei aus
4. Die Daten werden in die SQLite-Datenbank übernommen

---

## Technische Details

### Abhängigkeiten

- **express** - Web-Framework
- **better-sqlite3** - Synchroner SQLite-Treiber
- **bcrypt** - Passwort-Hashing
- **uuid** - Session-Token-Generierung
- **cors** - Cross-Origin-Unterstützung

### Sicherheit

- Passwörter werden mit bcrypt gehasht (Salt Rounds: 10)
- Session-Tokens laufen nach 24 Stunden ab
- API-Endpoints prüfen Rolle vor jeder Schreiboperation
- SQL-Injection wird durch Prepared Statements verhindert

### Concurrent Access

SQLite unterstützt mehrere gleichzeitige Leser. Schreiboperationen werden serialisiert durch SQLite's WAL-Modus (Write-Ahead Logging).

---

## Fehlerbehebung

### Server startet nicht
```bash
# Port bereits belegt?
lsof -i :3232

# Abhängigkeiten neu installieren
rm -rf node_modules
npm install
```

### Datenbank zurücksetzen
```bash
# Achtung: Alle Daten gehen verloren!
rm sap-planner.db
npm start  # Datenbank wird neu erstellt
```

### Passwort vergessen
Derzeit muss die Datenbank manuell bearbeitet werden oder über direkten SQLite-Zugriff zurückgesetzt werden.

---

## CLI-Tools

### manage-users.js

Kommandozeilen-Tool zur Benutzerverwaltung ohne laufenden Server:

```bash
# Benutzer erstellen
node manage-users.js add <username> <password> <role>

# Alle Benutzer anzeigen
node manage-users.js list

# Benutzer löschen
node manage-users.js delete <username>
```

**Beispiel:**
```bash
node manage-users.js add testuser passwort123 user
node manage-users.js list
```

> ⚠️ **Hinweis:** Der admin-Benutzer kann nicht über dieses Tool gelöscht werden.

---

## Lizenz

© 2026 Optima Solutions GmbH

