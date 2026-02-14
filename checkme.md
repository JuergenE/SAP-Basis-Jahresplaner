# 🔍 App Audit Checklist — SAP Basis Jahresplaner

> Erstellt: 2026-02-12 | Version: 0.1.3

---

## 1. NPM Dependencies

### Outdated Packages

| Package | Current | Latest | Severity |
|---------|---------|--------|----------|
| `express` | 4.22.1 | **5.2.1** | ⚠️ Major Update |
| `qs` (transitive, via express) | ≤6.14.1 | neuere Version | 🔴 CVE vorhanden |

> **Express 5** ist ein Major Update mit Breaking Changes. Vor dem Upgrade testen!
> `npm audit fix` behebt das `qs`-Problem (DoS über arrayLimit bypass: GHSA-w7fw-mjwx-w883).

- [x] ~~`npm audit fix` ausführen~~ ✅ 0 vulnerabilities
- [x] ~~Express 5 evaluieren~~ ✅ Upgrade auf Express 5.2.1 — keine Breaking Changes im Codebase

### Up-to-Date ✅
- `bcryptjs` ^3.0.3
- `better-sqlite3` ^12.6.2
- `cookie-parser` ^1.4.7
- `cors` ^2.8.5
- `express-rate-limit` ^8.2.1
- `helmet` ^8.1.0
- `uuid` ^13.0.0

---

## 2. CDN Libraries (sap-planner.html)

| Library | Aktuell | Latest | Status |
|---------|---------|--------|--------|
| React | 18.2.0 | **19.2.4** | 🟡 Major Update verfügbar |
| ReactDOM | 18.2.0 | **19.2.4** | 🟡 Major Update verfügbar |
| Babel Standalone | 7.23.5 | **7.26.4** | ✅ Update durchgeführt (7.29.1 existiert nicht auf cdnjs) |
| Tailwind CSS | CDN (unversioned) | N/A | 🟡 Play-CDN, nicht für Produktion |

- [x] ~~Babel auf 7.29.1 updaten~~ ⚠️ **Korrektur:** 7.29.1 existiert nicht auf cdnjs (404 White Screen Error). Update auf **7.26.4** (latest valid cdnjs version) durchgeführt.
- [x] ~~React 19 evaluieren~~ ⛔ **Nicht möglich** — React 19 entfernt UMD-Builds, die für CDN-Laden erforderlich sind. Migration erfordert Wechsel zu ESM-Imports (esm.sh). Bleibt auf React 18.2.0.
- [x] ~~Tailwind CDN versionieren~~ ⛔ **Nicht möglich** — Tailwind v3 Play CDN ist JIT-basiert und kann nicht versioniert werden. Funktioniert zuverlässig.

> **Hinweis:** Die Tailwind Play-CDN (`cdn.tailwindcss.com`) ist offiziell nur für Prototyping gedacht, nicht für Produktion. Funktioniert aber zuverlässig.

---

## 3. Security Findings

### 🔴 Kritisch

- [x] ~~**Helmet deaktiviert**~~ ✅ Wieder aktiviert mit `hsts: false, contentSecurityPolicy: false`

### 🟡 Mittel

- [x] ~~**Cookie `secure: false`**~~ ✅ Dynamisch: `req.secure || req.headers['x-forwarded-proto'] === 'https'`

- [x] ~~**CORS `origin: true`**~~ ✅ Jetzt konfigurierbar via `CORS_ORIGIN` Env-Variable (kommasepariert)

- [x] ~~**Session-Tokens ohne Ablaufdatum**~~ ✅ Bereits implementiert: 24h TTL, Index auf `expires_at`, Cleanup bei Login

### 🟢 Gering / Info

- [x] **SQL Injection** — ✅ Sicher
  - Alle Queries nutzen parametrisierte Statements (`?`)
  - Dynamic SQL in UPDATE-Endpoints nutzt Whitelist (nur bekannte Feldnamen)

- [x] **Input Validation** — ✅ Teilweise vorhanden
  - SID-Name: Max 8 Zeichen, Zeichenfilter
  - Notes: Max 5000 Zeichen
  - Passwort: Min 6 Zeichen

- [x] **Rate Limiting** — ✅ Konfiguriert
  - API: 300 req/15min
  - Login: 30 Versuche/15min

- [x] **Authentication** — ✅ HttpOnly Cookies

- [x] ~~**`express.static(__dirname)`**~~ ✅ Whitelist: nur `sap-planner.html` und `screenshot.png` erlaubt. `/server.js` → 404, `/package.json` → 404

---

## 4. Docker & Deployment

- [x] **Dockerfile** — Multi-Stage Build, non-root User ✅
- [x] **Healthcheck** — Konfiguriert ✅
- [x] **.dockerignore** — Vorhanden ✅

- [ ] **`docker-compose.yml` hat `build:` Direktive**
  - Portainer kann nicht direkt bauen, funktioniert nur mit vorgefertigtem Image
  - Für GitOps-Deployment ok (wird beim Deploy gebaut)

---

## 5. Ungenutzte / Überflüssige Dateien

| Datei | Beschreibung | Empfehlung |
|-------|-------------|------------|
| `sap-planner-backup.html` | Alte Backup-Kopie des Frontends (60KB) | 🗑️ Löschen |
| `SAP_Basis_Jahresplaner_CLNT_SRV Kopie.md.back` | Alte Backup-Dokumentation | 🗑️ Löschen |
| `check_schema.js` | DB-Schema Prüfskript (Debug-Tool) | 🗑️ Löschen oder in `tools/` verschieben |
| `migrate_manual.js` | Manuelles Migrations-Skript | 🗑️ Löschen oder in `tools/` verschieben |
| `ARCHITECTURE.md` | Architektur-Dokumentation | ✅ Behalten, ggf. aktualisieren |
| `sap-planner 2.db-shm` / `sap-planner 2.db-wal` | Stale SQLite WAL-Dateien einer Kopie | 🗑️ Löschen |
| `server.log` | Log-Datei (in .gitignore) | ✅ OK |
| `.DS_Store` | macOS Metadaten (in .gitignore) | ✅ OK |
| `data/` | Daten-Verzeichnis (Docker Volume) | ✅ OK |

- [x] ~~`sap-planner-backup.html` löschen~~ ✅
- [x] ~~`SAP_Basis_Jahresplaner_CLNT_SRV Kopie.md.back` löschen~~ ✅
- [x] ~~`check_schema.js` und `migrate_manual.js` löschen~~ ✅
- [x] ~~`sap-planner 2.db-*` Dateien löschen~~ ✅
- [x] ~~`.gitignore` erweitern: `*.back`, `checkme.md`~~ ✅

---

## 6. Code Quality

- [ ] **Version Hardcoded** (server.js Zeile 26)
  - `APP_VERSION = '0.1.3'` ist hardcoded als Fallback, wird aber aus package.json gelesen
  - Kein Problem, aber bei Version-Bump an beiden Stellen denken

- [ ] **Babel In-Browser Compilation**
  - JSX wird im Browser kompiliert (`type="text/babel"`)
  - Funktioniert, aber langsamer als vorcompilierter Code
  - Für interne App akzeptabel, für öffentliche Apps Build-Prozess empfohlen

---

## Zusammenfassung Prioritäten

| Priorität | Aktion | Aufwand |
|-----------|--------|---------|
| 🔴 Hoch | `npm audit fix` (qs CVE) ausführen | 1 Min |
| 🔴 Hoch | Helmet wieder aktivieren (ohne HSTS) | 5 Min |
| 🔴 Hoch | `express.static` einschränken | 15 Min |
| 🟡 Mittel | Cookie `secure` dynamisch setzen | 5 Min |
| 🟡 Mittel | Ungenutzte Dateien aufräumen | 5 Min |
| 🟡 Mittel | Babel CDN updaten (7.23.5 → ~~7.29.1~~ 7.26.4) | 1 Min |
| 🟢 Niedrig | CORS einschränken | 10 Min |
| 🟢 Niedrig | Session-Token TTL | 30 Min |
| 🟢 Niedrig | Express 5 evaluieren | 1-2 Std |
| 🟢 Niedrig | React 19 evaluieren | 2-4 Std |

