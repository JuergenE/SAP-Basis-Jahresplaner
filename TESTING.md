# 🧪 SAP Basis Jahresplaner — Testdokumentation

Diese Dokumentation beschreibt die automatisierte Teststrategie, die verfügbaren Test-Suites und wie sie ausgeführt werden.

## 🏗️ Test-Architektur

Wir nutzen zwei komplementäre Test-Ebenen:

1.  **Backend API Tests (Integration Tests):**
    *   **Framework:** [Jest](https://jestjs.io/) + [Supertest](https://github.com/ladjs/supertest)
    *   **Fokus:** Logik der REST-API, Datenbank-Operationen, Authentifizierung und Validierung.
    *   **Besonderheit:** Verwendet eine isolierte In-Memory-Datenbank (`:memory:`) für maximale Geschwindigkeit und Reproduzierbarkeit.

2.  **End-to-End Browser Tests (E2E):**
    *   **Framework:** [Playwright](https://playwright.dev/)
    *   **Fokus:** Benutzeroberfläche (UI), visuelle Elemente (Badges), JavaScript-Interaktionen im Browser.
    *   **Besonderheit:** Startet den echten Webserver und steuert einen Chromium-Browser fern.

---

## 🚀 Ausführung

### Voraussetzungen

1.  **Abhängigkeiten installieren:**
    ```bash
    npm install
    ```
2.  **Playwright Browser installieren:**
    ```bash
    npx playwright install chromium
    ```
3.  **Anmeldedaten:**
    Die E2E-Tests lesen Benutzername (`user`) und Passwort (`password`) aus der Datei `.env` im Hauptverzeichnis.

### Befehle

| Befehl | Beschreibung |
| :--- | :--- |
| `npm run test:api` | Führt alle 17 Backend-Tests aus (schnell, ca. 1 Sekunde). |
| `npm run test:e2e` | Führt alle Browser-Tests aus (UI-Interaktion, ca. 4 Sekunden). |
| `npm test` | Führt beide Suiten nacheinander aus (empfohlen vor einem Git Push). |

---

## 📋 Liste der Testfälle

### Backend API (`tests/api.test.js`)

| Bereich | Testfall | Beschreibung |
| :--- | :--- | :--- |
| **Auth** | Falsche Credentials | Prüft, dass der Zugriff mit falschen Daten (HTTP 401) verweigert wird. |
| **Auth** | Korrekte Credentials | Verifiziert Login-Response und Session-Cookie-Zuweisung. |
| **Auth** | Unberechtigter Zugriff | Stellt sicher, dass geschützte Endpunkte ohne Session geblockt werden. |
| **Landschaft** | Erstellen | Erstellt eine neue Systemlandschaft und prüft die Response. |
| **Landschaft** | Abrufen | Prüft, ob die erstellte Landschaft in der Liste erscheint. |
| **Landschaft** | Aktualisieren | Testet das Umbenennen einer Landschaft per PUT-Request. |
| **SIDs** | Default (DEV) | Erstellt eine SID ohne Typ-Angabe und prüft den Default 'DEV'. |
| **SIDs** | PRD Erstellung | Erstellt eine SID explizit mit dem Typ 'PRD'. |
| **SIDs** | QAS Erstellung | Erstellt eine SID explizit mit dem Typ 'QAS'. |
| **SIDs** | Validierung | Stellt sicher, dass das Fehlen der `landscape_id` einen Fehler (HTTP 400) wirft. |
| **Persistenz** | System-Typ TST | Prüft, ob der Typ 'TST' korrekt in der DB gespeichert und wieder ausgelesen wird. |
| **Persistenz** | Update DEV -> PPRD | Ändert den Typ einer bestehenden SID und verifiziert die Änderung. |
| **Persistenz** | Update PPRD -> PRD | Prüft das Update auf den PRD-Typ (Legacy `is_prd` Support). |
| **Aktivitäten** | Listen abrufen | Testet, ob der `activity-types` Endpunkt ein Array zurückgibt. |
| **Settings** | Einstellungen | Prüft, ob die globalen App-Einstellungen korrekt geladen werden. |
| **Cleanup** | Löschen | Verifiziert das Löschen einer Landschaft und damit verbundener SIDs. |
| **Lifecycle** | Auto-COMPLETED | Prüft den automatischen Wechsel von PLANNED zu COMPLETED nach 24 Std. |
| **Lifecycle** | Auto-ARCHIVED | Prüft den automatischen Wechsel von COMPLETED zu ARCHIVED nach 7 Tagen. |
| **Lifecycle** | Manuelle Archivierung | Verifiziert PUT Endpunkte für Aktivitäten, Sub-Aktivitäten & Serien. |

### E2E Browser (`tests/e2e/system-type.spec.js`)

| Bereich | Testfall | Beschreibung |
| :--- | :--- | :--- |
| **Gantt UI** | Badge-Rendering | Loggt sich ein und prüft, ob im Gantt-Sidebar die farbigen Typ-Badges (PRD, QAS, etc.) erscheinen. |
| **Settings UI** | Dropdown-Sichtbarkeit | Navigiert in den Editor und prüft, ob die Systemtyp-Auswahlboxen vorhanden sind. |
| **Browser API** | Persistenz-Check | Nutzt den Browser-Context für einen API-Call, der die Typ-Zugehörigkeit aller SIDs verifiziert. |
| **Gantt UI** | Archiv-Darstellung | Prüft, ob archivierte Termine als ausgegraut (Grayscale) und transparent angezeigt werden. |
| **Termin-Editor** | Archiv-Icon (📦) | Verifiziert, dass COMPLETED Termine den Archiv-Button anstelle des Löschen-Buttons anzeigen. |
| **Termin-Editor** | Bearbeitungs-Sperre | Stellt sicher, dass Input-Felder (Datum, Zeit, etc.) bei alten Terminen auf \`disabled\` gesetzt sind. |

---

## 🛠️ Fehlerbehandlung

*   **Tests werden übersprungen:** Prüfen Sie, ob in der `.env` Datei `user` und `password` korrekt gesetzt sind.
*   **Fehlermeldung `command not found: playwright`:** Führen Sie `npm install` aus.
*   **Timeout-Fehler:** Wenn die App lokal sehr langsam reagiert, kann das Zeitlimit in `playwright.config.js` (`timeout: 15000`) erhöht werden.
