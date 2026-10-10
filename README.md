# URL Scheduler

Selbst gehostete, deutschsprachige Webanwendung zum zeitgesteuerten Ausführen von HTTP-Aufrufen. Die Anwendung wird als einzelner Docker-Container betrieben; Jobs und Historie liegen in SQLite im persistenten Datenverzeichnis.

## Funktionsumfang

- Dashboard, Jobverwaltung, manuelle Starts und Ausführungshistorie
- Intervall-, Cron- und Einmalausführungen mit APScheduler
- HTTP GET/POST, Query-Parameter, Header, JSON-/Text-Body und begrenzte Timeouts
- Geschützte Weboberfläche mit konfigurierbarem Benutzer, PBKDF2-Passworthash und signierter Sitzung
- Verschlüsselte Speicherung sensibler Header, SSRF-Schutz, begrenzte Historie und SQLite-Migrationen

## Architektur

NiceGUI stellt die Oberfläche bereit. Services in `app/services.py` führen CRUD, Protokollpflege und Scheduler-Synchronisierung aus. `app/scheduler.py` lädt aktive Jobs nach dem Start und führt höchstens `MAX_CONCURRENT_JOBS` Requests gleichzeitig aus. `app/http_executor.py` löst Ziele auf, prüft IP-Adressen und pinnt die geprüfte Adresse für die HTTP-Verbindung. SQLAlchemy 2 und SQLite speichern Konfiguration und Historie; Alembic verwaltet Schemaänderungen.

## Voraussetzungen

- Docker Engine mit Docker Compose v2 oder NAS Container Manager
- Unterstützte Plattformen: Linux AMD64 und ARM64 (Python-Basisimage und festgelegte Python-Abhängigkeiten sind für beide Architekturen verfügbar)
- Port 8080, sofern nicht geändert

Eine lokal installierte Python-Laufzeit ist für den Dockerbetrieb nicht erforderlich.

## Installation mit Docker Compose

```sh
cp .env.example .env
```

Erzeuge Zugangsdaten und Schlüssel **vor** dem ersten Start. Falls lokal Python und die Abhängigkeiten verfügbar sind:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"  # APP_SESSION_SECRET
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # APP_ENCRYPTION_KEY
python -c "from app.security import hash_password; print(hash_password('HIER-EIN-LANGES-EINMALIGES-PASSWORT'))"
```

Trage die Werte in `.env` ein. Ohne lokale Python-Umgebung kannst du das Image zunächst bauen und die benötigten Werte anschließend im Container erzeugen:

```sh
docker compose build
docker compose run --rm --no-deps --entrypoint python url-scheduler -c \
  "from app.security import hash_password; print(hash_password('HIER-EIN-LANGES-EINMALIGES-PASSWORT'))"
docker compose run --rm --no-deps --entrypoint python url-scheduler -c \
  "import secrets; print(secrets.token_urlsafe(48))"
docker compose run --rm --no-deps --entrypoint python url-scheduler -c \
  "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Setze `APP_AUTH_USERNAME`, `APP_AUTH_PASSWORD_HASH`, `APP_SESSION_SECRET` und `APP_ENCRYPTION_KEY` in `.env`. Bewahre diese Werte sicher auf; insbesondere der Verlust des Verschlüsselungsschlüssels macht bereits gespeicherte Geheimheader unlesbar.

```sh
docker compose up -d --build
docker compose ps
docker compose logs -f url-scheduler
```

Die Compose-Datei bindet standardmäßig auf `127.0.0.1:8080`. Für direkten LAN-Zugriff setze `APP_BIND_ADDRESS=0.0.0.0`; beschränke den Port zusätzlich mit der Firewall auf das lokale Netz. Andernfalls verwende einen TLS-fähigen Reverse Proxy und aktiviere `APP_COOKIE_SECURE=true`. Bei einem Reverse Proxy müssen WebSocket-Upgrades unterstützt sein.

### NAS Container Manager

Lege einen Projektordner mit `compose.yaml` und `.env` auf dem NAS an, editiere `.env` mit den generierten Werten und importiere den Ordner als Compose-Projekt. Stelle sicher, dass das benannte Volume `scheduler-data` angelegt wird und dem Container Manager keine privilegierten Rechte oder Host-Socket-Mounts hinzugefügt werden. Ports und Zugangsdaten nur im lokalen Netz freigeben.

## Konfiguration

| Variable | Erforderlich | Standard | Beschreibung |
|---|---:|---|---|
| `APP_BIND_ADDRESS` | nein | `127.0.0.1` | Host-Portbindung in Compose (`0.0.0.0` nur bewusst verwenden) |
| `APP_HOST` | nein | `0.0.0.0` | Bind-Adresse innerhalb des Containers |
| `APP_PORT` | nein | `8080` | HTTP-Port |
| `APP_TIMEZONE` | nein | `Europe/Berlin` | Standardanzeigezone |
| `APP_DATA_DIR` | nein | `/app/data` im Container | SQLite-Datenverzeichnis |
| `APP_LOG_LEVEL` | nein | `INFO` | Python-Logstufe |
| `APP_AUTH_ENABLED` | nein | `true` | Zugriffsschutz; aktiv lassen |
| `APP_AUTH_USERNAME` | ja bei Auth | — | Anmeldename |
| `APP_AUTH_PASSWORD_HASH` | ja bei Auth | — | PBKDF2-SHA256-Hash aus `hash_password` |
| `APP_SESSION_SECRET` | ja bei Auth | — | Zufälliger Schlüssel, mindestens 32 Zeichen |
| `APP_ENCRYPTION_KEY` | für Request-Bodies/vertrauliche Header oder Query-Parameter | — | Fernet-Schlüssel, persistent und geheim aufbewahren |
| `APP_COOKIE_SECURE` | nein | `false` | `true` bei HTTPS/TLS-Proxy |
| `MAX_CONCURRENT_JOBS` | nein | `4` | Globale Obergrenze gleichzeitiger Requests |
| `DEFAULT_TIMEOUT_SECONDS` | nein | `15` | Timeout-Standardwert des Formulars |
| `LOG_RETENTION_DAYS` | nein | `90` | Einträge älter als diese Zahl löschen; `0` deaktiviert Zeitlimit |
| `LOG_RETENTION_MAX_RUNS` | nein | `10000` | Höchstzahl gespeicherter Einträge; `0` deaktiviert Anzahllimit |
| `APP_ALLOWED_PRIVATE_TARGETS` | nein | leer | Ausdrückliche IP-/CIDR-Allowlist für private Ziele (`/24` oder enger bei IPv4, `/64` oder enger bei IPv6), keine Hostnamen |
| `APP_RESPONSE_PREVIEW_BYTES` | nein | `0` | Maximale Antwortvorschau in Bytes; `0` deaktiviert |

`APP_AUTH_ENABLED=false` ist für Netzwerkbetrieb nicht zulässig. Das Datenverzeichnis und `.env` enthalten vertrauliche Informationen und müssen zugriffsbeschränkt sein.

## Jobs erstellen und Zeitpläne

Wähle im Formular einen Zeitplantyp:

- **Intervall:** ganzzahlige Dauer und Einheit Sekunden/Minuten/Stunden/Tage.
- **Cron:** fünf Felder `Minute Stunde Tag Monat Wochentag`, z. B. `0 8 * * 1` für Montag 08:00 Uhr. Validierung erfolgt mit APScheduler.
- **Einmalig:** lokaler ISO-Zeitpunkt, z. B. `2026-12-24T08:00:00`.

Optionale Start- und Endzeitpunkte sind für Intervall- und Cronjobs möglich. Zeiten ohne Offset werden als lokale Zeit der ausgewählten Jobzeitzone verstanden. Bei Sommerzeitlücken überspringt CronTrigger nicht existierende lokale Uhrzeiten; bei doppelt auftretenden Uhrzeiten ist das Verhalten APScheduler/zoneinfo-abhängig. Geplante Zeitstempel werden in SQLite als UTC-naive Werte gespeichert und bei Anzeige in die Zeitzone umgerechnet.

Jobs werden nach Neustart aus SQLite wiederhergestellt. Versäumte Termine werden mit `coalesce` und einer einsekündigen Misfire-Frist nicht unbegrenzt nachgeholt. Läuft ein Job bereits und parallele Ausführung ist aus, wird ein überlappender Start verworfen. Manuelle Starts werden unabhängig vom Aktivierungsstatus geplant und als manuell protokolliert. Neustart eines Einmaljobs führt nicht zur Wiederholung eines bereits verpassten Termins.

## HTTP-Konfiguration

Unter „Erweiterte HTTP-Einstellungen“ lassen sich Header und Query-Parameter als JSON-Schlüssel/Wert-Objekte einstellen. GET und POST sind verfügbar. Bodies sind nur für POST zugelassen und als JSON oder Text wählbar. Erfolg bedeutet HTTP 200–299. Wiederholungen sind begrenzt; POST wird standardmäßig nie wiederholt. Eine Aktivierung von POST-Retries kann externe Aktionen doppelt ausführen.

Sensible Header, Request-Bodies sowie vertrauliche Query-Parameter (Schlüssel mit `token`, `secret`, `password`, `key` oder `auth`) werden mit Fernet verschlüsselt gespeichert; vertrauliche Header und Query-Werte werden in Formularen nicht angezeigt. Solche Parameter dürfen nicht direkt in der URL stehen; lege sie als strukturierte Query-Parameter an. Der Schlüssel liegt in `.env`, also außerhalb der SQLite-Datei, aber nicht in einem dedizierten Secret Store. Schütze Backups und Hostdateien; rotiere den Schlüssel nicht ohne vorherige Migration der gespeicherten Geheimnisse. Headerwerte, Request-Bodies und Antwortvorschauen werden nicht in Container-Logs geschrieben. Antworten werden standardmäßig gar nicht gespeichert; bei Aktivierung wird die Vorschau begrenzt.

Redirects werden einzeln verfolgt und erneut geprüft. Umgeleitete Anfrageziele werden aufgelöst und IP-geprüft, die HTTP-Verbindung wird an eine aufgelöste Adresse gebunden. Redirect-Limit: fünf Weiterleitungen.

## Ausführungsprotokoll

Die Historie zeigt Jobname, Auslöser, Start, Dauer, Status, HTTP-Code und bereinigte Meldung; sie kann nach Ergebnis und Auslöser gefiltert werden. Historieneinträge bleiben nach Joblöschung über eine nullable Fremdschlüsselbeziehung erhalten. Die GUI bietet das manuelle Löschen von Einträgen vor einem Stichtag; automatische Bereinigung entfernt alte Runs anhand des Alters und/oder überschüssiger Anzahl. Jobkonfiguration wird dadurch nicht gelöscht. Container-Logs sind separat und enthalten Diagnosedaten ohne Request-Bodies oder Headerwerte.

## Sicherheitskonzept und Grenzen

- Standardmäßig blockiert: private, Loopback-, Link-local-, nicht spezifizierte, multicast- und reservierte Adressen (IPv4 und IPv6); jeder DNS-Record muss zulässig sein.
- Private Ziele können nur durch passende, ausreichend enge IP-/CIDR-Einträge freigegeben werden (z. B. `192.168.1.15` oder `192.168.1.0/24`, `fd12:3456:789a:1::/64`); DNS-Namen, breite Netze und Loopback-/Link-local-/reservierte Ziele lassen sich nicht freigeben. DNS-Änderungen nach Prüfung ändern die für den Request verwendete IP nicht.
- Zielprüfungen erfolgen auch vor jedem Redirect. HTTP-Proxys aus Umgebungsvariablen werden ignoriert.
- Login nutzt PBKDF2-Passworthash, zeitbegrenzte signierte HttpOnly-/SameSite-Cookies, Origin-Prüfung für schreibende Requests/WebSockets und begrenzte Loginversuche.
- Der Container läuft als Nicht-Root, ohne zusätzliche Linux-Capabilities, mit schreibgeschütztem Root-Dateisystem.

**Restrisiken:** Das Werkzeug ist ein gezielter Netzwerkanfrage-Generator. Private-Adressfreigaben, ein kompromittierter Zugang oder schwach verwaltete `.env`-Dateien können internen Zugriff ermöglichen. Ein Reverse Proxy muss HTTPS und WebSockets korrekt konfigurieren. Ohne `APP_COOKIE_SECURE=true` dürfen Cookies nicht über ein öffentliches HTTP-Netz transportiert werden. DNS-Pinning erschwert Rebinding, ersetzt aber keine Firewall-/Egress-Regeln. Nicht für untrusted Benutzer oder direkte Internet-Exposition ohne zusätzliche Schutzschicht einsetzen.

## Starten, Stoppen, Updates

```sh
docker compose up -d --build
docker compose stop
docker compose start
docker compose pull
docker compose up -d --build
docker compose logs --tail=200 url-scheduler
```

Healthcheck: `http://localhost:8080/healthz` liefert nur `ok` oder `not ready`; er führt keinen Job aus. Der Container meldet bei Datenbank- oder Schedulerproblemen `503`.

## Persistenz, Backup und Wiederherstellung

Das Compose-Volume `scheduler-data` enthält `scheduler.db`. Zusätzlich müssen `.env` (insbesondere Verschlüsselungs- und Sitzungsschlüssel) und das Datenbank-Backup sicher aufbewahrt werden. Erstelle Backups bei gestopptem Container, damit die SQLite-Datei konsistent kopiert wird:

```sh
docker compose stop
docker run --rm -v url-scheduler-gui_scheduler-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/url-scheduler-backup.tgz -C /data .
docker compose start
```

Ersetze beim Wiederherstellen das Volume mit einer Kopie des gesicherten Inhalts und stelle die zugehörige `.env` wieder her. Passe bei abweichendem Compose-Projektnamen den Volume-Namen (`docker volume ls`) an. Vor Updates zuerst Datenbank und `.env` sichern; Alembic-Migrationen erweitern das Schema, löschen keine Jobdaten absichtlich.

## Diagnose und Tests

```sh
docker compose ps
docker compose logs -f url-scheduler
docker compose exec url-scheduler python -c "from app.database import engine; print(engine.connect().exec_driver_sql('select 1').scalar())"
python -m pip install -r requirements.txt
python -m pytest -q
```

Tests verwenden lokale Testserver/Mocks und benötigen keinen externen Webdienst. Geprüft werden unter anderem Passworthashes, private und reservierte IPs, DNS-Mischantworten, verschlüsselte Header, Job-CRUD, Historie, Cronvalidierung und manuelle HTTP-Ausführung. Nicht jeder mögliche Redirect-, Timeout-, UI- und Multi-Container-Ausfallfall ist automatisiert abgedeckt; der Dienst ist als Einzelinstanz ausgelegt.

## Multi-Architecture-Build

Das Docker Official Python 3.12 Slim-Image und die verwendeten Wheel-basierten Python-Pakete unterstützen AMD64 und ARM64. Lokal kann Docker Buildx beide Image-Ziele bauen (QEMU kann auf dem NAS erforderlich sein):

```sh
docker buildx create --name scheduler-builder --use 2>/dev/null || docker buildx use scheduler-builder
docker buildx inspect --bootstrap
docker buildx build --platform linux/amd64,linux/arm64 -t url-scheduler:local .
```

Ein Multi-Plattform-Manifest lässt sich nicht direkt in den lokalen Docker-Image-Store laden; für Veröffentlichung ist ein Registry-Ziel erforderlich, z. B. `--push -t REGISTRY/URL-SCHEDULER:TAG`. Der Architektur-Build muss in einer geeigneten Buildx/QEMU-Umgebung tatsächlich ausgeführt werden; die Existenz der Dockerfile allein ist kein Buildnachweis.
