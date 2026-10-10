# URL Scheduler GUI

## Installation (Portainer / UGREEN NAS)

1. In MariaDB eine Datenbank `url_scheduler` und einen Benutzer anlegen (utf8mb4).
2. Portainer → Stacks → Add stack → Web editor → Inhalt von `compose.yaml` einfügen.
3. `DB_HOST`, `DB_USER`, `DB_PASSWORD`, Port und Zeitzone anpassen; Branch/Repo im Build-Kontext (`#main`) ggf. ändern.
4. Deploy. Oberfläche: `http://<NAS-IP>:8080`.

Tabellen werden beim Start automatisch angelegt. Login und Verschlüsselung sind standardmäßig aus
(optional: `APP_AUTH_ENABLED`, `APP_ENCRYPTION_KEY`). Ohne `DB_HOST` wird SQLite in `APP_DATA_DIR` genutzt.
