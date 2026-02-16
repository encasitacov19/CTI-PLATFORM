# CTI Platform

Plataforma de **Threat Intelligence** con backend en FastAPI y frontend en React. Integra GTI (VirusTotal) para obtener TTPs, genera alertas, dashboard, timeline y matriz MITRE. Incluye sincronización automática del dataset MITRE desde GitHub (STIX).

## Objetivo del proyecto
Este proyecto está diseñado para funcionar como un **radar de evolución del atacante**, no solo como un panel de visualización de técnicas.

La idea central es:
- observar técnicas MITRE por actor de amenaza de forma continua en el tiempo,
- detectar cuándo aparece una técnica **nueva y persistente** (repetida en días/muestras),
- reducir ruido de hallazgos puntuales,
- priorizar cambios reales de comportamiento adversario.

En términos prácticos, el foco pasa de:
- “este sample ejecutó muchas técnicas”

a:
- “este actor incorporó una nueva forma de atacar esta semana”.

Eso convierte la plataforma en una herramienta accionable para **detección temprana de cambios TTP**, priorización de análisis y toma de decisiones de defensa.

## Requisitos
- Python 3.10+
- Node.js 18+ (para el frontend)
- Docker (para Postgres)

## Ejecución por sistema operativo
### macOS
```bash
# Base de datos
docker-compose up -d

# Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requeriments.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

En otra terminal:
```bash
cd frontend
npm install
HOST=0.0.0.0 PORT=3000 npm start
```

### Linux (Ubuntu / Debian 12+)
```bash
# Base de datos
docker-compose up -d

# Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requeriments.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

En otra terminal:
```bash
cd frontend
npm install
HOST=0.0.0.0 PORT=3000 npm start
```

Si estás en Debian 11/Bullseye y ves errores por `str | None`, tu Python es 3.9.
Debes usar Python 3.10+ (recomendado 3.11).

### Windows (PowerShell)
```powershell
# Base de datos
docker-compose up -d

# Backend
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requeriments.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

En otra terminal:
```powershell
cd frontend
npm install
$env:HOST="0.0.0.0"
$env:PORT="3000"
npm start
```

## Problemas comunes
### `npm: command not found`
No tienes Node.js/npm instalado.

Linux (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y nodejs npm
node -v
npm -v
```

macOS (Homebrew):
```bash
brew install node
node -v
npm -v
```

Windows:
- instala Node.js LTS desde `https://nodejs.org/`
- cierra y abre terminal
- verifica con `node -v` y `npm -v`

### `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`
Estás ejecutando con Python 3.9.
Este proyecto requiere Python 3.10+.

Verifica versión:
```bash
python3 --version
```

Si estás en Linux viejo (ej. Debian 11), instala Python 3.11 y crea `venv` de nuevo antes de ejecutar `uvicorn`.

## Inicio rápido (otro dispositivo en la red)
Si quieres que alguien en la misma red abra la plataforma rápido, sigue estos pasos:

### 1) Levantar base de datos
```bash
docker-compose up -d
```

### 2) Configurar variables
En la raíz (`.env`):
```env
DATABASE_URL=postgresql://cti:cti@localhost:5432/cti
VT_API_KEY=TU_API_KEY_DE_VT
VT_SCAN_MIN_INTERVAL_MINUTES=60
VT_FILES_FALLBACK_LIMIT=40
NEW_ALERT_MIN_SIGHTINGS=3
NEW_ALERT_MIN_DISTINCT_DAYS=2
```

En `frontend/.env`:
```env
REACT_APP_API_BASE_URL=http://TU_IP_LOCAL:8000
```

### 3) Levantar backend
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requeriments.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4) Levantar frontend
```bash
cd frontend
npm install
HOST=0.0.0.0 PORT=3000 npm start
```

### 5) Abrir desde otro dispositivo
- Frontend: `http://TU_IP_LOCAL:3000`
- API: `http://TU_IP_LOCAL:8000`

Ejemplo:
- `http://192.168.1.20:3000`
- `http://192.168.1.20:8000`

### 6) Cómo saber `TU_IP_LOCAL`
- macOS / Linux: `ifconfig` o `ip a`
- Windows: `ipconfig`

Si no abre desde otro equipo:
- confirma que ambos están en la misma red,
- permite puertos `3000` y `8000` en firewall,
- reinicia frontend si cambiaste `frontend/.env`.
## Estructura
- `app/`: backend FastAPI
- `frontend/`: frontend React
- `docker-compose.yml`: Postgres local
- `requeriments.txt`: dependencias backend

> Nota: el archivo de dependencias se llama `requeriments.txt` (con esa ortografía).

## Archivos `.env` que debes crear
Para evitar errores en otro entorno, crea estos archivos:

1. `.env` en la raíz del proyecto (`cti-platform/.env`)
2. `frontend/.env`

Opcional (solo compatibilidad): `app/.env` con el mismo `DATABASE_URL` del `.env` raíz.
## Variables de entorno
Crea `.env` en la raíz del proyecto (mismo nivel que `docker-compose.yml`):

```
DATABASE_URL=postgresql://cti:cti@localhost:5432/cti
VT_API_KEY=TU_API_KEY_DE_VT
VT_SCAN_MIN_INTERVAL_MINUTES=60
VT_FILES_FALLBACK_LIMIT=40
NEW_ALERT_MIN_SIGHTINGS=3
NEW_ALERT_MIN_DISTINCT_DAYS=2
WATCHLIST_TECHNIQUES=T1190,T1059
WATCHLIST_MIN_SIGHTINGS=1
WATCHLIST_MIN_DISTINCT_DAYS=1
NEW_ALERT_TACTIC_THRESHOLD_OVERRIDES=initial-access:2/1,discovery:4/3
```

Crea `frontend/.env` en `cti-platform/frontend/.env`:

```env
REACT_APP_API_BASE_URL=http://TU_IP_LOCAL:8000
```
- `VT_SCAN_MIN_INTERVAL_MINUTES`: intervalo mínimo entre escaneos por actor en el colector masivo (`/admin/run-collector`).  
  Usa `0` para escanear siempre.
- `VT_FILES_FALLBACK_LIMIT`: cantidad máxima de samples usadas en el fallback por archivos (`behaviour_mitre_trees`) cuando `attack_techniques` viene vacío.
- `NEW_ALERT_MIN_SIGHTINGS`: mínimo de observaciones de una técnica para confirmar un `NEW`.
- `NEW_ALERT_MIN_DISTINCT_DAYS`: mínimo de días distintos en los que se observa la técnica para confirmar un `NEW`.
- `WATCHLIST_TECHNIQUES`: técnicas críticas separadas por coma; pueden confirmar `NEW` con umbral más sensible.
- `WATCHLIST_MIN_SIGHTINGS`: umbral de observaciones para técnicas de watchlist.
- `WATCHLIST_MIN_DISTINCT_DAYS`: umbral de días para técnicas de watchlist.
- `NEW_ALERT_TACTIC_THRESHOLD_OVERRIDES`: umbral por táctica (`tactica:sightings/days`), ej. `initial-access:2/1`.

## Base de datos (Postgres)
Levanta la base con Docker (obligatorio):

```bash
docker-compose up -d
```

### Cómo acceder a la BD
Opción 1 (recomendada, dentro del contenedor):

```bash
docker-compose exec db psql -U cti -d cti
```

Opción 2 (si tienes `psql` instalado localmente):

```bash
psql "postgresql://cti:cti@localhost:5432/cti"
```

Comandos útiles dentro de `psql`:

```sql
\dt
\d threat_actors
SELECT COUNT(*) FROM actor_techniques;
```

### Migraciones necesarias (solo si ya tenías una BD vieja)
Si es una instalación limpia, normalmente no necesitas esta sección.
Si vienes de una versión anterior, ejecuta estos SQL en la BD:

```sql
ALTER TABLE techniques ADD COLUMN IF NOT EXISTS description TEXT;

ALTER TABLE schedule_config ADD COLUMN IF NOT EXISTS time_hhmm VARCHAR;
ALTER TABLE schedule_config ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMP;
ALTER TABLE schedule_config ADD COLUMN IF NOT EXISTS running BOOLEAN DEFAULT FALSE;
ALTER TABLE schedule_config ADD COLUMN IF NOT EXISTS lock_until TIMESTAMP;

ALTER TABLE actor_techniques ADD COLUMN IF NOT EXISTS sightings_count INTEGER DEFAULT 1;
ALTER TABLE actor_techniques ADD COLUMN IF NOT EXISTS seen_days_count INTEGER DEFAULT 1;
ALTER TABLE actor_techniques ADD COLUMN IF NOT EXISTS new_alert_sent BOOLEAN DEFAULT FALSE;

UPDATE actor_techniques
SET sightings_count = COALESCE(sightings_count, 1),
    seen_days_count = COALESCE(seen_days_count, 1),
    new_alert_sent = COALESCE(new_alert_sent, TRUE);

CREATE TABLE IF NOT EXISTS technique_evidence (
  id SERIAL PRIMARY KEY,
  actor_id INTEGER REFERENCES threat_actors(id),
  technique_id INTEGER REFERENCES techniques(id),
  sample_hash VARCHAR,
  source VARCHAR DEFAULT 'files_behaviour_mitre_trees',
  observed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_use_cases (
  id SERIAL PRIMARY KEY,
  name VARCHAR UNIQUE,
  description VARCHAR,
  severity VARCHAR DEFAULT 'MEDIUM',
  enabled BOOLEAN DEFAULT TRUE,
  country_scope VARCHAR,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_conditions (
  id SERIAL PRIMARY KEY,
  use_case_id INTEGER REFERENCES detection_use_cases(id),
  tactic VARCHAR,
  technique_id INTEGER REFERENCES techniques(id),
  procedure VARCHAR,
  min_sightings INTEGER DEFAULT 1,
  min_days INTEGER DEFAULT 1,
  created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mitre_sync_config (
  id SERIAL PRIMARY KEY,
  day_of_week VARCHAR DEFAULT 'sun',
  time_hhmm VARCHAR DEFAULT '03:00',
  enabled BOOLEAN DEFAULT TRUE,
  updated_at TIMESTAMP,
  last_run_at TIMESTAMP,
  running BOOLEAN DEFAULT FALSE,
  lock_until TIMESTAMP
);
```

## Backend (FastAPI)
Instala dependencias:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requeriments.txt
```

Ejecuta el backend:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Para acceder desde otros dispositivos en la misma red, usa la IP local de tu equipo:

- API local: `http://localhost:8000`
- API en red: `http://TU_IP_LOCAL:8000` (ejemplo: `http://192.168.1.20:8000`)

Endpoints clave:
- `POST /admin/run-collector` : ejecuta recolección GTI para actores activos
- `POST /actors/{id}/scan` : escaneo de un actor específico
- `POST /admin/update-mitre` : sincroniza MITRE (legacy + STIX GitHub)
- `GET /jobs` : lista jobs (estado, progreso, timestamps)
- `GET /jobs/{job_id}` : detalle de un job específico
- `GET /dashboard/top-ttps` : top de técnicas priorizadas por impacto (actores + observaciones + táctica + vigencia). Soporta `suppress_noise=true`.
- `GET /dashboard/new-tactics-today` : tácticas detectadas hoy por primera vez en el histórico
- `GET /dashboard/weekly-comparison` : comparativa de `NEW` confirmados semana actual vs anterior
- `GET /dashboard/tactic-chains` : actores con cadenas tácticas críticas recientes
- `GET /dashboard/kpis` : KPIs de calidad (persistencia, tiempo a confirmación, ruido)
- `GET /mitre/matrix` : matriz MITRE (global o por actor)
- `GET /techniques/{tech_id}` : detalle + resumen MITRE + actores
- `GET /techniques` : catálogo de técnicas para búsquedas y formularios
- `GET /actors/{actor_id}/evidence` : hashes/muestras que soportan técnicas observadas
- `GET /detections/use-cases` : lista de casos de uso de detección
- `POST /detections/use-cases` : crea un caso de uso
- `PUT /detections/use-cases/{id}` : actualiza caso de uso
- `DELETE /detections/use-cases/{id}` : elimina caso de uso
- `GET /detections/use-cases/{id}` : detalle + condiciones
- `POST /detections/use-cases/{id}/conditions` : agrega condición
- `PUT /detections/conditions/{id}` : actualiza condición
- `DELETE /detections/conditions/{id}` : elimina condición
- `GET /detections/use-cases/{id}/matches` : actores que cumplen las condiciones del caso

## Frontend (React)
Desde `frontend/`:

```bash
npm install
HOST=0.0.0.0 PORT=3000 npm start
```

Acceso al frontend:

- Frontend local: `http://localhost:3000`
- Frontend en red: `http://TU_IP_LOCAL:3000` (ejemplo: `http://192.168.1.20:3000`)

Rutas principales:
- `/` Dashboard
- `/alerts` Alertas (por actor)
- `/matrix` Matriz MITRE
- `/detections` Casos de Uso y Detecciones
- `/playbook` Ruta Pentest (rompecabezas)
- `/techniques/:techId` Resumen MITRE + actores
- `/config` Configuración (actores, horarios, MITRE sync)

## Despliegue a Producción
Esta es una ruta simple y recomendada para desplegar en un VPS Linux (Ubuntu).

### 1. Preparar servidor
Instala dependencias base:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nginx docker.io docker-compose-plugin
```

Clona proyecto:

```bash
git clone <TU_REPO_GIT> cti-platform
cd cti-platform
```

### 2. Variables de entorno (backend)
Define el archivo `.env` en la raíz (`cti-platform/.env`) con valores de producción.

Recomendado:
- usar `VT_API_KEY` real,
- ajustar umbrales (`NEW_ALERT_*`, watchlist),
- no versionar secretos en Git.

### 3. Base de datos
Levanta Postgres:

```bash
docker compose up -d
```

Ejecuta migraciones SQL del README (sección **Migraciones necesarias**).

### 4. Backend (FastAPI)
Instala y prueba:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requeriments.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Luego, crea servicio `systemd` para que inicie solo:

Archivo `/etc/systemd/system/cti-backend.service`:

```ini
[Unit]
Description=CTI Platform Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/ruta/absoluta/cti-platform
EnvironmentFile=/ruta/absoluta/cti-platform/.env
ExecStart=/ruta/absoluta/cti-platform/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Activar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cti-backend
sudo systemctl restart cti-backend
sudo systemctl status cti-backend
```

### 5. Frontend (React build)
Construye frontend estático:

```bash
cd frontend
npm ci
npm run build
```

El contenido final queda en `frontend/build`.

### 6. Nginx (frontend + proxy API)
Ejemplo de sitio Nginx (`/etc/nginx/sites-available/cti-platform`):

```nginx
server {
    listen 80;
    server_name TU_DOMINIO;

    root /ruta/absoluta/cti-platform/frontend/build;
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        try_files $uri /index.html;
    }
}
```

Activar sitio:

```bash
sudo ln -s /etc/nginx/sites-available/cti-platform /etc/nginx/sites-enabled/cti-platform
sudo nginx -t
sudo systemctl restart nginx
```

### 7. HTTPS (recomendado)
Con Certbot:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d TU_DOMINIO
```

### 8. Actualizar versión en producción
Cada despliegue:

```bash
cd /ruta/absoluta/cti-platform
git pull
source venv/bin/activate
pip install -r requeriments.txt
sudo systemctl restart cti-backend
cd frontend
npm ci
npm run build
sudo systemctl reload nginx
```

### 9. Verificación rápida
- API: `curl http://127.0.0.1:8000/`
- Backend logs: `sudo journalctl -u cti-backend -f`
- Nginx logs: `sudo tail -f /var/log/nginx/error.log`

## MITRE Sync (STIX GitHub)
- La sincronización semanal se ejecuta en background (sin cron externo).
- Configurable en **Configuración**.
- El botón **“Cargar MITRE ahora”** ejecuta `load_mitre` + `sync_mitre_from_github`.

## Zona horaria
Toda la aplicación está configurada para **America/Bogota**.

## Notas
- `load_mitre` carga técnicas base, pero el resumen completo proviene del sync STIX.
- Las alertas aparecen solo si hay cambios (NEW / REACTIVATED / DISAPPEARED). Si no hay cambios, se muestran técnicas recientes.
- `NEW` se emite cuando la técnica demuestra persistencia (según `NEW_ALERT_MIN_SIGHTINGS` y `NEW_ALERT_MIN_DISTINCT_DAYS`), no necesariamente en la primera aparición.
