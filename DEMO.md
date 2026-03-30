# AtnLyze Demo Runbook

This demo is run manually from VS Code terminals. The old launcher scripts were removed.

## Preconditions

Before starting, verify these manually:

- `frontend/.env` uses the current LAN IPv4:
  - `VITE_API_BASE=http://<CURRENT-IP>:8001`
- `src/atnlyze/api/app.py` CORS `allow_origins` includes the current frontend origin:
  - `http://<CURRENT-IP>:5173`
- Docker Desktop is running.
- If you will demo on phone, the phone and laptop are on the same hotspot/Wi-Fi.

To get the current IPv4 on Windows:

```powershell
ipconfig
```

Use the `Wireless LAN adapter Wi-Fi` IPv4 address or the hotspot-facing IPv4. Ignore WSL/virtual adapter IPs like `172.21.x.x`.

## Startup Order

Use three VS Code terminals.

### Terminal 1: Start Docker Targets

From repo root:

```powershell
docker compose -f docker/docker-compose.yml up -d
```

Optional check:

```powershell
docker compose -f docker/docker-compose.yml ps
```

### Terminal 2: Start Backend

From repo root:

```powershell
.\.venv\Scripts\uvicorn.exe src.atnlyze.api.app:app --host 0.0.0.0 --port 8001
```

Health check from browser:

```text
http://localhost:8001/health
```

If demoing on phone, backend should also be reachable at:

```text
http://<CURRENT-IP>:8001/health
```

### Terminal 3: Start Frontend

From `frontend/`:

```powershell
npx vite --host 0.0.0.0 --port 5173
```

Laptop URLs:

- Frontend: `http://localhost:5173`
- Backend health: `http://localhost:8001/health`

Phone URLs:

- Frontend: `http://<CURRENT-IP>:5173`
- Backend health: `http://<CURRENT-IP>:8001/health`

Note: Vite may print more than one `Network` URL. Use the real hotspot/Wi-Fi IP, not the WSL/virtual adapter IP.

## Demo Flow

Once the dashboard is open:

1. Press `Reset Stats`.
2. Press `Start Benign Traffic` or `Launch Attack`.
3. If launching attack only, `live_waf_feed.py` is still started by the backend.
4. Verify traffic is visible in the arena and charts update.
5. Use `Stop All` when done.

Useful backend checks:

- Demo status: `http://localhost:8001/demo/status`
- Stats: `http://localhost:8001/stats`
- SSE stream: `http://127.0.0.1:8001/stream`

## Shutdown Order

### Stop Frontend

In the frontend terminal, press:

```text
Ctrl+C
```

### Stop Backend

In the backend terminal, press:

```text
Ctrl+C
```

### Stop Docker Targets

From repo root:

```powershell
docker compose -f docker/docker-compose.yml down
```

## Failure Fallbacks

### Frontend loads but stats show `Stats polling degraded: Network Error`

Cause is usually stale IP or stale CORS.

Check:

- `frontend/.env` has the current IP in `VITE_API_BASE`
- `src/atnlyze/api/app.py` CORS includes `http://<CURRENT-IP>:5173`

Then restart:

- backend terminal
- frontend terminal

### Phone cannot open `http://<CURRENT-IP>:5173`

Check:

- frontend was started with `--host 0.0.0.0`
- phone and laptop are on the same hotspot/Wi-Fi
- you are using the real Wi-Fi/hotspot IPv4 from `ipconfig`
- Windows Firewall is not blocking `5173`

### Arena is active but stats are dead

This usually means:

- `/stream` is reachable
- `/stats` is failing due to CORS or wrong `VITE_API_BASE`

Re-check IP and CORS first.

### `/stream` shows only keepalives and no traffic events

Check:

- `http://localhost:8001/demo/status`
- confirm `feed` is running
- if not, press `Start Benign Traffic` or `Launch Attack` again

### Hotspot IP changed

Repeat these manual updates:

- `frontend/.env`
- `src/atnlyze/api/app.py` CORS allow list

Then restart backend and frontend.

## Final Rehearsal Checklist

Before exhibition:

1. Run `ipconfig`.
2. Update `frontend/.env` if IP changed.
3. Update `src/atnlyze/api/app.py` CORS if IP changed.
4. Start Docker.
5. Start backend.
6. Start frontend.
7. Open laptop dashboard.
8. Open phone dashboard if needed.
9. Press `Reset Stats`.
10. Run one benign pass and one attack pass.
11. Verify `Stop All` works.
12. Shut everything down cleanly.
