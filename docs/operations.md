# Running and stopping

## Development

```bash
source venv/bin/activate
python app.py
# stop with Ctrl-C
```

## Background on a server

```bash
nohup python app.py > ruk.log 2>&1 &
echo $! > ruk.pid

# stop
kill "$(cat ruk.pid)" && rm -f ruk.pid
```

## On Termux

```bash
termux-wake-lock
tmux new -s ruk 'source venv/bin/activate && python app.py'
# detach: Ctrl-B then D
tmux attach -t ruk        # return
tmux kill-session -t ruk  # stop
```

## Behind systemd (Debian / Kali)

`/etc/systemd/system/ruk.service`:

```ini
[Unit]
Description=RUK SHADOW INTELLIGENCE
After=network.target

[Service]
Type=simple
User=ruk
WorkingDirectory=/opt/ruk-shadow-intelligence
EnvironmentFile=/opt/ruk-shadow-intelligence/.env
ExecStart=/opt/ruk-shadow-intelligence/venv/bin/python app.py
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ruk-shadow-intelligence/data /opt/ruk-shadow-intelligence/reports

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ruk
sudo systemctl status ruk
sudo journalctl -u ruk -f      # logs
sudo systemctl stop ruk        # stop
```

## Health check

```bash
curl -fsS http://127.0.0.1:8000/healthz
# {"status":"ok","product":"ruk-shadow-intelligence", ...}
```

`/healthz` returns no analytics data, so it is safe to expose to a load balancer
or uptime monitor.

## Terminal interface

```bash
python terminal_dashboard.py
```

```
  1. Dashboard                8. IP and Network Metadata
  2. Create Analytics Link    9. Export Reports
  3. Manage Campaigns        10. Security & Configuration
  4. Live Click Events       11. System Diagnostics
  5. Visitor Analytics       12. Help and Documentation
  6. Browser & Device        13. Exit
  7. Consent Management
```

| Option | What it does |
|---|---|
| **1 Dashboard** | Counters, recent events, recent links |
| **2 Create link** | Interactive generator with destination validation, campaign, expiry, QR code |
| **3 Campaigns** | Create, list and archive campaigns |
| **4 Live events** | Tail new events for up to five minutes, Ctrl-C to return |
| **5 Visitor analytics** | Device, browser, OS and country breakdowns |
| **6 Browser & device** | Browser/OS/version combinations and top referrers |
| **7 Consent** | Granted/declined counts, recent decisions, per-visitor erasure |
| **8 IP & network** | Exactly what the current IP policy stored, per event |
| **9 Export** | Write CSV or JSON to `reports/` |
| **10 Security & config** | Active posture, warnings, hardening checklist, password change |
| **11 Diagnostics** | DB integrity, schema version, dependencies, disk, geo state |
| **12 Help** | Offline documentation, including what the tool cannot do |
| **13 Exit** | Leave cleanly |

Non-interactive modes, safe from a script or CI because they never wait on
stdin:

```bash
python terminal_dashboard.py --create-admin [--username NAME]
python terminal_dashboard.py --diagnose
python terminal_dashboard.py --export json
```

## Web dashboard

| Route | Purpose | Auth |
|---|---|---|
| `/` | Public landing page | - |
| `/privacy` | Privacy notice generated from live config | - |
| `/l/<id>` | Visitor consent gateway | - |
| `/l/<id>.png` | QR code for the link | - |
| `/admin/login` | Sign in | - |
| `/admin` | Dashboard with live feed | session |
| `/admin/links` | Create, revoke, restore, delete links | session |
| `/admin/campaigns` | Campaign management and performance | session |
| `/admin/events` | Searchable, filterable event table | session |
| `/admin/privacy` | Retention, erasure, audit log | session |
| `/admin/export?format=csv` | Download events | session |
| `/admin/api/stats` | JSON counters for the dashboard | session |
| `/admin/stream` | Server-Sent Events feed | session |
| `/healthz` | Liveness probe, no data | - |

The live feed is real Server-Sent Events: the browser subscribes to
`/admin/stream`, the server polls the database once per second per connected
client, and each new event is pushed as

```
event: event
data: {"id":12,"time":"2026-10-29T18:14:59Z","campaign":"Autumn","browser":"Chrome 120", ...}
```

Each connection is recycled after five minutes so a stale tab cannot pin a
worker forever. The client reconnects automatically.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `SECRET_KEY must be set` | Production with no key | Generate one into `.env` |
| `PUBLIC_BASE_URL must use https` | Production with an http base URL | Use HTTPS, or `RUK_ENV=development` |
| Links open but no events appear | Visitor declined | Expected: declining records nothing |
| Links work locally but not from another device | `BIND_HOST=127.0.0.1` | Set `BIND_HOST=0.0.0.0`, or use a tunnel |
| Works on the LAN but not the internet | No port forwarding | Cloudflare Tunnel, ngrok, or a real server |
| `Unable to resolve host` on link creation | DNS failure or typo | Check the domain |
| "private or reserved" on link creation | SSRF protection | Intentional; use a public destination |
| Live feed stuck on "connecting" | Proxy buffering the SSE stream | `proxy_buffering off` for `/admin/stream` |
| Live feed reconnecting repeatedly | Proxy read timeout | `proxy_read_timeout 24h;` |
| `429` on login | Rate limit reached | Wait out `LOGIN_RATE_WINDOW`, or raise the limit |
| `Address already in use` | Port taken | Change `BIND_PORT`, or `ss -lptn 'sport = :8000'` |
| `No module named 'flask'` | venv not active | `source venv/bin/activate` |
| Termux: Pillow build fails | Missing headers | `pkg install libjpeg-turbo libpng clang make` |
| Termux: process dies on screen lock | Android battery optimisation | `termux-wake-lock`; disable optimisation for Termux |
| QR code 404 | Link revoked or deleted | Revoked links stop serving a QR on purpose |
| `database is locked` | Two writers | WAL gives concurrent readers, not writers; keep one writer process |
| Cannot sign in after editing `.env` | Session key changed | Sign in again |
| Geo columns empty | `GEO_PROVIDER=none` (default) | Enable `maxmind` or `http` |
